#!/usr/bin/env python3
"""
soludev_anecdotes_plugin.py

- Authenticates to SoluDev
- Pulls /users and /roles
- Normalizes them into table-like lists of dicts
- Pushes each as an Anecdotes "custom evidence"
- Uses retries, structured logging, and environment configuration
"""

import os
import sys
import time
import csv
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# -------------------------
# CONFIGURATION (env vars)
# -------------------------
SOLUDEV_BASE_URL = os.environ.get("SOLUDEV_BASE_URL", "http://10.1.0.14:8080").rstrip("/")
SOLUDEV_USERNAME = os.environ.get("SOLUDEV_USERNAME", "admin")
SOLUDEV_API_KEY = os.environ.get("SOLUDEV_API_KEY", "admin-api-key-12345")

ANECDOTES_API_BASE = os.environ.get("ANECDOTES_API_BASE", "https://api.anecdotes.ai")  # override if needed
ANECDOTES_API_TOKEN = os.environ.get("ANECDOTES_API_TOKEN")  # REQUIRED
ANECDOTES_EVIDENCE_PATH = os.environ.get("ANECDOTES_EVIDENCE_PATH", "/v1/custom-evidence")  # example path
_jwt_cache = {"token": None, "timestamp": 0}

RUN_MODE = os.environ.get("RUN_MODE", "once")  # "once" or "daemon" (daemon will sleep weekly)

# -------------------------
# LOGGING
# -------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s - %(message)s",
)
logger = logging.getLogger("soludev_plugin")

# -------------------------
# HTTP SESSION WITH RETRIES
# -------------------------
def create_session(retries: int = 5, backoff_factor: float = 0.8, status_forcelist=(429, 500, 502, 503, 504)) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

session = create_session()

# -------------------------
# DATA CLASSES
# -------------------------
@dataclass
class Evidence:
    name: str
    description: str
    columns: List[str]
    rows: List[Dict[str, Any]]

    def to_payload(self) -> Dict[str, Any]:
        """
        Format the payload expected by Anecdotes' custom evidence API.
        Adjust keys to match Anecdotes' exact schema if needed.
        """
        return {
            "evidence_name": self.name,
            "description": self.description,
            "columns": self.columns,
            "rows": self.rows,
            "collected_at": int(time.time()),
        }

# -------------------------
# SOLUDEV HELPERS
# -------------------------
def soludev_authenticate(sess: requests.Session) -> str:
    url = f"{SOLUDEV_BASE_URL}/login"
    payload = {"username": SOLUDEV_USERNAME, "api_key": SOLUDEV_API_KEY}
    logger.info("Authenticating to SoluDev at %s", url)
    resp = sess.post(url, json=payload, timeout=15)
    if resp.status_code != 200:
        logger.error("Failed to authenticate to SoluDev: %s %s", resp.status_code, resp.text)
        raise RuntimeError(f"Auth to SoluDev failed: {resp.status_code}")
    data = resp.json()
    # Accept a few possible shapes: {"token": "xxx"} or {"access_token":"xxx"} or direct Bearer
    token = data.get("token") or data.get("access_token") or data.get("bearer")
    if not token:
        # maybe the login returns the header or raw string
        if isinstance(data, str):
            token = data
    if not token:
        logger.error("No token found in SoluDev auth response: %s", data)
        raise RuntimeError("No token in SoluDev auth response")
    # Ensure "Bearer " prefix
    if not token.lower().startswith("bearer"):
        token = "Bearer " + token
    logger.info("Authenticated to SoluDev successfully")
    return token

def soludev_get(sess: requests.Session, token: str, path: str) -> Any:
    url = f"{SOLUDEV_BASE_URL.rstrip('/')}/{path.lstrip('/')}"
    headers = {"Authorization": token, "Accept": "application/json"}
    logger.debug("Requesting SoluDev %s", url)
    resp = sess.get(url, headers=headers, timeout=20)
    if resp.status_code != 200:
        logger.error("Error fetching %s: %s %s", path, resp.status_code, resp.text[:500])
        raise RuntimeError(f"SoluDev GET {path} returned {resp.status_code}")
    return resp.json()

# -------------------------
# TRANSFORM / NORMALIZE
# -------------------------
def normalize_users(raw_users: Any) -> Evidence:
    """
    Normalize user data that may come as:
    - A dict containing "users": [ ... ]
    - Or directly as a list of user dicts
    """
    # If it's a dict, unwrap the "users" key or similar
    if isinstance(raw_users, dict):
        for key in ("users", "data", "results"):
            if key in raw_users:
                raw_users = raw_users[key]
                break

    rows = []
    for u in (raw_users or []):
        if isinstance(u, str):
            # Handle the unlikely case of plain string usernames
            rows.append({
                "user_id": None,
                "username": u,
                "email": None,
                "roles": "",
                "raw": u
            })
            continue

        # Safely extract fields from user dict
        user_id = u.get("user_id") or u.get("id") or u.get("uid")
        username = (
            u.get("username")
            or f"{u.get('first_name', '')} {u.get('last_name', '')}".strip()
            or f"user_{user_id}"
        )
        email = u.get("email")
        roles_field = u.get("assigned_role") or u.get("roles") or u.get("role_names") or []
        if isinstance(roles_field, list):
            roles = ",".join([str(r) for r in roles_field])
        else:
            roles = str(roles_field)
        rows.append({
            "user_id": user_id,
            "username": username,
            "email": email,
            "roles": roles,
            "raw": u,
        })

    columns = ["user_id", "username", "email", "roles", "raw"]
    return Evidence(
        name="soludev_users",
        description="SoluDev users and roles",
        columns=columns,
        rows=rows,
    )

def normalize_roles(raw_roles: Any) -> Evidence:
    """
    Normalize role data that may come as:
    - A dict containing "roles": [ ... ]
    - Or directly as a list of role dicts
    """
    # If it's a dict, unwrap the "roles" key or similar
    if isinstance(raw_roles, dict):
        for key in ("roles", "data", "results"):
            if key in raw_roles:
                raw_roles = raw_roles[key]
                break

    rows = []
    for r in (raw_roles or []):
        if isinstance(r, str):
            rows.append({
                "role_id": None,
                "role_name": r,
                "permissions": "",
                "raw": r
            })
            continue

        role_id = r.get("role_id") or r.get("id") or r.get("rid")
        role_name = r.get("role_name") or r.get("name") or r.get("role")
        perms_field = r.get("permissions") or r.get("perms") or r.get("allowed_actions") or []
        if isinstance(perms_field, list):
            permissions = ",".join([str(p) for p in perms_field])
        else:
            permissions = str(perms_field)
        rows.append({
            "role_id": role_id,
            "role_name": role_name,
            "permissions": permissions,
            "raw": r,
        })

    columns = ["role_id", "role_name", "permissions", "raw"]
    return Evidence(
        name="soludev_roles",
        description="SoluDev roles and permissions",
        columns=columns,
        rows=rows,
    )

# -------------------------
# ANECDOTES HELPERS
# -------------------------
def get_jwt_token(force_refresh: bool = False) -> str:
    """
    Return a cached JWT token if it's less than 50 minutes old,
    otherwise exchange the API key for a new one.
    """
    import time

    # JWT expires in ~1h → refresh after 50 minutes
    if (
        not force_refresh
        and _jwt_cache["token"]
        and (time.time() - _jwt_cache["timestamp"]) < 3000
    ):
        return _jwt_cache["token"]

    api_token = os.getenv("ANECDOTES_API_TOKEN")
    if not api_token:
        raise RuntimeError("ANECDOTES_API_TOKEN is not set in environment")

    url = "https://gateway.anecdotes.ai/identity/v1/apikey/exchange"
    headers = {
        "accept": "text/plain",
        "x-anecdotes-api-key": api_token
    }

    logger.info("Requesting new JWT token from Anecdotes...")
    response = requests.get(url, headers=headers, timeout=15)

    if response.status_code != 200:
        raise RuntimeError(f"Failed to obtain JWT token: {response.status_code} - {response.text}")

    jwt_token = response.text.strip()
    _jwt_cache["token"] = jwt_token
    _jwt_cache["timestamp"] = time.time()

    logger.info("JWT token retrieved and cached")
    return jwt_token
    
def anecdotes_headers() -> dict:
    jwt_token = get_jwt_token()
    return {
        "Authorization": f"Bearer {jwt_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

def push_evidence_to_anecdotes(sess: requests.Session, evidence: "Evidence") -> None:
    """
    Upload the CSV evidence file to Anecdotes via the 'attach' endpoint.
    """
    # Map evidence name → Anecdotes evidence API ID
    evidence_api_map = {
        "soludev_users": "api_2790063117048",
        "soludev_roles": "api_2740514134242",
    }

    evidence_name = evidence.name
    evidence_id = evidence_api_map.get(evidence_name)
    if not evidence_id:
        raise RuntimeError(f"Unknown evidence name: {evidence_name}")

    # Determine CSV path (written earlier)
    output_dir = os.path.join(os.getcwd(), "evidence_output")
    csv_path = os.path.join(output_dir, f"{evidence_name}.csv")

    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Evidence file not found: {csv_path}")

    jwt_token = get_jwt_token()
    url = f"https://gateway.anecdotes.ai/evidence/v1/evidence/{evidence_id}/attach"

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {jwt_token}",
    }

    files = {
        "evidence_file": (os.path.basename(csv_path), open(csv_path, "rb"), "text/csv")
    }

    logger.info("Pushing evidence '%s' to Anecdotes (%s)", evidence_name, evidence_id)
    resp = sess.post(url, headers=headers, files=files, timeout=60)

    if resp.status_code not in (200, 201):
        logger.error("Failed to push evidence '%s': %s - %s", evidence_name, resp.status_code, resp.text)
        raise RuntimeError(f"Failed to push evidence {evidence_name}: {resp.status_code}")
    else:
        logger.info("Successfully uploaded evidence '%s' (%d bytes)", evidence_name, os.path.getsize(csv_path))

# -------------------------
# MAIN RUN LOGIC
# -------------------------
def sync_soludev_to_anecdotes(sess: requests.Session) -> None:
    """
    Main synchronization routine:
    - Fetch users and roles from SoluDev
    - Normalize them into structured evidence
    - Save as CSVs
    - Upload to Anecdotes via the evidence API
    """
    token = soludev_authenticate(sess)

    # Fetch & normalize
    raw_users = soludev_get(sess, token, "/users")
    raw_roles = soludev_get(sess, token, "/roles")

    users_evidence = normalize_users(raw_users)
    roles_evidence = normalize_roles(raw_roles)

    output_dir = os.path.join(os.getcwd(), "evidence_output")
    os.makedirs(output_dir, exist_ok=True)

    users_csv_path = os.path.join(output_dir, "soludev_users.csv")
    roles_csv_path = os.path.join(output_dir, "soludev_roles.csv")

    def write_csv(evidence: "Evidence", path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=evidence.columns)
            writer.writeheader()
            for row in evidence.rows:
                clean_row = {
                    k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
                    for k, v in row.items()
                }
                writer.writerow(clean_row)

    write_csv(users_evidence, users_csv_path)
    write_csv(roles_evidence, roles_csv_path)

    logger.info("CSV evidence files written:")
    logger.info("  Users: %s", users_csv_path)
    logger.info("  Roles: %s", roles_csv_path)

    push_evidence_to_anecdotes(sess, users_evidence)
    push_evidence_to_anecdotes(sess, roles_evidence)

    logger.info("Sync completed successfully (CSV upload mode)")

def main():
    logger.info("Starting SoluDev -> Anecdotes plugin")
    try:
        sync_soludev_to_anecdotes(session)
    except Exception as e:
        logger.exception("Unhandled exception in plugin: %s", e)
        sys.exit(2)

if __name__ == "__main__":
    main()
