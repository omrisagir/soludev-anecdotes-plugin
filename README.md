# soludev-anecdotes-plugin


This repo contains the SoluDev → Anecdotes plugin used for the Anecdotes Solutions Engineer home assignment.


It includes:
- `soludev_anecdotes_plugin.py` — the main plugin (fetches users & roles, writes CSVs, exchanges API key for JWT, uploads evidence).
- `health_app.py` — a minimal Flask app that exposes `/health` and `/metrics` endpoints to prove the program is running.
- `systemd/` — example systemd service and timer units for running the plugin and health app on a VM.
- `requirements.txt` — Python dependencies.


## Quick setup (on the VM)


1. Ensure you have Python 3.10+ installed.
2. Copy repository to `/home/<user>/soludev-anecdotes-plugin` or clone from GitHub.
3. Create virtualenv and install deps:


```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
