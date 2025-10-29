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

Configure environment variables — recommended in /etc/default/soludev_plugin:

SOLUDEV_BASE_URL="http://10.1.0.14:8080"
SOLUDEV_USERNAME="admin"
SOLUDEV_API_KEY="admin-api-key-12345"
ANECDOTES_API_TOKEN="<YOUR_API_TOKEN>"
LOG_LEVEL="INFO"

Save the file and chmod 640 /etc/default/soludev_plugin.

Start the health endpoint (optional systemd service provided) and verify:

sudo systemctl enable --now systemd/health_app.service
curl http://localhost:5000/health

Start the main plugin via systemd timer (example provided):

sudo cp systemd/anecdotes_plugin.service /etc/systemd/system/
sudo cp systemd/anecdotes_plugin.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now anecdotes_plugin.timer

Logs: journalctl -u anecdotes_plugin.service -f

Exposing a public link (health endpoint)

If the VM has an external IP: either open the VM firewall port 5000 for your IP or use an SSH tunnel or ngrok for a temporary HTTPS link. See the step-by-step doc in this repo for exact commands.

Pushing to GitHub

git init in the repository root

git add . git commit -m "Initial commit"

Create an empty repo on GitHub and follow the git remote add origin ... and git push -u origin main steps.
