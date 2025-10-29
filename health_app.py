from flask import Flask, jsonify
import os


app = Flask(__name__)


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'service': 'soludev_plugin', 'time': int(__import__('time').time())})


@app.route('/metrics')
def metrics():
    # simple metric: last run file timestamp if exists
    p = os.path.join(os.getcwd(), 'evidence_output')
    last = None
    try:
        if os.path.isdir(p):
            files = [os.path.join(p, f) for f in os.listdir(p) if f.endswith('.csv')]
            if files:
                last = max(os.path.getmtime(f) for f in files)
    except Exception:
        last = None
    return jsonify({'last_evidence_ts': last})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
