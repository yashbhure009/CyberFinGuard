from flask import Flask, request, jsonify
from importlib import import_module

try:
    CORS = import_module('flask_cors').CORS
except ImportError:
    def CORS(_app):
        """No-op fallback when flask-cors is not installed."""
        return None
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

# In-memory store (use DB for production)
scan_config = {
    "target_url": None,
    "cloud": {"provider": None, "account_id": None, "role_arn": None},
    "identity": {"url": None, "realm": None, "client_id": None, "client_secret": None},
    "business": {
        "asset_name": None, "asset_type": None, "business_unit": None,
        "asset_owner": None, "business_value": None,
        "downtime_cost": None, "recovery_cost": None
    }
}


@app.route('/api/config/website', methods=['POST'])
def set_website():
    data = request.json
    scan_config['target_url'] = data.get('target_url')
    return jsonify({"status": "ok", "target_url": scan_config['target_url']})


@app.route('/api/config/cloud', methods=['POST'])
def set_cloud():
    data = request.json
    scan_config['cloud'] = {
        "provider": data.get('provider'),
        "account_id": data.get('account_id'),
        "role_arn": data.get('role_arn')
    }
    return jsonify({"status": "ok", "cloud": scan_config['cloud']})


@app.route('/api/config/identity', methods=['POST'])
def set_identity():
    data = request.json
    scan_config['identity'] = {
        "url": data.get('keycloak_url'),
        "realm": data.get('realm'),
        "client_id": data.get('client_id'),
        "client_secret": data.get('client_secret')
    }
    return jsonify({"status": "ok", "identity": scan_config['identity']})


@app.route('/api/config/business', methods=['POST'])
def set_business():
    data = request.json
    scan_config['business'] = {
        "asset_name": data.get('asset_name'),
        "asset_type": data.get('asset_type'),
        "business_unit": data.get('business_unit'),
        "asset_owner": data.get('asset_owner'),
        "business_value": data.get('business_value'),
        "downtime_cost": data.get('downtime_cost'),
        "recovery_cost": data.get('recovery_cost')
    }
    return jsonify({"status": "ok", "business": scan_config['business']})


@app.route('/api/scan/run', methods=['POST'])
def run_scan():
    """Run full pipeline with user-provided config."""
    target = scan_config.get('target_url')
    if not target:
        return jsonify({"error": "Target URL not set"}), 400

    # Save config to file so pipeline can read it
    config_file = os.path.join(os.path.dirname(__file__), '..', 'scan_config.json')
    with open(config_file, 'w') as f:
        json.dump(scan_config, f, indent=2)

    # Run pipeline
    try:
        result = subprocess.run(
            ['python', 'main.py', target],
            capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(__file__))
        )
        return jsonify({
            "status": "ok",
            "stdout": result.stdout[-2000:],  # last 2000 chars
            "stderr": result.stderr[-1000:],
            "config": scan_config
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)