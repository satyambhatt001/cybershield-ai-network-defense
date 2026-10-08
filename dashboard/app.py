import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import logging
from flask import Flask, render_template, jsonify
import config
from core.logger import read_alerts

log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/alerts")
def api_alerts():
    alerts = read_alerts(50)
    return jsonify(alerts)


@app.route("/api/arp_table")
def api_arp_table():
    if os.path.exists(config.ARP_TABLE_FILE):
        with open(config.ARP_TABLE_FILE) as f:
            return jsonify(json.load(f))
    return jsonify({})


@app.route("/api/status")
def api_status():
    return jsonify({
        "interface"  : config.INTERFACE,
        "auto_block" : config.AUTO_BLOCK,
        "trusted_dns": config.TRUSTED_DNS_SERVER,
        "gateway_ip" : config.GATEWAY_IP,
        "status"     : "RUNNING"
    })


@app.route("/api/blocked")
def api_blocked():
    alerts  = read_alerts(200)
    blocked = []
    for a in alerts:
        if a.get("action") in ("ARP_BLOCK", "DNS_BLOCK"):
            target = a.get("target")
            if target and target not in blocked:
                blocked.append(target)
    return jsonify(blocked)


if __name__ == "__main__":
    print(f"[*] Dashboard → http://localhost:{config.DASHBOARD_PORT}")
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=False,
        use_reloader=False
    )
