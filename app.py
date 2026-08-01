"""
app.py — GPON-Guard: Physical-Layer Security & Anomaly Detection for GPON/EPON Networks

Entry point. Starts the background simulator (feeds telemetry + injects attack scenarios),
wires it to the detection engine, and serves a live Flask dashboard + REST API.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

from flask import Flask, jsonify, render_template
import db
import detector
from simulator import Simulator, ONU_REGISTRY

app = Flask(__name__)

db.init_db()


def on_simulator_event(event):
    detector.handle_event(event)


sim = Simulator(tick_seconds=2, attack_probability=0.15, on_event=on_simulator_event)
sim.start()


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    return jsonify(db.counts_summary())


@app.route("/api/onus")
def api_onus():
    latest = db.get_latest_telemetry_all()
    return jsonify(latest)


@app.route("/api/alerts")
def api_alerts():
    return jsonify(db.get_recent_alerts(limit=50))


@app.route("/api/registry")
def api_registry():
    return jsonify({"total_registered_onus": len(ONU_REGISTRY)})


if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)
