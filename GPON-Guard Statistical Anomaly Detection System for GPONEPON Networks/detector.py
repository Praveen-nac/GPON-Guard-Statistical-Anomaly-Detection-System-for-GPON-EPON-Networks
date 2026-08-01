"""
detector.py — the actual "cybersecurity brain" of GPON-Guard.

Two detection strategies, combined:

1. RULE-BASED (fast, deterministic, catches known attack patterns):
     - Unregistered ONU serial requests to join the PON  -> ROGUE_ONU (critical)
     - >=5 failed OLT-console logins from one IP within 60s -> BRUTE_FORCE (high)

2. STATISTICAL / BASELINE-DRIFT (catches unknown / novel anomalies, not just signatures):
     - Rolling z-score on Rx power, temperature, voltage, traffic per ONU.
       |z| > 3  -> SIGNAL_TAMPER or TRAFFIC_ANOMALY, severity scaled by how extreme z is.
     This is the same statistical idea used in real intrusion-detection / anomaly-detection
     research (e.g. isolation forests, control charts) but implemented here with a simple,
     explainable rolling z-score so it's easy to defend in a viva/interview and easy to swap
     for sklearn's IsolationForest later (see README "Future Work").

ONU_REGISTRY is imported from simulator so the detector knows which serials are legitimate.
"""

import statistics
import db
from simulator import ONU_REGISTRY

Z_THRESHOLD = 3.0
MIN_SAMPLES_FOR_ZSCORE = 6
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60  # seconds


def _zscore(history, current):
    if len(history) < MIN_SAMPLES_FOR_ZSCORE:
        return 0.0
    mean = statistics.mean(history)
    stdev = statistics.pstdev(history) or 0.01  # avoid divide-by-zero
    return (current - mean) / stdev


def _severity_from_z(z):
    z = abs(z)
    if z >= 6:
        return "critical"
    if z >= 4.5:
        return "high"
    return "medium"


def check_rogue_onu(reading):
    onu_id = reading["onu_id"]
    serial = reading["serial"]
    if ONU_REGISTRY.get(onu_id) != serial:
        db.insert_alert(
            onu_id, "security", "ROGUE_ONU", "critical",
            f"Unregistered ONU serial '{serial}' attempted to join as '{onu_id}'. "
            f"Not present in the whitelist — possible unauthorized fiber tap / device insertion."
        )
        return True
    return False


def check_signal_and_metrics(reading):
    onu_id = reading["onu_id"]
    history = db.get_recent_telemetry(onu_id, limit=20)
    if len(history) < MIN_SAMPLES_FOR_ZSCORE:
        return

    for field, label, event_type in [
        ("rx_power", "Rx optical power", "SIGNAL_TAMPER"),
        ("temperature", "temperature", "THERMAL_ANOMALY"),
        ("voltage", "voltage", "POWER_ANOMALY"),
        ("traffic_mbps", "traffic volume", "TRAFFIC_ANOMALY"),
    ]:
        past_values = [h[field] for h in history[:-1]]
        current = history[-1][field]
        z = _zscore(past_values, current)
        if abs(z) >= Z_THRESHOLD:
            severity = _severity_from_z(z)
            direction = "spike" if z > 0 else "drop"
            db.insert_alert(
                onu_id, "security" if event_type in ("SIGNAL_TAMPER", "TRAFFIC_ANOMALY") else "fault",
                event_type, severity,
                f"{label.capitalize()} {direction} on {onu_id}: {current} "
                f"(z-score {z:.2f} vs rolling baseline) — possible {label} tampering or fault."
            )


def check_brute_force(source_ip):
    attempts = db.get_recent_auth_attempts(source_ip, window_seconds=BRUTE_FORCE_WINDOW)
    failed = [a for a in attempts if not a["success"]]
    if len(failed) >= BRUTE_FORCE_THRESHOLD:
        db.insert_alert(
            None, "security", "BRUTE_FORCE", "high",
            f"{len(failed)} failed OLT web-console login attempts from {source_ip} "
            f"within {BRUTE_FORCE_WINDOW}s — likely credential brute-forcing."
        )


def handle_event(event):
    """Callback wired into the Simulator thread — routes each injected scenario to the
    right detection routine. Also runs statistical checks on the freshest reading."""
    etype = event["type"]
    if etype == "rogue_onu":
        check_rogue_onu(event["reading"])
    elif etype in ("signal_tamper", "traffic_anomaly"):
        check_signal_and_metrics(event["reading"])
    elif etype == "brute_force":
        check_brute_force(event["source_ip"])
