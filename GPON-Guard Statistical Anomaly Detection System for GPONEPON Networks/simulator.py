"""
simulator.py — simulates a GPON access network (1 OLT, 4 PON ports, 32 ONUs/port = 128 ONUs)
and periodically injects PHYSICAL-LAYER SECURITY EVENTS on top of normal telemetry noise:

  ROGUE_ONU        -> an unregistered/unauthorized ONU serial attempts to join a PON port
                       (models an attacker splicing into the fiber and inserting their own ONU
                       to eavesdrop or steal bandwidth — a known GPON downstream-encryption weak
                       spot since not all deployments enforce AES-128 on the downlink)
  SIGNAL_TAMPER     -> sudden abnormal Rx power drop/spike on a legitimate ONU, consistent with
                       an unauthorized fiber tap, splice, or connector interference
  BRUTE_FORCE       -> repeated failed logins against the OLT's management web console
  TRAFFIC_ANOMALY   -> a single ONU suddenly generating traffic far outside its historical
                       baseline (compromised CPE used for DDoS / bandwidth theft)

This is a SIMULATION for research/demo purposes — no real network traffic or hardware is
touched. It exists to give the detection engine (detector.py) realistic signals to reason about.
"""

import random
import time
import threading
import db

NUM_PON_PORTS = 4
ONUS_PER_PORT = 32

# Registered/whitelisted ONU serials (the legitimate fleet)
ONU_REGISTRY = {}
for port in range(1, NUM_PON_PORTS + 1):
    for idx in range(1, ONUS_PER_PORT + 1):
        onu_id = f"PON{port}-ONU{idx}"
        ONU_REGISTRY[onu_id] = f"HWTC{port:02d}{idx:03d}{random.randint(1000,9999)}"

# Baseline "healthy" ranges per ONU (used both to generate data and to detect drift)
BASELINES = {
    onu_id: {
        "rx_power": round(random.uniform(-22.0, -18.0), 2),  # dBm, typical GPON downstream
        "temperature": round(random.uniform(38.0, 46.0), 1),  # Celsius
        "voltage": round(random.uniform(3.2, 3.4), 2),        # Volts
        "traffic_mbps": round(random.uniform(5.0, 40.0), 1),
    }
    for onu_id in ONU_REGISTRY
}

SIM_LOGINS = ["admin", "root", "olt-admin", "supervisor"]
ATTACKER_IPS = ["203.0.113.45", "198.51.100.23", "192.0.2.77"]


def _jitter(value, spread):
    return value + random.uniform(-spread, spread)


def generate_normal_reading(onu_id):
    b = BASELINES[onu_id]
    return {
        "ts": time.time(),
        "onu_id": onu_id,
        "serial": ONU_REGISTRY[onu_id],
        "rx_power": round(_jitter(b["rx_power"], 0.4), 2),
        "tx_power": round(_jitter(2.0, 0.3), 2),
        "temperature": round(_jitter(b["temperature"], 1.0), 1),
        "voltage": round(_jitter(b["voltage"], 0.03), 2),
        "traffic_mbps": round(max(0.1, _jitter(b["traffic_mbps"], 3.0)), 1),
    }


def inject_signal_tamper(onu_id):
    """Simulate a fiber tap / tamper: abrupt, large Rx power deviation."""
    reading = generate_normal_reading(onu_id)
    drop = random.choice([-1, 1]) * random.uniform(6.0, 12.0)
    reading["rx_power"] = round(reading["rx_power"] + drop, 2)
    return reading


def inject_traffic_anomaly(onu_id):
    reading = generate_normal_reading(onu_id)
    reading["traffic_mbps"] = round(reading["traffic_mbps"] * random.uniform(8, 15), 1)
    return reading


def inject_rogue_onu():
    """A serial NOT in ONU_REGISTRY tries to register on a random PON port."""
    port = random.randint(1, NUM_PON_PORTS)
    fake_serial = f"UNKN{random.randint(100000,999999)}"
    fake_onu_id = f"PON{port}-ROGUE"
    return {
        "ts": time.time(),
        "onu_id": fake_onu_id,
        "serial": fake_serial,
        "rx_power": round(random.uniform(-25, -15), 2),
        "tx_power": round(random.uniform(1.5, 2.5), 2),
        "temperature": round(random.uniform(30, 50), 1),
        "voltage": round(random.uniform(3.1, 3.5), 2),
        "traffic_mbps": round(random.uniform(0.5, 5.0), 1),
    }


def inject_brute_force():
    ip = random.choice(ATTACKER_IPS)
    for _ in range(random.randint(6, 10)):
        db.insert_auth_attempt(ip, random.choice(SIM_LOGINS), success=False)
    return ip


class Simulator(threading.Thread):
    """Background thread: pushes telemetry every tick, occasionally injects an attack/fault."""

    def __init__(self, tick_seconds=2, attack_probability=0.12, on_event=None):
        super().__init__(daemon=True)
        self.tick_seconds = tick_seconds
        self.attack_probability = attack_probability
        self.on_event = on_event  # callback(event_dict) -> called for the detector to react to
        self._stop = threading.Event()
        self._onu_cycle = list(ONU_REGISTRY.keys())

    def stop(self):
        self._stop.set()

    def run(self):
        i = 0
        while not self._stop.is_set():
            # Push normal telemetry for a rotating batch of ONUs each tick (keeps DB size sane)
            batch = random.sample(self._onu_cycle, k=8)
            for onu_id in batch:
                reading = generate_normal_reading(onu_id)
                db.insert_telemetry(reading)

            # Occasionally inject an attack/fault scenario
            if random.random() < self.attack_probability:
                scenario = random.choice(
                    ["rogue_onu", "signal_tamper", "brute_force", "traffic_anomaly"]
                )
                if scenario == "rogue_onu":
                    reading = inject_rogue_onu()
                    db.insert_telemetry(reading)
                    if self.on_event:
                        self.on_event({"type": "rogue_onu", "reading": reading})
                elif scenario == "signal_tamper":
                    onu_id = random.choice(self._onu_cycle)
                    reading = inject_signal_tamper(onu_id)
                    db.insert_telemetry(reading)
                    if self.on_event:
                        self.on_event({"type": "signal_tamper", "reading": reading})
                elif scenario == "traffic_anomaly":
                    onu_id = random.choice(self._onu_cycle)
                    reading = inject_traffic_anomaly(onu_id)
                    db.insert_telemetry(reading)
                    if self.on_event:
                        self.on_event({"type": "traffic_anomaly", "reading": reading})
                elif scenario == "brute_force":
                    ip = inject_brute_force()
                    if self.on_event:
                        self.on_event({"type": "brute_force", "source_ip": ip})

            i += 1
            time.sleep(self.tick_seconds)
