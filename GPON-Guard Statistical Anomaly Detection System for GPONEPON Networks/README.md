# GPON-Guard
### Physical-Layer Security & Anomaly Detection for GPON/EPON Access Networks

A companion security layer to the **ISP Network Monitoring & Fault Detection System**
(github.com/Praveen-nac/isp-network-monitoring-system). Where that project answers
*"is the network healthy?"*, GPON-Guard answers *"is something on this network being
tampered with, spoofed, or attacked?"*

## Why this project exists

Most cybersecurity tooling is built for IT systems — servers, cloud, web apps. The access
layer of a broadband network (OLT, ONUs, the fiber itself) is largely invisible to that
tooling, even though it's physically reachable by anyone with access to a fiber cabinet,
splice closet, or roadside cabinet. A field engineer who has spent years racking OLTs and
splicing fiber sees a different threat surface than a SOC analyst does — that's the gap this
project is built to demonstrate.

GPON-Guard simulates a realistic 1-OLT / 4-port / 128-ONU access network and layers a
detection engine on top of it that watches for four scenario classes:

| Scenario | What it models | Detection method |
|---|---|---|
| **Rogue ONU** | An unauthorized ONU (unknown serial) attempts to register on a PON port — e.g. an attacker splicing into the fiber to insert their own device | Whitelist check against a registered-serial database |
| **Signal tampering** | Abrupt, abnormal Rx optical power deviation on a legitimate ONU — consistent with a fiber tap, unauthorized splice, or connector interference | Rolling z-score against each ONU's own historical baseline |
| **OLT console brute-force** | Repeated failed logins against the OLT's management interface | Rate-based rule (N failures / IP / time window) |
| **Traffic anomaly** | A single ONU suddenly generating traffic far outside its baseline — compromised CPE used for bandwidth theft or as a DDoS source | Rolling z-score on traffic volume |

## Architecture

```
Simulator thread (simulator.py)
   |  generates telemetry every tick for a rotating ONU batch
   |  occasionally injects one of the 4 attack/fault scenarios
   v
SQLite (db.py)  <-----lookups----- Detector (detector.py)
   |  telemetry, alerts, auth_attempts tables       - rule-based checks
   |                                                  - rolling z-score checks
   v
Flask REST API (app.py)  ->  /api/summary  /api/onus  /api/alerts
   |
   v
Live dashboard (templates/index.html + static/app.js)
   - PON topology view (color-coded by alert severity)
   - live per-ONU telemetry table
   - real-time alert feed
```

This mirrors the same pipeline shape as the monitoring project (collector → storage → API →
dashboard) but adds a **detection layer** in between storage and the API — the same pattern
production intrusion-detection systems use (collect → baseline → flag deviation → alert).

## Detection approach — why two methods, not one

- **Rule-based** catches known signatures instantly (a rogue serial, a login flood) but only
  catches what you already thought to write a rule for.
- **Statistical baseline drift (rolling z-score)** catches things you didn't anticipate — any
  ONU metric that moves far enough from *its own* recent history gets flagged, regardless of
  whether it matches a known pattern. This is the same underlying idea as more advanced
  anomaly-detection methods (e.g. Isolation Forest, One-Class SVM) but implemented in a
  transparent, explainable way that's easy to reason about and defend.

Combining both is deliberate: it's the same "signature + anomaly" hybrid design real
network-security tooling uses, applied to a domain (PON physical layer) that mainstream tools
don't cover.

## Running it

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`. The simulator starts automatically and begins generating
telemetry immediately; attack scenarios are injected at a configurable probability
(`attack_probability` in `simulator.py`, default 15% per tick) so alerts appear within the
first minute without needing to wait.

## Future work (good material for a research statement)

- Replace the rolling z-score with a trained **Isolation Forest** per ONU class, and compare
  false-positive rates against the simple statistical baseline.
- Model **downstream encryption weaknesses**: some GPON deployments don't enforce AES-128 on
  the downlink by default, which theoretically permits a correctly-positioned rogue ONU to
  eavesdrop on other subscribers' traffic — worth simulating as a follow-on scenario.
- Correlate alerts geographically/topologically (e.g. multiple signal-tamper alerts on the
  same PON port in a short window is a stronger signal than one isolated event).
- Feed real OLT SNMP/TR-069 telemetry into the same detection engine instead of simulated
  data, as a bridge from this prototype to a real deployment.
- Formal evaluation: precision/recall of the detector against labeled injected-attack ground
  truth (the simulator already knows exactly when and where it injected each scenario, so
  this is a straightforward next step).

## Tech stack

Python, Flask, SQLite, vanilla JS/CSS — deliberately the same stack as the monitoring
project, so this reads as a natural extension of that work rather than a disconnected
side-project.
