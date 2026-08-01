# GPON-Guard

Statistical Anomaly Detection System for GPON/EPON Networks

## About this project

After building my ISP Network Monitoring & Fault Detection System (see
github.com/Praveen-nac/isp-network-monitoring-system), I wanted to go a step further. That
project tells you if the network is healthy. It doesn't tell you if someone is attacking it.

So I started testing what a security layer for the same kind of network would actually look
like. Most cybersecurity work out there is built around servers, cloud, and web apps. Almost
nobody looks at the physical access layer of a broadband network — the OLT, the ONUs, the
fiber itself — even though I deal with that layer hands-on every day and know how exposed it
actually is. Anyone with access to a splice closet or a roadside cabinet can physically touch
it. That gap is what pushed me to build this.

I reused the same stack and the same overall pipeline design from my monitoring project
(collector -> storage -> API -> dashboard), and on top of that, learning from how that
project's fault-detection logic worked, I built out a proper detection engine for security
events instead of just faults.

## What it actually detects

I simulate a realistic access network — 1 OLT, 4 PON ports, 128 ONUs — and inject four kinds
of attack/tamper scenarios into it to test the detection logic against:

**Rogue ONU** — an unregistered device tries to join a PON port. This models someone
splicing into the fiber and inserting their own ONU. Caught with a simple whitelist check
against known serial numbers.

**Signal tampering** — a legitimate ONU's Rx optical power suddenly jumps or drops outside
its normal range, which is what you'd expect from a fiber tap, an unauthorized splice, or
someone messing with the connector. Caught using a rolling z-score against that ONU's own
recent history, not a fixed threshold, because normal signal levels vary ONU to ONU.

**OLT console brute-force** — repeated failed logins against the OLT's management
interface from the same source in a short window.

**Traffic anomaly** — an ONU suddenly sending traffic far above its baseline, which could
mean the customer's device has been compromised and is being used for bandwidth theft or as
part of a DDoS.

## How it's built

- `simulator.py` generates telemetry continuously for all 128 ONUs and occasionally injects
  one of the four scenarios above
- `db.py` stores everything in SQLite — telemetry, alerts, login attempts
- `detector.py` is the actual detection logic — some of it is rule-based (fast, catches
  known patterns), some of it is statistical baseline drift using z-scores (catches things
  that don't match a known signature but still look wrong)
- `app.py` serves a Flask REST API on top of all this
- the dashboard (templates + static JS) shows it live — a PON topology map, a live telemetry
  table, and an alert feed

I went with rule-based + statistical detection together on purpose, not just one. Rules catch
what you already thought to check for. The statistical side catches what you didn't. That's
the same basic idea real intrusion detection systems use, just applied to a part of the
network almost nothing else is built for.

## Running it

```
pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000. It starts generating data immediately and injects an
attack scenario roughly every few ticks, so you'll see alerts within the first minute.

## What I'd add next

- Swap the z-score logic for a trained Isolation Forest and actually compare false-positive
  rates between the two
- Simulate the encryption-weakness angle too — some GPON deployments don't enforce AES-128 on
  the downlink, which in theory lets a well-positioned rogue ONU eavesdrop on other
  subscribers' traffic
- Correlate alerts across a PON port instead of treating each one in isolation — multiple
  signal-tamper events on the same port in a short window means a lot more than one alone
- Eventually feed in real OLT SNMP/TR-069 data instead of simulated data
- Run a proper precision/recall evaluation against the simulator's own ground truth, since it
  already knows exactly when and where it injected each attack

## Stack

Python, Flask, SQLite, plain JS/CSS. Same stack as my monitoring project, on purpose — this
is meant to sit next to that project, not as something unrelated.
