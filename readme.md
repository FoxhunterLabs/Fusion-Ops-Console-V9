# Fusion Ops V9

Deterministic, replayable operations console focused on safety‑bounded autonomy, human oversight, and auditability.

This repository is an architecture‑first research prototype. The code exists to make the ideas concrete, inspectable, and falsifiable.

---

## What This Is

Fusion Ops V9 is a single‑process ops console that demonstrates:

* Deterministic state transitions
* Tamper‑evident journaling with full replay
* Threat doctrine driven by system integrity
* Human‑in‑the‑loop gating for side‑effecting actions
* Advisory‑only ML observation (no actuation authority)
* Synthetic telemetry with controlled fault injection

The system is designed so that **every decision can be explained, replayed, and audited**.

---

## What This Is Not

* Not a production system
* Not a framework or SDK
* Not optimized for performance or scale

It is intentionally built as a visible, end‑to‑end system to make architecture, constraints, and tradeoffs explicit.

---

## Requirements

* Python 3.10+
* pip

### Python Dependencies

```bash
pip install streamlit numpy pandas pydeck
```

---

## Run

```bash
streamlit run app.py
```

Optional environment variables:

* `FUSIONOPS_PROD_LOCKDOWN=1` — disables remote JS and visual effects
* `FUSIONOPS_ALLOW_REMOTE_JS=1` — enables particle background
* `FUSIONOPS_JOURNAL_SECRET=...` — enables HMAC signing for journal entries

---

## Design Notes

* ML components are **advisory only** and are explicitly prevented from taking actions
* All side‑effecting actions are gated by policy, integrity thresholds, and human approval
* Replay is deterministic across machines given identical inputs
* Journal integrity is enforced via hash chaining (and optional HMAC)

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
