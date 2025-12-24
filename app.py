# app.py
# ================================================================
# Fusion Ops V9 — Ops Console (Unified)
# Deterministic + Replayable + Governed + Tamper-Evident
# Tactical Map Surface + Threat Doctrine + Explainability + Human Gate
# ML Observer (Advisory Only): Observe → Infer → Signal → Propose (NEVER Act)
# ================================================================

from __future__ import annotations

import os
import json
import math
import time
import copy
import hmac
import hashlib
import platform
import sys
from collections import deque
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Iterable, Set, Literal

import numpy as np
import pandas as pd
import streamlit as st
import pydeck as pdk
import streamlit.components.v1 as components

# ================================================================
# Policy / Ops Flags
# ================================================================

CANON_FLOAT_NDIGITS = 6 # hash-chain policy; replay must agree across machines
PROD_LOCKDOWN = os.getenv("FUSIONOPS_PROD_LOCKDOWN", "0").strip() == "1"
ALLOW_REMOTE_JS = os.getenv("FUSIONOPS_ALLOW_REMOTE_JS", "0").strip() == "1"

# Duplicate detection memory bounds
SEEN_EVENT_IDS_MAX = int(os.getenv("FUSIONOPS_SEEN_EVENT_IDS_MAX", "5000"))

# Simple session-state replay cache sizing (avoids st.cache_data huge keys)
STATE_CACHE_MAX = int(os.getenv("FUSIONOPS_STATE_CACHE_MAX", "32"))

# Optional env fingerprinting (off by default to preserve cross-machine identical head hashes)
INCLUDE_ENV_FINGERPRINT = os.getenv("FUSIONOPS_INCLUDE_ENV_FINGERPRINT", "0").strip() == "1"


def rerun():
try:
st.rerun()
except Exception:
st.experimental_rerun()


# ================================================================
# Page Config
# ================================================================

st.set_page_config(
page_title="Fusion Ops V9",
page_icon="🧭",
layout="wide",
initial_sidebar_state="expanded",
)

# ================================================================
# OPS UI: Dark doctrine, high contrast, realistic HUD aesthetic
# ================================================================

OPS_CSS = """
<style>
:root{
--bg0:#04050a;
--bg1:#070b12;
--panel:#0b131c;
--panel2:#0a1118;

--text:#eef6fb;
--text2:#d6e6ef;
--muted:#a7bccb;
--muted2:#7f94a3;

--cyan:#00E0FF;
--cyan2:#58f3ff;
--violet:#b69cff;

--green:#3CFF98;
--amber:#FFCA28;
--orange:#FF8A3D;
--red:#FF3B5C;
--black:#A7B7C4;

--border: rgba(255,255,255,0.10);
--border2: rgba(0,224,255,0.13);
--shadow: rgba(0,0,0,0.58);
--glow: rgba(0,224,255,0.16);
}

html, body {
background:
radial-gradient(1400px 900px at 18% 12%, #0b2a3b 0%, #05060a 46%, #020308 100%) !important;
color: var(--text) !important;
}

.stApp{
position: relative;
z-index: 1;
}

/* HUD background grid + vignette + scanlines */
body:before{
content:"";
position:fixed; inset:0;
background:
linear-gradient(rgba(88,243,255,0.035) 1px, transparent 1px),
linear-gradient(90deg, rgba(88,243,255,0.022) 1px, transparent 1px);
background-size: 42px 42px, 42px 42px;
opacity: 0.35;
pointer-events:none;
z-index:0;
}
body:after{
content:"";
position:fixed; inset:0;
background:
radial-gradient(1200px 800px at 50% 30%, rgba(0,224,255,0.08), transparent 60%),
radial-gradient(1200px 900px at 50% 70%, rgba(255,59,92,0.05), transparent 65%),
linear-gradient(to bottom, rgba(0,0,0,0.28), rgba(0,0,0,0.55));
pointer-events:none;
z-index:0;
}

/* subtle scanline shimmer */
@keyframes scan {
0% { transform: translateY(-12px); opacity: 0.12; }
50% { opacity: 0.18; }
100% { transform: translateY(12px); opacity: 0.12; }
}
.scanlines{
position:fixed; inset:0;
background: repeating-linear-gradient(
to bottom,
rgba(255,255,255,0.025),
rgba(255,255,255,0.025) 1px,
rgba(0,0,0,0.0) 3px,
rgba(0,0,0,0.0) 6px
);
mix-blend-mode: overlay;
opacity: 0.10;
pointer-events:none;
z-index:0;
animation: scan 6.5s ease-in-out infinite;
}

* { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
a, a:visited { color: var(--cyan2) !important; }

/* Header */
.fusion-title{
font-size: 34px;
font-weight: 950;
letter-spacing: 0.18em;
text-transform: uppercase;
color: var(--cyan);
margin: 6px 0 0 0;
text-shadow: 0 0 18px var(--glow);
}
.fusion-subtitle{
font-size: 12px;
color: var(--muted);
letter-spacing: 0.11em;
margin: -2px 0 10px 0;
}
.banner{
display:flex; gap:10px; align-items:center;
padding: 8px 12px;
border-radius: 14px;
border: 1px solid var(--border);
background: rgba(7,10,14,0.62);
box-shadow: 0 14px 44px var(--shadow);
}
.banner b{ color: var(--cyan2); }
.banner .tag{
font-size: 11px;
letter-spacing: 0.12em;
text-transform: uppercase;
padding: 2px 8px;
border-radius: 999px;
border: 1px solid rgba(255,255,255,0.10);
background: rgba(255,255,255,0.04);
color: var(--muted);
}
.banner .tag.secure{ color: var(--green); border-color: rgba(60,255,152,0.25); }
.banner .tag.advisory{ color: var(--violet); border-color: rgba(182,156,255,0.25); }
.banner .tag.lock{ color: var(--amber); border-color: rgba(255,202,40,0.25); }

/* Cards */
.ops-card{
background: linear-gradient(180deg, rgba(11,19,28,0.88), rgba(9,14,20,0.86));
border: 1px solid var(--border);
border-radius: 16px;
padding: 12px 14px;
box-shadow: 0 14px 48px var(--shadow);
position: relative;
overflow:hidden;
}
.ops-card:before{
content:"";
position:absolute; inset:0;
background: radial-gradient(900px 250px at 10% 0%, rgba(0,224,255,0.10), transparent 60%);
pointer-events:none;
}
.ops-label{
font-size: 11px;
color: var(--muted);
letter-spacing: 0.18em;
text-transform: uppercase;
margin-bottom: 8px;
}
.ops-mono{
font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

/* Status bar */
.statusbar{
display:flex;
flex-wrap: wrap;
gap: 10px;
align-items:center;
justify-content: space-between;
padding: 10px 12px;
border-radius: 16px;
border: 1px solid var(--border);
background: rgba(7,10,14,0.72);
box-shadow: 0 14px 48px var(--shadow);
}
.sb-item{ font-size: 12px; color: var(--text); opacity: 0.99; }
.sb-k{ color: var(--muted); margin-right: 6px; letter-spacing:0.06em; }
.sb-v b{ color: var(--cyan2); text-shadow:0 0 10px rgba(0,224,255,0.16); }

.pill{
display:inline-block;
padding: 2px 9px;
border-radius: 999px;
border: 1px solid var(--border);
background: rgba(255,255,255,0.04);
font-size: 11px;
letter-spacing: 0.12em;
text-transform: uppercase;
}
.pill.green{ color: var(--green); border-color: rgba(60,255,152,0.26); }
.pill.amber{ color: var(--amber); border-color: rgba(255,202,40,0.26); }
.pill.orange{ color: var(--orange); border-color: rgba(255,138,61,0.26); }
.pill.red{ color: var(--red); border-color: rgba(255,59,92,0.26); }
.pill.black{ color: var(--black); border-color: rgba(167,183,196,0.26); }
.pill.violet{ color: var(--violet); border-color: rgba(182,156,255,0.26); }

@keyframes flash-bg {
0% { background: rgba(7,10,14,0.72); }
45% { background: rgba(255,59,92,0.22); }
100% { background: rgba(7,10,14,0.72); }
}
.flash{ animation: flash-bg 0.9s ease-in-out 2; }

@keyframes pulse-ring {
0% { box-shadow: 0 0 0 0 rgba(255,59,92,0.62); }
100% { box-shadow: 0 0 0 14px rgba(255,59,92,0); }
}
.critical-dot{
width: 10px; height: 10px; border-radius: 8px;
display:inline-block; background: var(--red);
margin-right: 8px; animation: pulse-ring 1.2s ease-out infinite;
}

small { color: var(--muted) !important; }

/* Sidebar */
section[data-testid="stSidebar"]{
background: linear-gradient(180deg, rgba(6,10,16,0.94), rgba(4,6,10,0.92));
border-right: 1px solid var(--border);
}

/* Widget legibility */
div[data-testid="stMarkdownContainer"] p,
div[data-testid="stMarkdownContainer"] span,
div[data-testid="stMarkdownContainer"] li { color: var(--text) !important; }

label, .stTextInput label, .stTextArea label, .stSelectbox label,
.stRadio label, .stCheckbox label, .stSlider label {
color: var(--text2) !important;
font-weight: 680 !important;
letter-spacing: 0.02em;
}

input, textarea {
color: var(--text) !important;
background: rgba(255,255,255,0.05) !important;
}

div[data-baseweb="select"] > div {
background: rgba(255,255,255,0.05) !important;
color: var(--text) !important;
border-color: var(--border) !important;
}

div[data-testid="stDataFrame"], div[data-testid="stTable"] {
border: 1px solid var(--border) !important;
border-radius: 12px !important;
overflow: hidden;
}

button[kind="primary"], button[kind="secondary"]{
border-radius: 12px !important;
}

div[data-testid="stToolbar"]{ opacity:0.18; }
</style>
<div class="scanlines"></div>
"""
st.markdown(OPS_CSS, unsafe_allow_html=True)

# ================================================================
# Particles background (optional; disabled in PROD_LOCKDOWN)
# ================================================================

def render_particles_background(enabled: bool):
# Tightened: requires explicit ALLOW_REMOTE_JS and not PROD_LOCKDOWN.
if (not enabled) or PROD_LOCKDOWN or (not ALLOW_REMOTE_JS):
return
html = """
<div id="tsparticles" style="
position: fixed; inset: 0;
z-index: 0;
pointer-events: none;
opacity: 0.42;">
</div>
<script src="https://cdn.jsdelivr.net/npm/tsparticles@3/tsparticles.bundle.min.js"></script>
<script>
(async () => {
if (window.__fusionParticlesInit) return;
window.__fusionParticlesInit = true;
await tsParticles.load({
id: "tsparticles",
options: {
background: { color: { value: "transparent" }},
fpsLimit: 60,
particles: {
number: { value: 92, density: { enable: true, area: 980 }},
color: { value: ["#00E0FF", "#58f3ff", "#a7bccb", "#b69cff"] },
links: { enable: true, distance: 132, color: "#00E0FF", opacity: 0.11, width: 1 },
move: { enable: true, speed: 0.55, outModes: { default: "out" } },
opacity: { value: { min: 0.10, max: 0.38 } },
size: { value: { min: 0.8, max: 2.4 } }
},
interactivity: { events: { resize: true } },
detectRetina: true
}
});
})();
</script>
"""
components.html(html, height=0)

# ================================================================
# Helpers: canonicalization + stable IDs (hardened)
# ================================================================

def _round_floats(x: Any, ndigits: int = CANON_FLOAT_NDIGITS) -> Any:
# numpy scalars -> python scalars (critical for deterministic JSON + replay)
if isinstance(x, (np.floating,)):
x = float(x)
if isinstance(x, (np.integer,)):
x = int(x)
if isinstance(x, (np.bool_,)):
x = bool(x)

# numpy arrays -> lists (avoid non-serializable objects)
if isinstance(x, (np.ndarray,)):
return _round_floats(x.tolist(), ndigits)

# pandas Timestamp -> ISO string (stable)
if isinstance(x, (pd.Timestamp,)):
return x.isoformat()

if isinstance(x, float):
if math.isnan(x):
return "NaN"
if math.isinf(x):
return "Inf" if x > 0 else "-Inf"
return round(x, ndigits)
if isinstance(x, (list, tuple)):
return [_round_floats(v, ndigits) for v in x]
if isinstance(x, (set, frozenset)):
return sorted([_round_floats(v, ndigits) for v in x], key=lambda z: str(z))
if isinstance(x, dict):
return {str(k): _round_floats(v, ndigits) for k, v in sorted(x.items(), key=lambda kv: str(kv[0]))}
return x

def canonical_json(obj: Any) -> str:
return json.dumps(
_round_floats(obj),
sort_keys=True,
separators=(",", ":"),
ensure_ascii=False,
allow_nan=False,
)

def sha256_hex(payload: Any) -> str:
return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

def stable_id(prefix: str, payload: Any) -> str:
h = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:12]
return f"{prefix}_{h}"

def _eid_digest64(eid: str) -> int:
# Stable 64-bit digest for rolling XOR
h = hashlib.sha256(eid.encode("utf-8")).digest()
return int.from_bytes(h[:8], "big", signed=False)

# ================================================================
# Threat Doctrine (V9)
# ================================================================

class ThreatLevel(str, Enum):
GREEN = "GREEN" # normal
AMBER = "AMBER" # elevated
ORANGE = "ORANGE" # severe
RED = "RED" # critical
BLACK = "BLACK" # unsafe / autonomous stop

THREAT_COLOR_CLASS = {
ThreatLevel.GREEN: "green",
ThreatLevel.AMBER: "amber",
ThreatLevel.ORANGE: "orange",
ThreatLevel.RED: "red",
ThreatLevel.BLACK: "black",
}

THREAT_DOCTRINE = [
{"level": ThreatLevel.GREEN, "rule": "Integrity ≥ 0.80 and CriticalInsights == 0",
"meaning": "Nominal. Autonomy permitted within policy.", "ops": "Monitor. No special actions required."},
{"level": ThreatLevel.AMBER, "rule": "0.65 ≤ Integrity < 0.80 OR (CriticalInsights == 0 and Warnings elevated)",
"meaning": "Elevated monitoring. Conditions trending.", "ops": "Increase sampling. Validate feeds. Prep human gate."},
{"level": ThreatLevel.ORANGE, "rule": "0.45 ≤ Integrity < 0.65 OR CriticalInsights in [1..2] OR QuarantineRate high",
"meaning": "Severe. Human must actively supervise.", "ops": "Require approval for side effects. Investigate anomaly source."},
{"level": ThreatLevel.RED, "rule": "0.30 ≤ Integrity < 0.45 OR CriticalInsights ≥ 3",
"meaning": "Critical. High risk of bad actions.", "ops": "Block auto-actions. Force operator acknowledgements. Consider manual mode."},
{"level": ThreatLevel.BLACK, "rule": "Integrity < 0.30 OR data integrity compromised",
"meaning": "Unsafe. Autonomy halted by doctrine.", "ops": "Stop autonomous side effects. Snapshot, contain, audit, recover."},
]

# ================================================================
# Data Models
# ================================================================

class ValidationDisposition(str, Enum):
ACCEPTED = "accepted"
REJECTED = "rejected"
QUARANTINED = "quarantined"

@dataclass
class SourceRuntime:
id: str
name: str
enabled: bool = True
operator_weight: float = 1.0
manual_mode: bool = False

@dataclass(frozen=True)
class EventEnvelope:
event_id: str
source_id: str
ingest_tick: int
event_ts: float
schema_version: str
payload: Dict[str, Any]

@dataclass
class QuarantineEntry:
envelope: EventEnvelope
disposition: ValidationDisposition
reason: str

@dataclass
class Insight:
insight_id: str
source_id: str
tick: int
level: Literal["Info", "Warning", "Critical"]
kind: Literal["clarity", "trust", "correlation", "schema", "threat", "ml"]
msg: str
metrics: Dict[str, float]

@dataclass
class Recommendation:
rec_id: str
insight_id: str
tick: int
level: Literal["Info", "Warning", "Critical"]
action: str
action_class: str
target_source_id: str
rationale: str
confidence: float
requires_approval: bool
blocked_reason: str = ""
integrity_at_issue: float = 1.0
operator_load_at_issue: str = "Low"
threat_at_issue: str = "GREEN"

@dataclass
class Decision:
decision_id: str
tick: int
rec_id: str
choice: Literal["approve", "reject", "defer"]
comment: str

@dataclass
class AutonomyAction:
action_id: str
tick: int
rec_id: str
action_class: str
target_source_id: str
status: Literal["queued", "executed", "blocked"]
note: str = ""
side_effect: bool = False # tightened audit semantics

@dataclass
class TrustComponents:
freshness: float
schema: float
dropout: float
drift: float
manual_penalty: float
operator_weight: float

@dataclass
class TrustSample:
tick: int
total: float
base: float
components: TrustComponents
deltas: Optional[TrustComponents] = None
blame: List[str] = field(default_factory=list)

@dataclass
class SourceStats:
attempts: int = 0
accepted: int = 0
rejected: int = 0
quarantined: int = 0

# Freshness semantics split:
last_attempt_tick: Optional[int] = None # any delivery attempt (accepted/rejected/quarantined)
last_accept_tick: Optional[int] = None # last accepted truth

watermark_ts: Optional[float] = None
enabled_ticks: int = 0
ticks_with_delivery: int = 0
recent_lags: List[float] = field(default_factory=list)

# schema boundary tracking (for threshold-crossing breadcrumbs)
schema_band: int = 0

@dataclass
class PolicyConfig:
integrity_floor: float = 0.30
approval_required_below: float = 0.65
approval_required_for: Set[str] = field(default_factory=lambda: {"escalate", "cross_feed", "set_manual", "schema_investigate"})
always_requires_approval: Set[str] = field(default_factory=lambda: {"set_manual"})
pending_med: int = 3
pending_high: int = 6
suppress_warnings_under_high_load: bool = True

@dataclass
class InjectionConfig:
dropout_rate: float = 0.0
spoof_jitter: float = 0.0
schema_corrupt_rate: float = 0.0
incident_spike_rate: float = 0.0
storm_mode: bool = False

# --- ML Observer (Advisory Only) ---

@dataclass
class MLAssessment:
assessment_id: str
tick: int
signal_type: Literal["ANOMALY", "TREND", "CONFIDENCE", "UNCERTAINTY"]
confidence: float
time_horizon: Literal["SHORT", "MEDIUM", "LONG"]
primary_factors: List[str]
natural_language_summary: str
counterfactual: str
recommendation_class: Literal["REVIEW_REQUIRED", "MONITOR", "NO_ACTION"]
feature_hash: str

@dataclass
class SystemState:
tick: int = 0
sources: Dict[str, SourceRuntime] = field(default_factory=dict)
events: Dict[str, List[EventEnvelope]] = field(default_factory=dict)
quarantine: List[QuarantineEntry] = field(default_factory=list)
stats: Dict[str, SourceStats] = field(default_factory=dict)
metrics_history: Dict[str, List[Dict[str, float]]] = field(default_factory=dict)
trust_history: Dict[str, List[TrustSample]] = field(default_factory=dict)
insights: List[Insight] = field(default_factory=list)
recommendations: List[Recommendation] = field(default_factory=list)
autonomy_actions: List[AutonomyAction] = field(default_factory=list)
decisions: Dict[str, Decision] = field(default_factory=dict)
last_insight_tick: Dict[str, int] = field(default_factory=dict)
last_critical_count: int = 0
critical_flash: bool = False

# bounded duplicate detection memory:
seen_event_ids: Set[str] = field(default_factory=set)
seen_queue: deque[str] = field(default_factory=deque)
seen_ids_xor: int = 0 # rolling XOR of 64-bit digests

injections: InjectionConfig = field(default_factory=InjectionConfig)

# V9 additions
ml_assessments: List[MLAssessment] = field(default_factory=list)
effective_config_hash: str = ""
effective_ml_cfg: Dict[str, Any] = field(default_factory=dict)

@property
def seen_ids_digest(self) -> str:
return f"{int(self.seen_ids_xor) & ((1<<64)-1):016x}"


# ================================================================
# Engine Config
# ================================================================

DEFAULT_CLARITY_CONFIG = {
"window_size": 12,
"vol_warning": 0.35,
"vol_critical": 0.60,
"inst_warning": 0.40,
"inst_critical": 0.65,
"nov_warning": 0.50,
"nov_critical": 0.75,
}
INSIGHT_REFRACTORY_TICKS = 5

DEFAULT_TRUST_WEIGHTS = {
"freshness": 0.30,
"schema": 0.25,
"dropout": 0.25,
"drift": 0.20,
}

DEFAULT_ML_CFG = {
"enabled": True,
"risk_review_threshold": 0.62,
"risk_monitor_threshold": 0.48,
"horizon": "SHORT", # SHORT/MEDIUM/LONG
"mode": "bounded_energy_v1",
}

DEFAULT_POLICY = PolicyConfig()

MAX_EVENTS_PER_SOURCE = 600
MAX_INSIGHTS = 2600
MAX_RECS = 2400
MAX_QUARANTINE = 2400
MAX_ACTIONS = 2400
MAX_ML = 1600

# ================================================================
# Engine Context (pure; no global mutation)
# ================================================================

@dataclass
class EngineContext:
clarity: "ClarityEngine"
trust: "TrustFabric"
tick_dt_s: float
policy: PolicyConfig
ml_cfg: Dict[str, Any]

def _policy_from_dict(d: Dict[str, Any]) -> PolicyConfig:
dd = dict(d or {})
# accept lists from config, convert to sets
if "approval_required_for" in dd and not isinstance(dd["approval_required_for"], set):
dd["approval_required_for"] = set(dd["approval_required_for"])
if "always_requires_approval" in dd and not isinstance(dd["always_requires_approval"], set):
dd["always_requires_approval"] = set(dd["always_requires_approval"])
return PolicyConfig(**dd)

def _clamp01(x: Any, default: float) -> float:
try:
v = float(x)
except Exception:
return float(default)
if math.isnan(v) or math.isinf(v):
return float(default)
return float(np.clip(v, 0.0, 1.0))

def validate_config_update(path: str, value: Any) -> Tuple[bool, Any, str]:
"""
Harden config_update so journal replay cannot nuke required fields or inject nonsense.
Returns (ok, sanitized_value, reason).
"""
p = str(path or "").strip()
if not p:
return False, value, "config_update path empty"

# Disallow changing canon policy via journal
if p in ("canon_float_ndigits",):
return False, value, "config_update cannot change canon_float_ndigits"

# Whole-object updates
if p == "ml":
if not isinstance(value, dict):
return False, value, "ml config must be dict"
v = dict(value)
out = dict(DEFAULT_ML_CFG)

# allow only known keys
allowed = set(DEFAULT_ML_CFG.keys())
for k in list(v.keys()):
if k not in allowed:
v.pop(k, None)

out["enabled"] = bool(v.get("enabled", out["enabled"]))
out["risk_review_threshold"] = _clamp01(v.get("risk_review_threshold", out["risk_review_threshold"]), out["risk_review_threshold"])
out["risk_monitor_threshold"] = _clamp01(v.get("risk_monitor_threshold", out["risk_monitor_threshold"]), out["risk_monitor_threshold"])
hz = str(v.get("horizon", out["horizon"])).upper()
out["horizon"] = hz if hz in ("SHORT", "MEDIUM", "LONG") else "SHORT"
out["mode"] = str(v.get("mode", out["mode"]))
return True, out, "ok"

if p == "policy":
if not isinstance(value, dict):
return False, value, "policy config must be dict"
v = dict(value)
base = asdict(DEFAULT_POLICY)

allowed = set(base.keys())
for k in list(v.keys()):
if k not in allowed:
v.pop(k, None)

# sanitize numeric
out = dict(base)
out["integrity_floor"] = _clamp01(v.get("integrity_floor", out["integrity_floor"]), out["integrity_floor"])
out["approval_required_below"] = _clamp01(v.get("approval_required_below", out["approval_required_below"]), out["approval_required_below"])
out["pending_med"] = int(max(0, v.get("pending_med", out["pending_med"])))
out["pending_high"] = int(max(0, v.get("pending_high", out["pending_high"])))
out["suppress_warnings_under_high_load"] = bool(v.get("suppress_warnings_under_high_load", out["suppress_warnings_under_high_load"]))

# sanitize sets
ar = v.get("approval_required_for", out["approval_required_for"])
aa = v.get("always_requires_approval", out["always_requires_approval"])
out["approval_required_for"] = sorted(list(set(ar))) if isinstance(ar, (list, set, tuple)) else sorted(list(DEFAULT_POLICY.approval_required_for))
out["always_requires_approval"] = sorted(list(set(aa))) if isinstance(aa, (list, set, tuple)) else sorted(list(DEFAULT_POLICY.always_requires_approval))
return True, out, "ok"

# Nested updates (ml.* etc.) are allowed but sanitized at apply-time by re-validation if root replaced.
# For non-ml/policy, accept as-is (still deterministic).
return True, value, "ok"

def make_engine_context(cfg: Dict[str, Any]) -> EngineContext:
pol = _policy_from_dict(cfg.get("policy", {}))
dt = float(cfg.get("tick_dt_s", 1.0))
clarity = ClarityEngine(cfg.get("clarity", DEFAULT_CLARITY_CONFIG))
trust = TrustFabric(cfg.get("trust_weights", DEFAULT_TRUST_WEIGHTS))
ml_cfg = dict(cfg.get("ml", DEFAULT_ML_CFG))
# sanitize ml cfg in case cfg came from journal updates:
ok, ml_cfg2, _ = validate_config_update("ml", ml_cfg)
ml_cfg = ml_cfg2 if ok else dict(DEFAULT_ML_CFG)
return EngineContext(clarity=clarity, trust=trust, tick_dt_s=dt, policy=pol, ml_cfg=ml_cfg)

# ================================================================
# Schema validation (minimal hardened)
# ================================================================

def validate_event(envelope: EventEnvelope) -> Tuple[ValidationDisposition, Dict[str, Any], str]:
p = envelope.payload
if not isinstance(p, dict):
return (ValidationDisposition.REJECTED, {}, "payload not dict")

sid = envelope.source_id
sv = envelope.schema_version
if sv != "v1":
return (ValidationDisposition.QUARANTINED, p, f"unknown schema version {sv}")

def has_num(k: str) -> bool:
return k in p and isinstance(p[k], (int, float, np.integer, np.floating)) and not (
isinstance(p[k], float) and (math.isnan(p[k]) or math.isinf(p[k]))
)

if sid == "ship":
req = ["lat", "lon", "speed", "heading"]
if not all(has_num(k) for k in req):
return (ValidationDisposition.REJECTED, p, "ship missing/invalid fields")
if not (-90 <= float(p["lat"]) <= 90 and -180 <= float(p["lon"]) <= 180):
return (ValidationDisposition.QUARANTINED, p, "ship lat/lon out of bounds")
return (ValidationDisposition.ACCEPTED, p, "ok")

if sid == "air":
req = ["lat", "lon", "alt", "speed", "heading"]
if not all(has_num(k) for k in req):
return (ValidationDisposition.REJECTED, p, "air missing/invalid fields")
if not (-90 <= float(p["lat"]) <= 90 and -180 <= float(p["lon"]) <= 180):
return (ValidationDisposition.QUARANTINED, p, "air lat/lon out of bounds")
return (ValidationDisposition.ACCEPTED, p, "ok")

if sid == "incident":
if not (has_num("value") and has_num("severity")):
return (ValidationDisposition.REJECTED, p, "incident missing/invalid fields")
return (ValidationDisposition.ACCEPTED, p, "ok")

if sid == "weather":
req = ["wind", "value"]
if not all(has_num(k) for k in req):
return (ValidationDisposition.REJECTED, p, "weather missing/invalid fields")
return (ValidationDisposition.ACCEPTED, p, "ok")

return (ValidationDisposition.QUARANTINED, p, f"unknown source_id {sid}")

# ================================================================
# Clarity Engine
# ================================================================

class ClarityEngine:
def __init__(self, config: Dict[str, Any]):
self.config = config

@staticmethod
def _volatility(events: List[EventEnvelope]) -> float:
if len(events) < 4:
return 0.0
speeds = [float(e.payload.get("speed", 0.0)) for e in events]
return float(min(1.0, float(np.std(speeds)) / 25.0))

@staticmethod
def _instability(events: List[EventEnvelope]) -> float:
if len(events) < 4:
return 0.0
headings = [float(e.payload.get("heading", 0.0)) for e in events]
diffs = np.abs(np.diff(headings))
return float(min(1.0, float(np.mean(diffs)) / 45.0))

@staticmethod
def _novelty(events: List[EventEnvelope]) -> float:
if len(events) < 4:
return 0.0
vals = []
for e in events:
vals.append(float(e.payload.get("value", e.payload.get("speed", 0.0))))
if len(set(vals)) == 1:
return 0.0
return float(min(1.0, abs(vals[-1] - float(np.mean(vals))) / (float(np.std(vals)) + 1e-5)))

def compute_metrics(self, events: List[EventEnvelope]) -> Dict[str, float]:
tail = events[-int(self.config["window_size"]):]
vol = self._volatility(tail)
inst = self._instability(tail)
nov = self._novelty(tail)
clarity = float(1.0 - (0.4 * vol + 0.4 * inst + 0.2 * nov))
return {
"vol": float(vol),
"inst": float(inst),
"nov": float(nov),
"clarity": float(np.clip(clarity, 0.0, 1.0)),
}

def assess_level(self, metrics: Dict[str, float]) -> Optional[str]:
vol, inst, nov = metrics["vol"], metrics["inst"], metrics["nov"]
critical = (vol >= self.config["vol_critical"]) or (inst >= self.config["inst_critical"]) or (nov >= self.config["nov_critical"])
warning = (vol >= self.config["vol_warning"]) or (inst >= self.config["inst_warning"]) or (nov >= self.config["nov_warning"])
if critical:
return "Critical"
if warning:
return "Warning"
return None

# ================================================================
# Trust Fabric (explainable + blame) — deterministic drift (no polyfit)
# ================================================================

def _extract_signal(payload: Dict[str, Any]) -> float:
if "speed" in payload:
return float(payload.get("speed", 0.0))
if "value" in payload:
return float(payload.get("value", 0.0))
return 0.0

class TrustFabric:
def __init__(self, weights: Dict[str, float], freshness_horizon_ticks: int = 10):
self.w = weights
self.freshness_horizon = max(3, int(freshness_horizon_ticks))

@staticmethod
def _slope(vals: List[float]) -> float:
n = len(vals)
if n < 2:
return 0.0
# Deterministic order of operations (no BLAS/LAPACK)
xs = list(range(n))
x_mean = sum(xs) / float(n)
y_mean = sum(vals) / float(n)
num = 0.0
den = 0.0
for i in range(n):
dx = float(xs[i] - x_mean)
dy = float(vals[i] - y_mean)
num += dx * dy
den += dx * dx
return (num / den) if den != 0.0 else 0.0

@staticmethod
def _drift_score(events: List[EventEnvelope]) -> float:
if len(events) < 10:
return 0.0
vals = [_extract_signal(e.payload) for e in events[-30:]]
# Quantize inputs to canon policy to reduce boundary flips
vals_q = [float(_round_floats(float(v))) if isinstance(_round_floats(float(v)), (int, float)) else float(v) for v in vals]

slope = TrustFabric._slope(vals_q)
slope_component = min(1.0, abs(float(slope)) / 5.0)

diffs = [vals_q[i+1] - vals_q[i] for i in range(len(vals_q) - 1)]
if len(diffs) < 3:
z_component = 0.0
else:
m = sum(diffs) / float(len(diffs))
var = sum((d - m) ** 2 for d in diffs) / float(len(diffs))
sd = math.sqrt(var)
if sd < 1e-5:
z_component = 0.0
else:
z = (diffs[-1] - m) / (sd + 1e-5)
z_component = min(1.0, abs(float(z)) / 3.0)

return float(np.clip(0.5 * slope_component + 0.5 * z_component, 0.0, 1.0))

def compute_sample(
self,
tick: int,
src: SourceRuntime,
stats: SourceStats,
accepted_events: List[EventEnvelope],
prev: Optional["TrustSample"],
) -> "TrustSample":
# Freshness = "fresh accepted truth", not "fresh attempt"
if stats.last_accept_tick is None:
freshness = 0.0
else:
delay = tick - stats.last_accept_tick
freshness = float(np.clip(1.0 - (delay / float(self.freshness_horizon)), 0.0, 1.0))

schema = float(np.clip(stats.accepted / float(stats.attempts), 0.0, 1.0)) if stats.attempts > 0 else 1.0
dropout = float(np.clip(stats.ticks_with_delivery / float(stats.enabled_ticks), 0.0, 1.0)) if stats.enabled_ticks > 0 else 1.0
drift = float(np.clip(self._drift_score(accepted_events), 0.0, 1.0))

base = (
self.w["freshness"] * freshness
+ self.w["schema"] * schema
+ self.w["dropout"] * dropout
+ self.w["drift"] * (1.0 - drift)
)
base = float(np.clip(base, 0.0, 1.0))

manual_penalty = 0.4 if src.manual_mode else 1.0
operator_weight = float(np.clip(src.operator_weight, 0.0, 1.0))
total = float(np.clip(base * manual_penalty * operator_weight, 0.0, 1.0))

comp = TrustComponents(
freshness=float(freshness),
schema=float(schema),
dropout=float(dropout),
drift=float(drift),
manual_penalty=float(manual_penalty),
operator_weight=float(operator_weight),
)

deltas = None
blame: List[str] = []
if prev is not None:
deltas = TrustComponents(
freshness=float(comp.freshness - prev.components.freshness),
schema=float(comp.schema - prev.components.schema),
dropout=float(comp.dropout - prev.components.dropout),
drift=float(comp.drift - prev.components.drift),
manual_penalty=float(comp.manual_penalty - prev.components.manual_penalty),
operator_weight=float(comp.operator_weight - prev.components.operator_weight),
)
if deltas.freshness <= -0.2:
blame.append(f"Freshness fell {prev.components.freshness:.2f} → {comp.freshness:.2f}")
if deltas.schema <= -0.1:
blame.append(f"Schema score fell {prev.components.schema:.2f} → {comp.schema:.2f}")
if deltas.dropout <= -0.1:
blame.append(f"Dropout worsened {prev.components.dropout:.2f} → {comp.dropout:.2f}")
if deltas.drift >= 0.2:
blame.append(f"Drift increased {prev.components.drift:.2f} → {comp.drift:.2f}")
if prev.components.manual_penalty != comp.manual_penalty:
blame.append("Manual mode changed")
if abs(deltas.operator_weight) >= 0.2:
blame.append(f"Operator weight changed {prev.components.operator_weight:.1f} → {comp.operator_weight:.1f}")

return TrustSample(tick=tick, total=total, base=base, components=comp, deltas=deltas, blame=blame)

@staticmethod
def generate_trust_insight(sid: str, sample: TrustSample, src: SourceRuntime) -> Optional[Insight]:
t = sample.total
manual_suffix = " [manual]" if src.manual_mode else ""
if t >= 0.8 and sample.tick % 30 == 0:
level = "Info"
msg = f"{sid.upper()} trust healthy{manual_suffix}"
elif t < 0.4:
level = "Critical"
msg = f"{sid.upper()} trust drop — data quality risk{manual_suffix}"
elif t < 0.6:
level = "Warning"
msg = f"{sid.upper()} trust degradation — monitor feed{manual_suffix}"
else:
return None

metrics = {
"trust": float(sample.total),
"base": float(sample.base),
"freshness": float(sample.components.freshness),
"schema": float(sample.components.schema),
"dropout": float(sample.components.dropout),
"drift": float(sample.components.drift),
"manual_penalty": float(sample.components.manual_penalty),
"operator_weight": float(sample.components.operator_weight),
}

return Insight(
insight_id=stable_id("ins_trust", {"sid": sid, "tick": sample.tick, "level": level, "metrics": metrics}),
source_id=sid,
tick=sample.tick,
level=level, # type: ignore
kind="trust",
msg=msg,
metrics=metrics,
)

# ================================================================
# ML Observer (Advisory Only)
# ================================================================

def _clip01(x: float) -> float:
return float(np.clip(float(x), 0.0, 1.0))

def _safe_mean(xs: List[float]) -> float:
return float(np.mean(xs)) if xs else 0.0

def _safe_std(xs: List[float]) -> float:
return float(np.std(xs)) if xs else 0.0

def extract_features_for_ml(state: SystemState) -> Dict[str, Any]:
"""
Deterministic boundary: only uses accepted state summaries + bounded scalars.
No raw/unvalidated input, no UI-driven state, no hidden coupling.
"""
def last_trust(sid: str) -> float:
h = state.trust_history.get(sid, [])
return float(h[-1].total) if h else 1.0

def last_clarity(sid: str) -> float:
mh = state.metrics_history.get(sid, [])
return float(mh[-1].get("clarity", 1.0)) if mh else 1.0

def q_rate() -> float:
attempts = sum(int(s.attempts) for s in state.stats.values())
quarantined = sum(int(s.quarantined) for s in state.stats.values())
return float(quarantined / float(max(1, attempts)))

# lag norms (late-only clamp)
lags = []
for s in state.stats.values():
lags.extend([max(0.0, float(x)) for x in s.recent_lags[-15:]])
lag_mean = _safe_mean(lags)
lag_std = _safe_std(lags)
lag_norm = _clip01(abs(lag_mean) / 4.0) # bounded heuristic
lag_var = _clip01(lag_std / 3.0)

integrity = _global_integrity_score(state)
crit = sum(1 for i in state.insights[-60:] if i.level == "Critical")
warn = sum(1 for i in state.insights[-60:] if i.level == "Warning")

feats = {
"tick": int(state.tick),
"integrity": float(_clip01(integrity)),
"q_rate": float(_clip01(q_rate())),
"crit60": int(crit),
"warn60": int(warn),
"ship_trust": float(_clip01(last_trust("ship"))),
"air_trust": float(_clip01(last_trust("air"))),
"ship_clarity": float(_clip01(last_clarity("ship"))),
"air_clarity": float(_clip01(last_clarity("air"))),
"lag_norm": float(lag_norm),
"lag_var": float(lag_var),
}
feats["feature_hash"] = sha256_hex({k: feats[k] for k in feats if k != "feature_hash"})[:16]
return feats

def ml_observer_assess(features: Dict[str, Any], ml_cfg: Dict[str, Any]) -> MLAssessment:
"""
Advisory-only bounded scoring placeholder (replaceable by frozen offline model later).
Deterministic given (features, ml_cfg).
"""
integrity = float(features["integrity"])
q_rate = float(features["q_rate"])
lag_norm = float(features["lag_norm"])
lag_var = float(features["lag_var"])
ship_t = float(features["ship_trust"])
air_t = float(features["air_trust"])
ship_c = float(features["ship_clarity"])
air_c = float(features["air_clarity"])

low_integrity = 1.0 - integrity
low_trust = 1.0 - float(_clip01(0.5 * (ship_t + air_t)))
low_clarity = 1.0 - float(_clip01(0.5 * (ship_c + air_c)))

energy = (
0.36 * low_integrity +
0.20 * q_rate +
0.14 * lag_norm +
0.10 * lag_var +
0.10 * low_trust +
0.10 * low_clarity
)
energy = float(_clip01(energy))

signal_type: Literal["ANOMALY", "TREND", "CONFIDENCE", "UNCERTAINTY"]
if energy >= 0.70 or q_rate >= 0.22:
signal_type = "ANOMALY"
elif energy >= 0.55 or lag_var >= 0.55:
signal_type = "UNCERTAINTY"
elif energy >= 0.42:
signal_type = "TREND"
else:
signal_type = "CONFIDENCE"

risk_review = float(ml_cfg.get("risk_review_threshold", 0.62))
risk_monitor = float(ml_cfg.get("risk_monitor_threshold", 0.48))

rec_class: Literal["REVIEW_REQUIRED", "MONITOR", "NO_ACTION"]
if energy >= risk_review:
rec_class = "REVIEW_REQUIRED"
elif energy >= risk_monitor:
rec_class = "MONITOR"
else:
rec_class = "NO_ACTION"

factors = [
("integrity_drop", 0.36 * low_integrity),
("quarantine_rate", 0.20 * q_rate),
("lag_mean", 0.14 * lag_norm),
("lag_variance", 0.10 * lag_var),
("trust_decay", 0.10 * low_trust),
("clarity_decay", 0.10 * low_clarity),
]
factors_sorted = sorted(factors, key=lambda kv: float(kv[1]), reverse=True)
primary = [k for k, v in factors_sorted[:3] if float(v) > 0.03] or [factors_sorted[0][0]]

horizon = str(ml_cfg.get("horizon", "SHORT")).upper()
if horizon not in ("SHORT", "MEDIUM", "LONG"):
horizon = "SHORT"

cf = "If quarantine rate were 50% lower, the signal would likely de-escalate." if q_rate > 0.12 else \
"If lag variance were 30% lower, uncertainty would likely not trigger."

summary = (
f"Advisory risk-energy={energy:.2f}. "
f"Primary drivers: {', '.join(primary)}. "
f"This is a review signal only; no authority implied."
)

aid = stable_id("ml", {
"tick": int(features["tick"]),
"signal": signal_type,
"energy": float(energy),
"feature_hash": str(features.get("feature_hash", "")),
"ml_cfg": {"risk_review_threshold": risk_review, "risk_monitor_threshold": risk_monitor, "horizon": horizon, "mode": ml_cfg.get("mode", "")},
})

return MLAssessment(
assessment_id=aid,
tick=int(features["tick"]),
signal_type=signal_type,
confidence=float(_clip01(1.0 - abs(energy - 0.5) * 1.1)),
time_horizon=horizon, # type: ignore
primary_factors=primary,
natural_language_summary=summary,
counterfactual=cf,
recommendation_class=rec_class,
feature_hash=str(features.get("feature_hash", "")),
)

def build_ml_assessment_payload(state: SystemState, ml_cfg: Dict[str, Any]) -> Dict[str, Any]:
feats = extract_features_for_ml(state)
a = ml_observer_assess(feats, ml_cfg)
return {"assessment": asdict(a), "features": feats}

# ================================================================
# Journal: tamper-evident hash chain + optional HMAC
# ================================================================

def _journal_entry_hash(prev_hash: str, entry: Dict[str, Any]) -> str:
material = canonical_json({
"prev": prev_hash,
"seq": entry["seq"],
"tick": entry["tick"],
"kind": entry["kind"],
"payload": entry["payload"],
})
return hashlib.sha256(material.encode("utf-8")).hexdigest()

def _journal_entry_sig(entry_hash: str) -> str:
secret = os.getenv("FUSIONOPS_JOURNAL_SECRET", "")
if not secret:
return ""
return hmac.new(secret.encode("utf-8"), entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

def validate_journal(journal: List[Dict[str, Any]]) -> Tuple[bool, str]:
prev = "GENESIS"
secret = os.getenv("FUSIONOPS_JOURNAL_SECRET", "")
for i, e in enumerate(journal):
if not isinstance(e, dict):
return False, f"entry not dict at index {i}"

# Required keys check (clean failure, no KeyError explosions)
for k in ("seq", "tick", "kind", "payload", "hash"):
if k not in e:
return False, f"missing key '{k}' at seq {i}"

try:
if int(e.get("seq", -1)) != i:
return False, f"seq mismatch at {i}"
except Exception:
return False, f"seq not int at {i}"

try:
expected = _journal_entry_hash(prev, {"seq": e["seq"], "tick": e["tick"], "kind": e["kind"], "payload": e["payload"]})
except Exception:
return False, f"hash material invalid at {i}"

if e.get("hash") != expected:
return False, f"hash mismatch at {i}"

if secret:
expected_sig = hmac.new(secret.encode("utf-8"), expected.encode("utf-8"), hashlib.sha256).hexdigest()
if e.get("sig") != expected_sig:
return False, f"sig mismatch at {i}"

prev = e["hash"]
return True, "ok"

def validate_journal_semantics(journal: List[Dict[str, Any]]) -> Tuple[bool, str]:
last_tick = -1
seen_tick_batches: Set[int] = set()
seen_ml: Set[int] = set()

for e in journal:
tick = int(e.get("tick", 0))
kind = str(e.get("kind", ""))

if tick < 0:
return False, "negative tick"
if tick < last_tick:
return False, f"tick decreased at seq {e.get('seq', '?')}"
last_tick = tick

if kind == "tick_batch":
if tick in seen_tick_batches:
return False, f"duplicate tick_batch tick={tick}"
seen_tick_batches.add(tick)
if "events" not in e.get("payload", {}):
return False, f"tick_batch missing events at tick={tick}"

if kind == "ml_assessment":
if tick in seen_ml:
return False, f"duplicate ml_assessment tick={tick}"
seen_ml.add(tick)
p = e.get("payload", {})
if "assessment" not in p or "features" not in p:
return False, "ml_assessment missing assessment/features"

if kind == "decision":
p = e.get("payload", {})
if "rec_id" not in p:
return False, "decision missing rec_id"
if "choice" not in p:
return False, "decision missing choice"

if kind == "operator_cmd":
p = e.get("payload", {})
if "cmd" not in p:
return False, "operator_cmd missing cmd"

if kind == "config_update":
p = e.get("payload", {})
if "path" not in p or "value" not in p:
return False, "config_update missing path/value"
ok, _, reason = validate_config_update(str(p.get("path", "")), p.get("value"))
if not ok:
return False, f"invalid config_update: {reason}"

return True, "ok"

def append_journal(kind: str, tick: int, payload: Dict[str, Any]):
j = st.session_state.journal
seq = len(j)
prev_hash = j[-1].get("hash", "GENESIS") if j else "GENESIS"

# sanitize config updates at the boundary (prevents journaling garbage)
if kind == "config_update":
ok, v2, _ = validate_config_update(str(payload.get("path", "")), payload.get("value"))
if ok:
payload = dict(payload)
payload["value"] = v2

entry = {"seq": seq, "kind": kind, "tick": int(tick), "payload": payload}
entry_hash = _journal_entry_hash(prev_hash, entry)
entry["hash"] = entry_hash
sig = _journal_entry_sig(entry_hash)
if sig:
entry["sig"] = sig

# Dev invariant: hash must change with every append (guards replay cache assumptions)
if not PROD_LOCKDOWN and j:
if entry_hash == prev_hash:
raise RuntimeError("journal head hash did not change on append (should be impossible)")

j.append(entry)

def _iter_journal_until(journal: List[Dict[str, Any]], until_tick: Optional[int]) -> Iterable[Dict[str, Any]]:
for e in journal:
if until_tick is not None and int(e.get("tick", 0)) > int(until_tick):
break
yield e

def journal_head_hash(journal: List[Dict[str, Any]]) -> str:
return (journal[-1].get("hash", "GENESIS") if journal else "GENESIS")

def journal_has_kind_at_tick(journal: List[Dict[str, Any]], kind: str, tick: int) -> bool:
for e in reversed(journal):
et = int(e.get("tick", -1))
if et < tick:
break
if et == tick and e.get("kind") == kind:
return True
return False

def apply_config_update(cfg: Dict[str, Any], path: str, value: Any) -> Dict[str, Any]:
"""
Minimal safe updater (now validated).
Supports:
- path like "ml" or "policy" or "clarity" or "trust_weights" or "tick_dt_s"
- path like "ml.risk_review_threshold"
Returns a new config dict.
"""
out = copy.deepcopy(cfg)
parts = [p for p in str(path).split(".") if p.strip()]
if not parts:
return out

# If root replacement, validate + sanitize
if len(parts) == 1 and parts[0] in ("ml", "policy"):
ok, v2, _ = validate_config_update(parts[0], value)
if not ok:
return out
out[parts[0]] = v2
return out

cur = out
for p in parts[:-1]:
if p not in cur or not isinstance(cur[p], dict):
cur[p] = {}
cur = cur[p]
cur[parts[-1]] = value

# If we mutated nested ml/policy fields, re-sanitize those sections.
if parts[0] in ("ml", "policy"):
ok, v2, _ = validate_config_update(parts[0], out.get(parts[0]))
if ok:
out[parts[0]] = v2

return out

# ================================================================
# Synthetic telemetry generation (with journaled injectors)
# ================================================================

JITTER_VERSION = "jitter_v1"

def _jitter_v1(seed: int, tick: int, sid: str) -> float:
key = sha256_hex({"seed": seed, "tick": tick, "sid": sid, "jitter": JITTER_VERSION})
x = int(key[:8], 16) / float(16**8)
j = (x - 0.5) * 3.0
if tick % 17 == 0:
j -= 2.0
return float(j)

def _rand01(seed: int, tick: int, key: str) -> float:
h = sha256_hex({"seed": seed, "tick": tick, "key": key})
return int(h[:8], 16) / float(16**8)

def _maybe_corrupt_payload(seed: int, tick: int, sid: str, p: Dict[str, Any], rate: float) -> Dict[str, Any]:
if rate <= 0:
return p
r = _rand01(seed, tick, f"corrupt:{sid}")
if r > rate:
return p
mode = int(_rand01(seed, tick, f"corruptmode:{sid}") * 4.999)
if mode == 0:
return {"oops": "badshape", "payload": p}
if mode == 1:
q = dict(p)
q.pop(next(iter(q.keys())), None)
return q
if mode == 2:
q = dict(p)
q[next(iter(q.keys()))] = "NaN" # type error test
return q
if mode == 3:
q = dict(p)
q["lat"] = 9999
return q
# explicit float nan test (will be rejected by validate_event)
q = dict(p)
q["speed"] = float("nan")
return q

def generate_synthetic_batch(
tick: int,
sources: Dict[str, SourceRuntime],
run_cfg: Dict[str, Any],
inj: InjectionConfig,
) -> List[EventEnvelope]:
seed = int(run_cfg["seed"])
dt = float(run_cfg.get("tick_dt_s", 1.0))
logical_ts = tick * dt
out: List[EventEnvelope] = []

def mk_event(source_id: str, schema_version: str, payload: Dict[str, Any]) -> EventEnvelope:
event_ts = float(logical_ts + _jitter_v1(seed, tick, source_id))
eid = stable_id("evt", {"tick": tick, "sid": source_id, "ts": event_ts, "payload": payload, "jitter": JITTER_VERSION})
return EventEnvelope(
event_id=eid,
source_id=source_id,
ingest_tick=tick,
event_ts=event_ts,
schema_version=schema_version,
payload=payload,
)

def drop_this(sid: str) -> bool:
if inj.dropout_rate <= 0:
return False
return _rand01(seed, tick, f"drop:{sid}") < inj.dropout_rate

storm = bool(inj.storm_mode)

if sources["ship"].enabled and not drop_this("ship"):
base_lat = 40.0 + float(np.sin(tick / (9.0 if not storm else 7.0)))
base_lon = -80.0 + float(np.cos(tick / (9.0 if not storm else 7.0)))
base_speed = 11.0 + float(np.sin(tick / (5.0 if not storm else 4.0)) * (3.0 if not storm else 4.5))
base_heading = float((tick * 4) % 360)

sj = float(np.clip(inj.spoof_jitter, 0.0, 1.0))
if sj > 0:
noise = (_rand01(seed, tick, "shipnoise") - 0.5) * 2.0
base_heading = float((base_heading + noise * 90.0 * sj) % 360)
base_speed = float(max(0.0, base_speed + noise * 6.0 * sj))

payload = {"lat": base_lat, "lon": base_lon, "speed": base_speed, "heading": base_heading}
payload = _maybe_corrupt_payload(seed, tick, "ship", payload, inj.schema_corrupt_rate)
out.append(mk_event("ship", run_cfg["sources_default"]["ship"]["schema_version"], payload))

if sources["air"].enabled and not drop_this("air"):
base_lat = 39.0 + float(np.sin(tick / (12.0 if not storm else 9.0)))
base_lon = -81.0 + float(np.cos(tick / (12.0 if not storm else 9.0)))
base_alt = 31000.0 + float(np.sin(tick / 6.0) * (1500.0 if not storm else 2400.0))
base_speed = 440.0 + float(np.cos(tick / 7.0) * (40.0 if not storm else 70.0))
base_heading = float((tick * 6) % 360)

sj = float(np.clip(inj.spoof_jitter, 0.0, 1.0))
if sj > 0:
noise = (_rand01(seed, tick, "airnoise") - 0.5) * 2.0
base_heading = float((base_heading + noise * 120.0 * sj) % 360)
base_speed = float(max(0.0, base_speed + noise * 55.0 * sj))
base_alt = float(max(0.0, base_alt + noise * 2500.0 * sj))

payload = {"lat": base_lat, "lon": base_lon, "alt": base_alt, "speed": base_speed, "heading": base_heading}
payload = _maybe_corrupt_payload(seed, tick, "air", payload, inj.schema_corrupt_rate)
out.append(mk_event("air", run_cfg["sources_default"]["air"]["schema_version"], payload))

if sources["incident"].enabled and not drop_this("incident"):
r = _rand01(seed, tick, "incident")
spike = float(np.clip(inj.incident_spike_rate, 0.0, 1.0))
val = float((r - 0.5) * 0.8 + (1.0 if tick % 40 == 0 else 0.0))
sev = 0
if tick % 50 == 0:
sev = 2
elif tick % 20 == 0:
sev = 1

if spike > 0 and _rand01(seed, tick, "incident_spike") < spike:
sev = min(5, sev + 2)
val = float(val + 1.2)

payload = {"value": val, "severity": int(sev)}
payload = _maybe_corrupt_payload(seed, tick, "incident", payload, inj.schema_corrupt_rate)
out.append(mk_event("incident", run_cfg["sources_default"]["incident"]["schema_version"], payload))

if sources["weather"].enabled and not drop_this("weather"):
wind = 10.0 + float(np.sin(tick / (12.0 if not storm else 8.0)) * (3.0 if not storm else 8.0))
tempish = float(np.cos(tick / (14.0 if not storm else 10.0)) * (4.0 if not storm else 7.0))
payload = {"wind": wind, "value": tempish}
payload = _maybe_corrupt_payload(seed, tick, "weather", payload, inj.schema_corrupt_rate)
out.append(mk_event("weather", run_cfg["sources_default"]["weather"]["schema_version"], payload))

return out

# ================================================================
# Core reducers + scoring
# ================================================================

def _trim_list_inplace(xs: List[Any], cap: int):
if len(xs) > cap:
del xs[: len(xs) - cap]

def _insight_key(ins: Insight) -> str:
return f"{ins.kind}:{ins.source_id}:{ins.level}:{ins.msg}"

def pending_recommendations(state: SystemState) -> List[Recommendation]:
decided = set(state.decisions.keys())
return [r for r in state.recommendations if r.rec_id not in decided]

def operator_load_label(policy: PolicyConfig, pending_count: int, recent_insights: int) -> str:
if pending_count >= policy.pending_high or recent_insights >= 10:
return "High"
if pending_count >= policy.pending_med or recent_insights >= 5:
return "Medium"
return "Low"

def _global_clarity_score(state: SystemState) -> float:
vals = []
for sid, evs in state.events.items():
mh = state.metrics_history.get(sid, [])
if mh:
vals.append(float(mh[-1].get("clarity", 1.0)))
elif len(evs) >= 4:
vals.append(0.8)
return float(np.clip(float(np.mean(vals)), 0.0, 1.0)) if vals else 1.0

def _global_trust_score(state: SystemState) -> float:
vals = []
for sid, hist in state.trust_history.items():
if hist:
vals.append(hist[-1].total)
return float(np.clip(float(np.mean(vals)), 0.0, 1.0)) if vals else 1.0

def _global_health_score(state: SystemState) -> float:
now = state.tick
scores = []
for sid, src in state.sources.items():
stats = state.stats.get(sid, SourceStats())
if not src.enabled:
scores.append(0.50)
continue
if stats.last_attempt_tick is None:
scores.append(0.10)
continue

delay = now - stats.last_attempt_tick
delay_score = 1.0 if delay <= 2 else (0.6 if delay <= 6 else 0.25)

if stats.recent_lags:
lag_tail = stats.recent_lags[-20:]
# late-only clamp (don’t penalize early timestamps)
lag_tail = [max(0.0, float(x)) for x in lag_tail]
lag_mean = float(np.mean(lag_tail))
lag_std = float(np.std(lag_tail))
mean_pen = float(np.clip(abs(lag_mean) / 3.0, 0.0, 1.0))
std_pen = float(np.clip(lag_std / 2.0, 0.0, 1.0))
lag_score = float(np.clip(1.0 - 0.6 * mean_pen - 0.4 * std_pen, 0.0, 1.0))
else:
lag_score = 0.7

scores.append(float(np.clip(0.65 * delay_score + 0.35 * lag_score, 0.0, 1.0)))

return float(np.clip(float(np.mean(scores)), 0.0, 1.0)) if scores else 1.0

def _global_integrity_score(state: SystemState) -> float:
clarity = _global_clarity_score(state)
trust = _global_trust_score(state)
health = _global_health_score(state)
return float(np.clip(0.4 * clarity + 0.3 * trust + 0.3 * health, 0.0, 1.0))

def integrity_state_label(score: float) -> str:
if score >= 0.85:
return "Stable Autonomous Operation"
if score >= 0.7:
return "Watch / Elevated Monitoring"
if score >= 0.5:
return "Degraded — Verify Feeds"
if score >= 0.3:
return "Critical — Operator Focus Required"
return "Unsafe Autonomous Operation"

def _apply_critical_flash(state: SystemState):
total_critical = sum(1 for i in state.insights if i.level == "Critical")
state.critical_flash = total_critical > state.last_critical_count
state.last_critical_count = total_critical

def _update_metrics_history(state: SystemState, ctx: EngineContext):
for sid, evs in state.events.items():
if not evs:
continue
metrics = ctx.clarity.compute_metrics(evs)
hist = state.metrics_history.setdefault(sid, [])
row = {"tick": float(state.tick)}
row.update({k: float(v) for k, v in metrics.items()})
hist.append(row)
_trim_list_inplace(hist, 260)

def _update_trust_history(state: SystemState, ctx: EngineContext) -> List[Insight]:
trust_insights: List[Insight] = []
for sid, src in state.sources.items():
stats = state.stats.setdefault(sid, SourceStats())
evs = state.events.get(sid, [])
prev = state.trust_history.get(sid, [])[-1] if state.trust_history.get(sid) else None
sample = ctx.trust.compute_sample(state.tick, src, stats, evs, prev)
hist = state.trust_history.setdefault(sid, [])
hist.append(sample)
_trim_list_inplace(hist, 260)
ins = ctx.trust.generate_trust_insight(sid, sample, src)
if ins is not None:
trust_insights.append(ins)
return trust_insights

def _filter_new_insights(state: SystemState, candidates: List[Insight]) -> List[Insight]:
out: List[Insight] = []
now_tick = state.tick
for ins in candidates:
key = _insight_key(ins)
last = state.last_insight_tick.get(key)
if last is not None and (now_tick - last) < INSIGHT_REFRACTORY_TICKS:
continue
out.append(ins)
state.last_insight_tick[key] = now_tick
return out

def _generate_clarity_insights(state: SystemState, ctx: EngineContext) -> List[Insight]:
out: List[Insight] = []
for sid in sorted(state.events.keys()):
evs = state.events.get(sid, [])
if len(evs) < 4:
continue
metrics = ctx.clarity.compute_metrics(evs)
level = ctx.clarity.assess_level(metrics)
if level is None:
continue
src = state.sources.get(sid)
if src and src.manual_mode and level in ("Critical", "Warning"):
level2: Literal["Info", "Warning", "Critical"] = "Info"
msg = f"{sid.upper()} stability deviation (manual mode)"
else:
level2 = level # type: ignore
msg = f"{sid.upper()} stability deviation"
out.append(
Insight(
insight_id=stable_id("ins_clarity", {"sid": sid, "tick": state.tick, "level": level2, "metrics": metrics}),
source_id=sid,
tick=state.tick,
level=level2, # type: ignore
kind="clarity",
msg=msg,
metrics={k: float(v) for k, v in metrics.items()},
)
)
return out

def _quarantine_rate_global(state: SystemState) -> float:
attempts = 0
quarantined = 0
for s in state.stats.values():
attempts += int(s.attempts)
quarantined += int(s.quarantined)
return float(quarantined / float(max(1, attempts)))

def compute_threat_level(state: SystemState) -> ThreatLevel:
integrity = _global_integrity_score(state)
crit = sum(1 for i in state.insights[-60:] if i.level == "Critical")
warn = sum(1 for i in state.insights[-60:] if i.level == "Warning")
q_rate = _quarantine_rate_global(state)

if integrity < 0.30:
return ThreatLevel.BLACK
if integrity < 0.45 or crit >= 3:
return ThreatLevel.RED
if integrity < 0.65 or (1 <= crit <= 2) or q_rate > 0.18:
return ThreatLevel.ORANGE
if integrity < 0.80 or warn >= 6 or q_rate > 0.10:
return ThreatLevel.AMBER
return ThreatLevel.GREEN

def _generate_threat_insight(state: SystemState, threat: ThreatLevel) -> Optional[Insight]:
if state.tick % 10 != 0:
return None
integrity = _global_integrity_score(state)
q = _quarantine_rate_global(state)
msg = f"Threat doctrine: {threat.value}"
return Insight(
insight_id=stable_id("ins_threat", {"tick": state.tick, "threat": threat.value, "integrity": integrity, "q": q}),
source_id="global",
tick=state.tick,
level="Warning" if threat in (ThreatLevel.AMBER, ThreatLevel.ORANGE) else ("Critical" if threat in (ThreatLevel.RED, ThreatLevel.BLACK) else "Info"),
kind="threat",
msg=msg,
metrics={"integrity": float(integrity), "quarantine_rate": float(q), "threat": float(["GREEN","AMBER","ORANGE","RED","BLACK"].index(threat.value))},
)

def _schema_band(q_rate: float, r_rate: float) -> int:
# boundaries aligned with doctrine notes
if r_rate > 0.10 or q_rate > 0.22:
return 3
if r_rate > 0.05 or q_rate > 0.18:
return 2
if q_rate > 0.10:
return 1
return 0

def _generate_recommendations(state: SystemState, new_insights: List[Insight], policy: PolicyConfig, threat: ThreatLevel):
pending = len(pending_recommendations(state))
recent_ins = len(state.insights[-12:])
load = operator_load_label(policy, pending, recent_ins)
integrity = _global_integrity_score(state)

doctrine_blocks_auto = threat in (ThreatLevel.RED, ThreatLevel.BLACK)
doctrine_requires_gate = threat in (ThreatLevel.ORANGE, ThreatLevel.RED, ThreatLevel.BLACK)

side_effecting: Set[str] = {"escalate", "cross_feed", "schema_investigate", "set_manual"}

def _record_action(rec: Recommendation):
status: Literal["queued", "executed", "blocked"]
status = "queued" if rec.requires_approval else "executed"

side_effect = rec.action_class in side_effecting

note = rec.blocked_reason or ("Awaiting operator decision" if rec.requires_approval else "Recorded (no side effect)")
act_id = stable_id("act", {"tick": rec.tick, "rec_id": rec.rec_id, "status": status})
state.autonomy_actions.append(
AutonomyAction(
action_id=act_id,
tick=rec.tick,
rec_id=rec.rec_id,
action_class=rec.action_class,
target_source_id=rec.target_source_id,
status=status,
note=note,
side_effect=side_effect,
)
)
_trim_list_inplace(state.autonomy_actions, MAX_ACTIONS)

for ins in new_insights:
# Safety invariant: ML is advisory-only and must not generate recommendations
if ins.kind == "ml":
continue

if load == "High" and policy.suppress_warnings_under_high_load and ins.level == "Warning":
continue

src_cfg = state.sources.get(ins.source_id)
manual = src_cfg.manual_mode if src_cfg else False

action = "Log insight"
rationale_parts: List[str] = []
action_class = "log"
target_sid = ins.source_id

if ins.kind == "clarity":
if manual:
action = "Operator review (manual mode)"
action_class = "manual_review"
rationale_parts.append("Manual override active; no auto-escalation.")
else:
v, i, n = ins.metrics.get("vol", 0.0), ins.metrics.get("inst", 0.0), ins.metrics.get("nov", 0.0)
cfg = DEFAULT_CLARITY_CONFIG
rationale_parts.append(
f"Clarity thresholds: vol({v:.2f}) warn≥{cfg['vol_warning']:.2f}/crit≥{cfg['vol_critical']:.2f}, "
f"inst({i:.2f}) warn≥{cfg['inst_warning']:.2f}/crit≥{cfg['inst_critical']:.2f}, "
f"nov({n:.2f}) warn≥{cfg['nov_warning']:.2f}/crit≥{cfg['nov_critical']:.2f}."
)
if ins.level == "Critical":
action = "Escalate + widen monitoring window"
action_class = "escalate"
rationale_parts.append("Critical deviation: immediate attention.")
elif ins.level == "Warning":
action = "Expand monitoring and confirm pattern"
action_class = "monitor"
rationale_parts.append("Warning deviation: watch trend.")
else:
action = "Acknowledge clarity state"
action_class = "ack"

elif ins.kind == "trust":
if ins.level == "Critical":
action = "Review feed + consider manual mode"
action_class = "set_manual"
rationale_parts.append("Severe trust degradation indicates data quality risk.")
elif ins.level == "Warning":
action = "Monitor trust + review overrides"
action_class = "monitor"
rationale_parts.append("Trust degrading; check freshness/schema/dropout/drift.")
else:
action = "Acknowledge trust state"
action_class = "ack"
rationale_parts.append("Informational trust update.")

th = state.trust_history.get(ins.source_id, [])
if th and th[-1].blame:
rationale_parts.append("Blame: " + " | ".join(th[-1].blame[:3]))

elif ins.kind == "schema":
if ins.level == "Critical":
action = "Investigate schema drift + quarantine reasons"
action_class = "schema_investigate"
rationale_parts.append("High reject/quarantine rates detected; review contract compatibility.")
elif ins.level == "Warning":
action = "Review schema validation failures"
action_class = "schema_monitor"
rationale_parts.append("Schema issues rising; monitor quarantine lane.")
else:
action = "Log schema health"
action_class = "log"

elif ins.kind == "threat":
action = "Acknowledge doctrine state"
action_class = "doctrine_ack"
rationale_parts.append("Threat doctrine updated; ensure ops posture matches.")

requires_approval = False
blocked_reason = ""

if action_class in policy.always_requires_approval:
requires_approval = True
blocked_reason = "Policy: always requires approval"

if not requires_approval and doctrine_requires_gate and action_class in side_effecting:
requires_approval = True
blocked_reason = f"Threat doctrine {threat.value}: human gate required"

if doctrine_blocks_auto and action_class in side_effecting:
requires_approval = True
blocked_reason = blocked_reason or f"Threat doctrine {threat.value}: auto side-effects blocked"

if not requires_approval:
if integrity < policy.integrity_floor and action_class in side_effecting:
requires_approval = True
blocked_reason = f"Integrity {integrity:.2f} below floor {policy.integrity_floor:.2f}"
elif integrity < policy.approval_required_below and action_class in policy.approval_required_for:
requires_approval = True
blocked_reason = f"Integrity {integrity:.2f} below approval threshold {policy.approval_required_below:.2f}"

if load == "High" and action_class in policy.approval_required_for:
requires_approval = True
blocked_reason = blocked_reason or "Operator load High — enforce human gate"

rationale_parts.append(f"Integrity={integrity:.2f}, OperatorLoad={load}, Threat={threat.value}.")

if "clarity" in ins.metrics:
confidence = float(np.clip(1.0 - ins.metrics["clarity"], 0.0, 1.0))
elif "trust" in ins.metrics:
confidence = float(np.clip(1.0 - ins.metrics["trust"], 0.0, 1.0))
else:
confidence = 0.55

rec_payload = {
"insight_id": ins.insight_id,
"tick": state.tick,
"level": ins.level,
"action": action,
"class": action_class,
"target": target_sid,
"requires_approval": requires_approval,
"integrity": float(integrity),
"operator_load": load,
"threat": threat.value,
}
rec_id = stable_id("rec", rec_payload)

rec = Recommendation(
rec_id=rec_id,
insight_id=ins.insight_id,
tick=state.tick,
level=ins.level,
action=action,
action_class=action_class,
target_source_id=target_sid,
rationale=" ".join(rationale_parts),
confidence=float(confidence),
requires_approval=requires_approval,
blocked_reason=blocked_reason,
integrity_at_issue=float(integrity),
operator_load_at_issue=str(load),
threat_at_issue=threat.value,
)
state.recommendations.append(rec)
_trim_list_inplace(state.recommendations, MAX_RECS)
_record_action(rec)

def _seen_add(state: SystemState, eid: str):
if eid in state.seen_event_ids:
return

# if bounded, evict oldest
if len(state.seen_event_ids) >= SEEN_EVENT_IDS_MAX and state.seen_queue:
old = state.seen_queue.popleft()
if old in state.seen_event_ids:
state.seen_event_ids.remove(old)
state.seen_ids_xor ^= _eid_digest64(old)

state.seen_event_ids.add(eid)
state.seen_queue.append(eid)
state.seen_ids_xor ^= _eid_digest64(eid)

def _apply_tick_batch(state: SystemState, tick: int, envelopes: List[EventEnvelope], ctx: EngineContext):
state.tick = int(tick)
dt = float(max(1e-6, ctx.tick_dt_s))
logical_ts = float(state.tick * dt)

for sid, src in state.sources.items():
stats = state.stats.setdefault(sid, SourceStats())
if src.enabled:
stats.enabled_ticks += 1

delivered_this_tick: Set[str] = set()

envelopes_sorted = sorted(envelopes, key=lambda e: (e.source_id, e.event_id))
for env in envelopes_sorted:
if env.event_id in state.seen_event_ids:
state.quarantine.append(QuarantineEntry(env, ValidationDisposition.QUARANTINED, "duplicate event_id"))
_trim_list_inplace(state.quarantine, MAX_QUARANTINE)
continue

_seen_add(state, env.event_id)

sid = env.source_id
stats = state.stats.setdefault(sid, SourceStats())
stats.attempts += 1
stats.last_attempt_tick = state.tick
delivered_this_tick.add(sid)

prior_wm = stats.watermark_ts if stats.watermark_ts is not None else env.event_ts
stats.watermark_ts = float(max(float(prior_wm), float(env.event_ts)))

lag = float(logical_ts - float(env.event_ts))
stats.recent_lags.append(lag)
_trim_list_inplace(stats.recent_lags, 140)

disp, cleaned, reason = validate_event(env)

if disp == ValidationDisposition.ACCEPTED:
stats.accepted += 1
stats.last_accept_tick = state.tick
env2 = EventEnvelope(env.event_id, env.source_id, env.ingest_tick, env.event_ts, env.schema_version, dict(cleaned))
state.events.setdefault(sid, []).append(env2)
_trim_list_inplace(state.events[sid], MAX_EVENTS_PER_SOURCE)
elif disp == ValidationDisposition.QUARANTINED:
stats.quarantined += 1
state.quarantine.append(QuarantineEntry(env, disp, reason))
_trim_list_inplace(state.quarantine, MAX_QUARANTINE)
else:
stats.rejected += 1
state.quarantine.append(QuarantineEntry(env, disp, reason))
_trim_list_inplace(state.quarantine, MAX_QUARANTINE)

for sid in delivered_this_tick:
state.stats[sid].ticks_with_delivery += 1

_update_metrics_history(state, ctx)

candidates: List[Insight] = []
candidates.extend(_generate_clarity_insights(state, ctx))
candidates.extend(_update_trust_history(state, ctx))

# Schema insights: periodic + threshold-crossing breadcrumbs
for sid, stats in state.stats.items():
if stats.attempts <= 0:
continue
q_rate = stats.quarantined / float(max(1, stats.attempts))
r_rate = stats.rejected / float(max(1, stats.attempts))
band = _schema_band(q_rate, r_rate)

if band != stats.schema_band:
stats.schema_band = band
level: Literal["Info", "Warning", "Critical"] = "Info"
if band == 1:
level = "Warning"
elif band >= 2:
level = "Critical" if band == 3 else "Warning"
candidates.append(
Insight(
insight_id=stable_id("ins_schema_cross", {"sid": sid, "tick": state.tick, "band": band, "q": q_rate, "r": r_rate, "level": level}),
source_id=sid,
tick=state.tick,
level=level,
kind="schema",
msg=f"{sid.upper()} schema boundary crossed — q={q_rate:.2f}, rej={r_rate:.2f}",
metrics={"quarantine_rate": float(q_rate), "reject_rate": float(r_rate), "band": float(band), "attempts": float(stats.attempts)},
)
)

if state.tick % 25 == 0:
for sid, stats in state.stats.items():
if stats.attempts <= 0:
continue
q_rate = stats.quarantined / float(max(1, stats.attempts))
r_rate = stats.rejected / float(max(1, stats.attempts))
level2: Literal["Info", "Warning", "Critical"] = "Info"
if r_rate > 0.05:
level2 = "Warning"
if r_rate > 0.10 or q_rate > 0.20:
level2 = "Critical"
candidates.append(
Insight(
insight_id=stable_id("ins_schema", {"sid": sid, "tick": state.tick, "q": q_rate, "r": r_rate, "level": level2}),
source_id=sid,
tick=state.tick,
level=level2,
kind="schema",
msg=f"{sid.upper()} schema health — q={q_rate:.2f}, rej={r_rate:.2f}",
metrics={"quarantine_rate": float(q_rate), "reject_rate": float(r_rate), "attempts": float(stats.attempts)},
)
)

new_insights = _filter_new_insights(state, candidates)
state.insights.extend(new_insights)
_trim_list_inplace(state.insights, MAX_INSIGHTS)

threat = compute_threat_level(state)
t_ins = _generate_threat_insight(state, threat)
if t_ins is not None:
state.insights.append(t_ins)
_trim_list_inplace(state.insights, MAX_INSIGHTS)

_generate_recommendations(state, new_insights + ([t_ins] if t_ins else []), ctx.policy, threat)
_apply_critical_flash(state)

def _apply_operator_cmd(state: SystemState, cmd: Dict[str, Any]):
kind = cmd.get("cmd")

if kind == "set_source":
sid = cmd["source_id"]
if sid not in state.sources:
return
src = state.sources[sid]
if "enabled" in cmd:
src.enabled = bool(cmd["enabled"])
if "manual_mode" in cmd:
src.manual_mode = bool(cmd["manual_mode"])
if "operator_weight" in cmd:
src.operator_weight = float(np.clip(float(cmd["operator_weight"]), 0.0, 1.0))

elif kind == "set_injections":
inj = state.injections
for k in ["dropout_rate", "spoof_jitter", "schema_corrupt_rate", "incident_spike_rate", "storm_mode"]:
if k in cmd:
setattr(inj, k, cmd[k])

def _apply_decision_effects(state: SystemState, decision: Decision):
rec_map = {r.rec_id: r for r in state.recommendations}
rec = rec_map.get(decision.rec_id)
if rec is None:
return

def _set_action_status(status: Literal["queued", "executed", "blocked"], note: str):
for act in reversed(state.autonomy_actions):
if act.rec_id == decision.rec_id:
act.status = status
act.note = note
return

if decision.choice == "approve":
_set_action_status("executed", f"Approved at tick {decision.tick}")
if rec.action_class == "set_manual" and rec.target_source_id in state.sources:
state.sources[rec.target_source_id].manual_mode = True
elif decision.choice == "reject":
_set_action_status("blocked", f"Rejected at tick {decision.tick}")
else:
_set_action_status("queued", f"Deferred at tick {decision.tick}")

# ================================================================
# Replay build (config_update aware)
# ================================================================

def rebuild_state(journal: List[Dict[str, Any]], initial_run_config: Dict[str, Any], until_tick: Optional[int] = None) -> SystemState:
run_cfg_effective = copy.deepcopy(initial_run_config)
ctx = make_engine_context(run_cfg_effective)

src_defaults = run_cfg_effective["sources_default"]
sources: Dict[str, SourceRuntime] = {
sid: SourceRuntime(
id=sid,
name=cfg["name"],
enabled=bool(cfg["enabled"]),
operator_weight=float(cfg["operator_weight"]),
manual_mode=bool(cfg["manual_mode"]),
)
for sid, cfg in src_defaults.items()
}
state = SystemState(tick=0, sources=sources)
state.seen_queue = deque([], maxlen=SEEN_EVENT_IDS_MAX)

for entry in _iter_journal_until(journal, until_tick):
kind = entry.get("kind")
tick = int(entry.get("tick", 0))
payload = entry.get("payload", {})

if kind == "config_snapshot":
continue

if kind == "config_update":
path = str(payload.get("path", ""))
value = payload.get("value")
# Apply validated update
run_cfg_effective = apply_config_update(run_cfg_effective, path, value)
ctx = make_engine_context(run_cfg_effective)
continue

if kind == "operator_cmd":
_apply_operator_cmd(state, payload)

elif kind == "decision":
d = Decision(
decision_id=stable_id("dec", payload),
tick=tick,
rec_id=payload["rec_id"],
choice=payload["choice"],
comment=payload.get("comment", ""),
)
state.decisions[d.rec_id] = d
_apply_decision_effects(state, d)

elif kind == "tick_batch":
envs = []
for e in payload.get("events", []):
envs.append(EventEnvelope(
event_id=e["event_id"],
source_id=e["source_id"],
ingest_tick=int(e["ingest_tick"]),
event_ts=float(e["event_ts"]),
schema_version=e["schema_version"],
payload=dict(e["payload"]),
))
_apply_tick_batch(state, tick, envs, ctx)

elif kind == "ml_assessment":
a = payload.get("assessment", {})
try:
state.ml_assessments.append(MLAssessment(**a))
_trim_list_inplace(state.ml_assessments, MAX_ML)

ml = state.ml_assessments[-1]
lvl: Literal["Info", "Warning", "Critical"] = "Info"
if ml.recommendation_class == "REVIEW_REQUIRED":
lvl = "Warning"

state.insights.append(
Insight(
insight_id=stable_id("ins_ml", {"tick": ml.tick, "id": ml.assessment_id}),
source_id="ml",
tick=ml.tick,
level=lvl,
kind="ml",
msg=f"ML observer: {ml.signal_type} → {ml.recommendation_class} (conf={ml.confidence:.2f})",
metrics={"confidence": float(ml.confidence), "review": float(1.0 if ml.recommendation_class == "REVIEW_REQUIRED" else 0.0)},
)
)
_trim_list_inplace(state.insights, MAX_INSIGHTS)
except Exception:
# Deterministic breadcrumb (no exception string)
err_id = stable_id("ml_parse_fail", {"tick": tick, "payload_hash": sha256_hex(payload)[:16]})
state.insights.append(
Insight(
insight_id=stable_id("ins_ml_fail", {"tick": tick, "id": err_id}),
source_id="ml",
tick=tick,
level="Warning",
kind="ml",
msg="ML observer payload parse failed (quarantined)",
metrics={"parse_fail": 1.0},
)
)
_trim_list_inplace(state.insights, MAX_INSIGHTS)

state.effective_config_hash = sha256_hex(run_cfg_effective)[:16]
state.effective_ml_cfg = dict(run_cfg_effective.get("ml", DEFAULT_ML_CFG))
return state

# ================================================================
# Replay cache (session-state LRU; avoids huge Streamlit cache keys)
# ================================================================

def _state_cache_get(key: Tuple[str, str, Optional[int]]) -> Optional[SystemState]:
cache = st.session_state.get("_state_cache", {})
order = st.session_state.get("_state_cache_order", [])
if key in cache:
# bump recency
try:
order.remove(key)
except ValueError:
pass
order.append(key)
st.session_state["_state_cache_order"] = order
return cache[key]
...
