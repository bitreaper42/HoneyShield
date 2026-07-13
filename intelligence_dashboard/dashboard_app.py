"""
dashboard_app.py  —  HoneyShield Threat Intelligence Portal
============================================================
Enterprise-grade dark dashboard. Fixed dark theme. No sidebar.
Mono two-color palette. Professional typography.

Run from the intelligence_dashboard/ directory:
    streamlit run dashboard_app.py
"""

import json
import time
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from db_helper import (
    STATUS_ORDER,
    fetch_all_incidents,
    fetch_summary_metrics,
)

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="HoneyShield  |  Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────────────────────
# DESIGN TOKENS  —  fixed dark theme, two-color accent system
# ─────────────────────────────────────────────────────────────────────────────
BG        = "#080d14"          # deepest background
SURFACE   = "#0f1621"          # card / panel surface
SURFACE2  = "#161e2e"          # subtle inset
BORDER    = "#1e2d42"          # borders
TEXT      = "#c9d4e3"          # primary text
SUBTEXT   = "#4b5e78"          # captions, labels
ACCENT    = "#3b82f6"          # primary accent  (electric blue)
DANGER    = "#e53e3e"          # alerts / triggered state
MONO      = "JetBrains Mono"
SANS      = "Inter"

# Mono funnel: single blue ramp from bright to dim
FUNNEL_COLORS = [
    "#1d4ed8",   # LURE_CAPTURED
    "#2563eb",   # APK_DOWNLOADED
    "#3b82f6",   # STATIC_ANALYSIS_COMPLETED
    "#60a5fa",   # DYNAMIC_ANALYSIS_COMPLETED
    "#7c3aed",   # C2_DOMAINS_ISOLATED
    "#8b5cf6",   # TRAP_READY
    "#ef4444",   # TRAP_TRIGGERED  (only exception: danger red)
    "#374151",   # PIPELINE_FAILED
]
STATUS_COLOR_MAP = dict(zip(STATUS_ORDER, FUNNEL_COLORS))

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL CSS
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Reset & base ── */
html, body, [class*="css"] {{
    font-family: '{SANS}', system-ui, sans-serif !important;
    background-color: {BG} !important;
    color: {TEXT} !important;
}}

/* ── Hide sidebar completely ── */
[data-testid="collapsedControl"] {{ display: none !important; }}
section[data-testid="stSidebar"] {{ display: none !important; }}

/* ── Remove top bar chrome ── */
header[data-testid="stHeader"] {{
    background: {BG};
    border-bottom: 1px solid {BORDER};
    height: 0px !important;
}}

/* ── Main container padding ── */
.block-container {{
    padding: 2rem 2.5rem 3rem 2.5rem !important;
    max-width: 100% !important;
}}

/* ── Page title block ── */
.hs-title-bar {{
    padding: 28px 0 20px 0;
    border-bottom: 1px solid {BORDER};
    margin-bottom: 24px;
}}
.hs-title {{
    font-size: 1.55rem;
    font-weight: 700;
    color: {TEXT};
    letter-spacing: -0.01em;
    margin: 0;
    line-height: 1.2;
}}
.hs-subtitle {{
    font-size: 0.78rem;
    color: {SUBTEXT};
    font-weight: 400;
    margin-top: 4px;
    letter-spacing: 0.03em;
    text-transform: uppercase;
}}

/* ── Control bar ── */
.hs-controls {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 14px 20px;
    margin-bottom: 28px;
}}

/* ── Section label ── */
.hs-label {{
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: {SUBTEXT};
    margin-bottom: 12px;
    padding-bottom: 6px;
    border-bottom: 1px solid {BORDER};
}}

/* ── KPI card ── */
.hs-kpi {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 22px 20px 18px 20px;
}}
.hs-kpi-val {{
    font-size: 2.2rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    color: {ACCENT};
    line-height: 1;
    margin-bottom: 6px;
}}
.hs-kpi-val.red {{ color: {DANGER}; }}
.hs-kpi-lbl {{
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: {SUBTEXT};
}}

/* ── Divider ── */
hr {{
    border: none;
    border-top: 1px solid {BORDER} !important;
    margin: 24px 0 !important;
}}

/* ── Alert strip ── */
.hs-alert {{
    background: #1a0a0a;
    border: 1px solid {DANGER};
    border-left: 3px solid {DANGER};
    border-radius: 6px;
    padding: 10px 16px;
    color: #fc8181;
    font-size: 0.82rem;
    font-weight: 600;
    letter-spacing: 0.03em;
    margin-bottom: 20px;
}}

/* ── Status badge ── */
.hs-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 3px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-family: '{MONO}', monospace;
}}

/* ── Mono text ── */
.mono {{
    font-family: '{MONO}', monospace;
    font-size: 0.79rem;
    background: {SURFACE2};
    padding: 2px 7px;
    border-radius: 4px;
    color: {ACCENT};
}}

/* ── Detail panel ── */
.hs-detail-header {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 16px;
    font-size: 0.82rem;
    color: {TEXT};
}}

/* ── Forensic block ── */
.hs-forensic {{
    background: #130808;
    border: 1px solid {DANGER};
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 18px;
}}
.hs-forensic-heading {{
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    color: {DANGER};
    margin-bottom: 6px;
}}
.hs-forensic-body {{
    font-size: 0.82rem;
    color: #fc8181;
}}

/* ── Pending state ── */
.hs-pending {{
    text-align: center;
    padding: 56px 0;
    color: {SUBTEXT};
    font-size: 0.88rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}}

/* ── Dataframe overrides ── */
[data-testid="stDataFrame"] {{
    border: 1px solid {BORDER} !important;
    border-radius: 8px !important;
}}

/* ── Tab strip ── */
button[data-baseweb="tab"] {{
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    letter-spacing: 0.02em !important;
    color: {SUBTEXT} !important;
}}
button[aria-selected="true"][data-baseweb="tab"] {{
    color: {ACCENT} !important;
}}

/* ── Streamlit inputs ── */
.stTextInput input, .stMultiSelect > div {{
    background: {SURFACE2} !important;
    border-color: {BORDER} !important;
    color: {TEXT} !important;
    font-size: 0.82rem !important;
}}
label[data-testid="stWidgetLabel"] p {{
    font-size: 0.72rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    color: {SUBTEXT} !important;
}}
.stButton > button {{
    background: {SURFACE2} !important;
    border: 1px solid {BORDER} !important;
    color: {TEXT} !important;
    font-size: 0.78rem !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
}}
.stButton > button:hover {{
    border-color: {ACCENT} !important;
    color: {ACCENT} !important;
}}
</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def badge_html(status: str) -> str:
    c = STATUS_COLOR_MAP.get(status, "#374151")
    return (
        f'<span class="hs-badge" style="background:{c}20;color:{c};'
        f'border:1px solid {c}50">{status}</span>'
    )

def section(title: str) -> None:
    st.markdown(f'<div class="hs-label">{title}</div>', unsafe_allow_html=True)

def kpi(col, label: str, value, red: bool = False) -> None:
    col.markdown(
        f'<div class="hs-kpi">'
        f'<div class="hs-kpi-val {"red" if red else ""}">{value}</div>'
        f'<div class="hs-kpi-lbl">{label}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

def fmt_dt(val) -> str:
    if not val:
        return "—"
    try:
        dt = datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        return dt.strftime("%d %b %Y  %H:%M UTC")
    except Exception:
        return str(val)

def plotly_base() -> dict:
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=SANS, color=SUBTEXT, size=11),
        margin=dict(l=0, r=0, t=10, b=10),
    )


# ─────────────────────────────────────────────────────────────────────────────
# PAGE TITLE
# ─────────────────────────────────────────────────────────────────────────────
st.markdown(
    f'<div class="hs-title-bar">'
    f'<div class="hs-title">🛡️ &nbsp;HoneyShield</div>'
    f'<div class="hs-subtitle">Threat Intelligence Portal &nbsp;·&nbsp; Phishing APK Campaign Monitor</div>'
    f'</div>',
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# DATA LOAD
# ─────────────────────────────────────────────────────────────────────────────
@st.cache_data(ttl=30)
def load_data():
    return fetch_all_incidents()

try:
    all_docs = load_data()
except ConnectionError as e:
    st.error(f"Database connection failed — {e}")
    st.stop()

metrics = fetch_summary_metrics(all_docs)





# ─────────────────────────────────────────────────────────────────────────────
# ALL INCIDENTS — no filtering
# ─────────────────────────────────────────────────────────────────────────────
filtered = all_docs


# ─────────────────────────────────────────────────────────────────────────────
# KPI RIBBON
# ─────────────────────────────────────────────────────────────────────────────
section("Operational Overview")
k1, k2, k3, k4 = st.columns(4)
kpi(k1, "Total Inbound Attacks",      metrics["total"])
kpi(k2, "Active Probes — Trap Ready", metrics["active_probes"])
kpi(k3, "Successful Captures",        metrics["captures"],      red=True)
kpi(k4, "Pipeline Success Rate",      f"{metrics['success_rate']}%")

st.divider()


# ─────────────────────────────────────────────────────────────────────────────
# CHARTS
# ─────────────────────────────────────────────────────────────────────────────
section("Attack Funnel  &  Status Distribution")
col_f, col_d = st.columns([3, 2])

sc = metrics["status_counts"]

with col_f:
    funnel_s = [s for s in STATUS_ORDER if s != "PIPELINE_FAILED"]
    funnel_v = [sc.get(s, 0) for s in funnel_s]
    fc_colors = FUNNEL_COLORS[:len(funnel_s)]

    fig = go.Figure(go.Funnel(
        y=funnel_s,
        x=funnel_v,
        textposition="inside",
        textinfo="value+percent initial",
        marker=dict(color=fc_colors, line=dict(color=BG, width=1)),
        connector=dict(line=dict(color=BORDER, width=1, dash="dot")),
    ))
    fig.update_layout(**plotly_base(), height=300)
    st.plotly_chart(fig, use_container_width=True)

with col_d:
    labels = list(sc.keys())
    values = [sc[k] for k in labels]
    colors = [STATUS_COLOR_MAP.get(k, "#374151") for k in labels]

    fig2 = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.62,
        marker=dict(colors=colors, line=dict(color=BG, width=2)),
        textinfo="percent",
        textfont=dict(size=10, color=TEXT),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
    ))
    fig2.update_layout(
        **plotly_base(),
        legend=dict(
            orientation="v",
            font=dict(size=9, color=SUBTEXT),
            bgcolor="rgba(0,0,0,0)",
        ),
        height=300,
        annotations=[dict(
            text=f"<b>{metrics['total']}</b><br><span style='font-size:10px'>Total</span>",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=17, color=TEXT),
        )],
    )
    st.plotly_chart(fig2, use_container_width=True)

st.divider()


# ─────────────────────────────────────────────────────────────────────────────
# INCIDENTS TABLE
# ─────────────────────────────────────────────────────────────────────────────
section(f"Incident Register  —  {len(filtered)} record(s)")

if not filtered:
    st.info("No incidents match the current filters.")
else:
    rows = []
    for d in filtered:
        rows.append({
            "Incident ID":   "..." + d["_id"][-10:],
            "Status":        d.get("incident_status", "—"),
            "Threat Score":  d.get("apk_analysis", {}).get("unified_threat_score", 0),
            "Channel":       d.get("ingress_data", {}).get("channel", "—"),
            "Contact":       d.get("ingress_data", {}).get("attacker_contact", "—"),
            "Created":       fmt_dt(d.get("createdAt", "")),
            "__id":          d["_id"],
        })
    df = pd.DataFrame(rows)

    def color_status(val):
        c = STATUS_COLOR_MAP.get(val, "#374151")
        return f"background-color:{c}18;color:{c};font-weight:600;font-size:0.73rem;font-family:'{MONO}'"

    styled = (
        df.drop(columns=["__id"])
          .style
          .applymap(color_status, subset=["Status"])
          .set_properties(**{"font-size": "0.8rem", "color": TEXT})
    )
    st.dataframe(styled, use_container_width=True, height=240)

    st.divider()


    # ─────────────────────────────────────────────────────────────────────────
    # INCIDENT DETAIL INSPECTOR
    # ─────────────────────────────────────────────────────────────────────────
    section("Incident Detail Inspector")

    id_list    = [d["_id"] for d in filtered]
    short_list = ["..." + i[-10:] for i in id_list]

    sel = st.selectbox("Select incident", options=short_list, label_visibility="collapsed")
    incident = next((d for d in filtered if ("..." + d["_id"][-10:]) == sel), None)

    if incident:
        status   = incident.get("incident_status", "—")
        sc_color = STATUS_COLOR_MAP.get(status, "#374151")

        st.markdown(
            f'<div class="hs-detail-header">'
            f'Full ID: &nbsp;<span class="mono">{incident["_id"]}</span>'
            f'&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;'
            f'Status: &nbsp;{badge_html(status)}'
            f'</div>',
            unsafe_allow_html=True,
        )

        tab1, tab2, tab3, tab4 = st.tabs([
            "Ingress & Payload",
            "Threat Intel & C2",
            "Deception Layer",
            "Forensic Intercept",
        ])

        # ── TAB 1 ─────────────────────────────────────────────────────────────
        with tab1:
            ig      = incident.get("ingress_data", {})
            ak      = incident.get("apk_analysis", {})
            scanner = ak.get("scanner_json_report", {})
            perms   = scanner.get("detections", {}).get("permissions", [])

            c1, c2 = st.columns(2)
            with c1:
                section("Ingress Data")
                st.markdown(f"**Attacker Contact** &nbsp; `{ig.get('attacker_contact', '—')}`")
                st.markdown(f"**Channel** &nbsp; `{ig.get('channel', '—')}`")
                st.markdown(f"**Received** &nbsp; {fmt_dt(incident.get('createdAt'))}")
            with c2:
                section("APK Static Analysis")
                st.markdown(f"**Threat Score** &nbsp; `{ak.get('unified_threat_score', 0)} / 100`")
                st.markdown(f"**Verdict** &nbsp; `{ak.get('verdict', 'UNDETECTED')}`")
                st.markdown(f"**SHA-256** &nbsp; `{ak.get('apk_hash') or '—'}`")
                st.markdown(f"**Package** &nbsp; `{scanner.get('package_name') or '—'}`")
                st.markdown(f"**File Size** &nbsp; `{scanner.get('file_size_mb') or '—'} MB`")

            st.divider()

            if perms:
                section("Dangerous Permissions Detected")
                for p in perms:
                    st.error(f"`{p['permission']}` — {p.get('description', '')}")
            else:
                st.success("No dangerous permissions flagged by the static scanner.")

            brands = scanner.get("detections", {}).get("brand_matches", [])
            if brands:
                section("Brand Impersonation Indicators")
                for b in brands:
                    st.warning(f"Brand: `{b['brand']}` | Substrings: `{b.get('allowed_substrings', [])}`")

            h_urls = scanner.get("detections", {}).get("urls", [])
            if h_urls:
                section("Hardcoded URLs in APK")
                for u in h_urls:
                    st.code(u, language=None)

        # ── TAB 2 ─────────────────────────────────────────────────────────────
        with tab2:
            oa = incident.get("osint_analysis", {})
            ia = oa.get("infrastructure_audit", {})

            c1, c2 = st.columns(2)
            with c1:
                section("VirusTotal Analysis")
                st.markdown(f"**Extracted URL** &nbsp; `{oa.get('extracted_url') or '—'}`")
                behaviors = oa.get("sandbox_behaviors", [])
                if behaviors:
                    section("Sandbox Behaviors")
                    for b in behaviors:
                        st.markdown(f"- `{b}`")
                else:
                    st.caption("No dynamic behaviors logged.")
            with c2:
                section("Infrastructure Audit")
                sus = ia.get("suspicious_domains", [])
                if sus:
                    st.error(f"Suspicious Domains: `{', '.join(sus)}`")
                gen = ia.get("general_domains", [])
                if gen:
                    st.warning(f"General Domains: `{', '.join(gen)}`")
                ben = ia.get("benign_domains", [])
                if ben:
                    st.info(f"Filtered Benign: `{', '.join(ben)}`")
                ips = ia.get("outbound_ips", [])
                if ips:
                    st.markdown(f"**Outbound IPs (C2):** `{', '.join(ips)}`")

            c2_eps = oa.get("c2_endpoints_discovered", [])
            if c2_eps:
                section("Active C2 Endpoints Discovered")
                for ep in c2_eps:
                    st.code(ep, language=None)

            all_urls = ia.get("all_extracted_urls", [])
            if all_urls:
                with st.expander("All Extracted URLs from APK"):
                    for u in all_urls:
                        st.code(u, language=None)

        # ── TAB 3 ─────────────────────────────────────────────────────────────
        with tab3:
            ht = incident.get("honeytokens", {})
            section("Synthetic Credentials Assigned to This Campaign")
            st.caption("These credentials were injected into the attacker's C2 server as bait.")
            c1, c2, c3 = st.columns(3)
            c1.metric("Username",           ht.get("username") or "—")
            c2.metric("Password",           ht.get("password") or "—")
            c3.metric("Virtual OTP Number", ht.get("virtual_otp_number") or "—")
            st.divider()
            if status == "TRAP_READY":
                st.success("Trap is armed. Honeytokens injected. Awaiting attacker login on Simulated Bank Portal.")
            elif status == "TRAP_TRIGGERED":
                st.error("Trap has fired. See Forensic Intercept tab for captured attacker data.")
            else:
                st.info(f"Status: `{status}` — Trap not yet armed.")

        # ── TAB 4 ─────────────────────────────────────────────────────────────
        with tab4:
            fi = incident.get("forensic_intercept", {})
            if status == "TRAP_TRIGGERED":
                st.markdown(
                    '<div class="hs-forensic">'
                    '<div class="hs-forensic-heading">LIVE ATTACKER DE-ANONYMISED</div>'
                    '<div class="hs-forensic-body">'
                    'Forensic evidence captured and permanently preserved. '
                    'TTL index removed — document will not auto-expire.'
                    '</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )
                c1, c2, c3 = st.columns(3)
                c1.metric("Attacker Real IP", fi.get("attacker_real_ip") or "—")
                c2.metric("Triggered At",     fmt_dt(fi.get("triggeredAt")))
                c3.metric("Device",           "See below")

                section("Device Fingerprint  (User-Agent)")
                st.code(fi.get("device_fingerprint") or "—", language=None)
                st.divider()
            else:
                st.markdown(
                    '<div class="hs-pending">'
                    'AWAITING TRIGGER<br>'
                    '<span style="font-size:0.75rem;letter-spacing:0.02em;">'
                    'Activates when the attacker attempts login with assigned honeytokens.'
                    '</span>'
                    '</div>',
                    unsafe_allow_html=True,
                )

