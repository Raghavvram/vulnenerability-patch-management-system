import os
import sys
import json
import asyncio
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

# Ensure src on path
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_path = os.path.join(repo_root, "src")
if os.path.isdir(src_path) and src_path not in sys.path:
	sys.path.insert(0, src_path)

from services.main_orchestrator import process_scan
from services.parser_service import parse_nmap_xml

load_dotenv()

st.set_page_config(page_title="Vulnerability Dashboard", layout="wide")
st.title("Vulnerability Management Dashboard")

with st.sidebar:
	st.header("Upload Scan")
	uploaded = st.file_uploader("Upload Nmap scan XML (scan.xml)", type=["xml"]) 
	use_only_parse = st.checkbox("Parse only (skip enrichment/LLM/prioritization)")
	mock_if_empty = st.checkbox("Mock vulnerabilities if enrichment returns none")
	priority_filter = st.multiselect("Filter by Priority", ["Critical","High","Medium","Low"], [])
	min_cvss = st.slider("Min CVSS", 0.0, 10.0, 0.0, 0.1)
	run_btn = st.button("Process Scan")

@st.cache_data(show_spinner=False)
def parse_only(xml_text: str):
	parsed = parse_nmap_xml(xml_text)
	return parsed

@st.cache_data(show_spinner=False)
def full_process(xml_text: str):
	result = asyncio.run(process_scan(xml_text))
	return result


def _ensure_mock(hosts: list[dict]) -> list[dict]:
	if not hosts:
		return hosts
	any_vuln = any((s.get("vulnerabilities") for h in hosts for s in h.get("services", [])))
	if any_vuln:
		return hosts
	# Inject a small mock vuln to enable charts during demo
	for h in hosts:
		for s in h.get("services", []):
			if s.get("service"):
				s.setdefault("vulnerabilities", []).append({
					"cve_id": "CVE-0000-TEST",
					"cvss": 7.5,
					"epss": 0.4,
					"description": "Demo vulnerability for visualization"
				})
				s["cvss_max"] = max(s.get("cvss_max", 0), 7.5)
				s["epss_max"] = max(s.get("epss_max", 0), 0.4)
				break
		break
	return hosts

if run_btn and uploaded:
	xml_text = uploaded.read().decode("utf-8")
	with st.spinner("Processing scan..."):
		if use_only_parse:
			result = parse_only(xml_text)
		else:
			result = full_process(xml_text)

	st.success("Processing complete")

	# Normalize result structure
	hosts = []
	if "prioritized_hosts" in result:
		hosts = result.get("prioritized_hosts", [])
	elif "analyzed_hosts" in result:
		hosts = result.get("analyzed_hosts", [])
	else:
		hosts = result.get("hosts", [])

	if mock_if_empty:
		hosts = _ensure_mock(hosts)

	# Flatten services
	services_rows = []
	cve_rows = []
	for h in hosts:
		for s in h.get("services", []):
			prio = (s.get("priority_info", {}) or {}).get("priority")
			row = {
				"ip": h.get("ip"),
				"hostname": h.get("hostname", ""),
				"service": s.get("service"),
				"port": s.get("port"),
				"protocol": s.get("protocol"),
				"version": s.get("version", ""),
				"vuln_count": len(s.get("vulnerabilities", [])) if isinstance(s.get("vulnerabilities"), list) else 0,
				"cvss_max": s.get("cvss_max", 0) or 0,
				"epss_max": s.get("epss_max", 0) or 0,
				"priority": prio,
				"priority_score": (s.get("priority_info", {}) or {}).get("priority_score"),
			}
			services_rows.append(row)
			for v in s.get("vulnerabilities", []) or []:
				cve_rows.append({
					"ip": h.get("ip"),
					"hostname": h.get("hostname", ""),
					"service": s.get("service"),
					"port": s.get("port"),
					"cve": v.get("cve_id"),
					"cvss": v.get("cvss", 0) or 0,
					"epss": v.get("epss", 0) or 0,
					"description": (v.get("description", "") or "")[:300]
				})

	services_df = pd.DataFrame(services_rows)
	cve_df = pd.DataFrame(cve_rows)

	# Apply filters
	if priority_filter:
		services_df = services_df[services_df["priority"].isin(priority_filter)]
	if min_cvss > 0 and not services_df.empty:
		services_df = services_df[services_df["cvss_max"] >= min_cvss]
		cve_df = cve_df[cve_df["cvss"] >= min_cvss] if not cve_df.empty else cve_df

	# Tabs for navigation
	tab_overview, tab_cves, tab_hosts, tab_raw = st.tabs(["Overview", "CVEs", "Hosts", "Raw"]) 

	with tab_overview:
		# KPI cards
		c1, c2, c3, c4 = st.columns(4)
		c1.metric("Total Hosts", len(hosts))
		total_services = len(services_df) if not services_df.empty else 0
		c2.metric("Total Services", total_services)
		total_vuln_services = int(services_df[services_df["vuln_count"] > 0]["vuln_count"].count()) if not services_df.empty else 0
		c3.metric("Vulnerable Services", total_vuln_services)
		prioritized = int(services_df[services_df["priority"].notna()]["priority"].count()) if not services_df.empty else 0
		c4.metric("Prioritized Services", prioritized)

		colA, colB = st.columns([2, 1])
		with colA:
			fig = px.treemap(
				services_df.fillna({"hostname": "", "service": "unknown"}),
				path=[px.Constant("All"), "ip", "service", "port"],
				values="vuln_count",
				color="cvss_max",
				color_continuous_scale="Reds",
				title="Vulnerabilities by Host > Service > Port"
			)
			st.plotly_chart(fig, config={"responsive": True, "displaylogo": False})
		with colB:
			sev_counts = services_df["priority"].fillna("None").value_counts().reset_index()
			sev_counts.columns = ["priority", "count"]
			fig2 = px.bar(sev_counts, x="priority", y="count", title="Service Priority Counts", color="priority")
			st.plotly_chart(fig2, config={"responsive": True, "displaylogo": False})

		colC, colD = st.columns([1, 1])
		with colC:
			# Pie chart by service family
			pie_df = services_df.fillna("unknown").groupby("service", as_index=False)["vuln_count"].sum()
			fig_pie = px.pie(pie_df, names="service", values="vuln_count", title="Vulnerabilities by Service")
			st.plotly_chart(fig_pie, config={"responsive": True, "displaylogo": False})
		with colD:
			# Heatmap: Host vs Service by vuln count
			if not services_df.empty:
				pivot = services_df.pivot_table(index="ip", columns="service", values="vuln_count", aggfunc="sum").fillna(0)
				fig_heat = go.Figure(data=go.Heatmap(z=pivot.values, x=list(pivot.columns), y=list(pivot.index), colorscale='Reds'))
				fig_heat.update_layout(title="Heatmap: Host vs Service Vulnerabilities")
				st.plotly_chart(fig_heat, config={"responsive": True, "displaylogo": False})

		st.subheader("Services Table")
		st.dataframe(services_df, width='stretch', height=420)

	with tab_cves:
		if cve_df.empty:
			st.info("No CVEs found.")
		else:
			col1, col2 = st.columns([2,1])
			with col1:
				fig3 = px.scatter(cve_df, x="cvss", y="epss", color="service", hover_data=["cve", "description"], title="CVEs: CVSS vs EPSS")
				st.plotly_chart(fig3, config={"responsive": True, "displaylogo": False})
			with col2:
				top_cves = cve_df.sort_values(["cvss", "epss"], ascending=False).head(15)[["cve", "cvss", "epss", "service"]]
				st.table(top_cves)

			# Line chart: distribution of CVSS
			cvss_hist = cve_df.copy()
			cvss_hist["cvss_bucket"] = (cvss_hist["cvss"].fillna(0) // 1) * 1
			cvss_counts = cvss_hist.groupby("cvss_bucket").size().reset_index(name="count")
			fig_line = px.line(cvss_counts, x="cvss_bucket", y="count", markers=True, title="CVSS Score Distribution (bucketed)")
			st.plotly_chart(fig_line, config={"responsive": True, "displaylogo": False})

	with tab_hosts:
		if services_df.empty:
			st.info("No services to display.")
		else:
			hosts_list = sorted(services_df["ip"].dropna().unique())
			chosen = st.selectbox("Select Host", hosts_list)
			h_df = services_df[services_df["ip"] == chosen]
			st.subheader(f"Host: {chosen}")
			colx, coly = st.columns([2,1])
			with colx:
				fig_bar = px.bar(h_df, x="service", y="vuln_count", color="priority", title="Host Service Vulnerabilities")
				st.plotly_chart(fig_bar, config={"responsive": True, "displaylogo": False})
			with coly:
				prio_counts = h_df["priority"].fillna("None").value_counts().reset_index()
				prio_counts.columns = ["priority", "count"]
				fig_pie2 = px.pie(prio_counts, names="priority", values="count", title="Priorities for Host")
				st.plotly_chart(fig_pie2, config={"responsive": True, "displaylogo": False})
			st.write("Services")
			st.dataframe(h_df, width='stretch', height=380)

	with tab_raw:
		st.subheader("Raw Output")
		st.code(json.dumps(result, indent=2)[:12000])
