"""Renders findings + the principal graph to a static HTML report.
No web framework: string.Template (stdlib) for the shell, pyvis for the
interactive graph. Open output/report.html in a browser, that's the demo.
"""
import os
from datetime import datetime, timezone
from html import escape
from string import Template

from pyvis.network import Network

from .cis_mapping import controls_for

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLOR = {
    "Critical": "#b91c1c", "High": "#c2410c", "Medium": "#a16207", "Low": "#15803d", "Info": "#1d4ed8",
}

REPORT_TEMPLATE = Template("""<!doctype html>
<html><head><meta charset="utf-8"><title>IAM Privilege Escalation Report - $account_id</title>
<style>
body { font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0b1220; color:#e2e8f0; }
h1 { font-size: 1.4rem; }
.summary { display:flex; gap:1rem; margin: 1rem 0 2rem; }
.card { background:#111827; border-radius:8px; padding:1rem 1.5rem; border:1px solid #1f2937; min-width:6rem; }
.card .n { font-size:1.8rem; font-weight:700; }
table { width:100%; border-collapse: collapse; margin-top:1rem; }
th, td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #1f2937; font-size:.9rem; vertical-align:top; }
th { color:#94a3b8; text-transform:uppercase; font-size:.75rem; }
.sev { display:inline-block; padding:.15rem .6rem; border-radius:999px; font-size:.75rem; font-weight:600; color:#fff; white-space:nowrap; }
iframe { width:100%; height:600px; border:1px solid #1f2937; border-radius:8px; background:#fff; }
.evidence { color:#94a3b8; }
.controls { color:#60a5fa; font-size:.8rem; }
</style></head>
<body>
<h1>IAM Privilege Escalation Report</h1>
<p>Account: <code>$account_id</code> &mdash; generated $generated_at</p>
<div class="summary">$summary_cards</div>
<h2>Attack path graph</h2>
<iframe src="graph.html"></iframe>
<h2>Findings ($finding_count)</h2>
<table>
<tr><th>Severity</th><th>Rule</th><th>Principal</th><th>Target</th><th>Evidence</th><th>Compliance</th></tr>
$rows
</table>
</body></html>""")

ROW_TEMPLATE = Template("""<tr>
<td><span class="sev" style="background:$color">$severity</span></td>
<td>$title</td>
<td>$principal ($principal_type)</td>
<td>$target</td>
<td class="evidence">$evidence</td>
<td class="controls">$controls</td>
</tr>""")


def _build_pyvis_graph(graph, findings, out_path):
    net = Network(height="600px", width="100%", directed=True, bgcolor="#0b1220", font_color="#e2e8f0",
                   cdn_resources="in_line")
    flagged = {f["principal"] for f in findings} | {f["target"] for f in findings}
    for node, data in graph.nodes(data=True):
        if data.get("admin"):
            color = "#b91c1c"
        elif node in flagged:
            color = "#c2410c"
        else:
            color = "#1d4ed8"
        shape = "box" if data.get("type") == "role" else "ellipse"
        label = "admin-equivalent" if data.get("admin") else data.get("type", "")
        net.add_node(node, label=node, color=color, shape=shape, title=f"{node}: {label}")
    for src, dst, data in graph.edges(data=True):
        net.add_edge(src, dst, title=data.get("relation", ""))
    # pyvis's own write_html() opens the file with the platform default
    # encoding (cp1252 on Windows), which breaks on inlined unicode assets.
    # Generate the HTML string ourselves and write it as UTF-8 explicitly.
    html = net.generate_html(name=os.path.basename(out_path))
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)


def generate_report(graph, findings, account_id, out_dir="output") -> str:
    os.makedirs(out_dir, exist_ok=True)
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    _build_pyvis_graph(graph, findings, os.path.join(out_dir, "graph.html"))

    counts: dict = {}
    for f in findings_sorted:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary_cards = "".join(
        f'<div class="card"><div class="n">{counts.get(sev, 0)}</div><div>{sev}</div></div>'
        for sev in ["Critical", "High", "Medium", "Low", "Info"] if counts.get(sev)
    )

    rows = []
    for f in findings_sorted:
        controls = controls_for(f["rule_id"])
        control_text = "; ".join(controls.get("cis_aws", []) + controls.get("nist_csf", []))
        rows.append(ROW_TEMPLATE.substitute(
            color=SEVERITY_COLOR.get(f["severity"], "#475569"),
            severity=escape(f["severity"]),
            title=escape(f["title"]),
            principal=escape(f["principal"]),
            principal_type=escape(f["principal_type"]),
            target=escape(f["target"]),
            evidence=escape(f["evidence"]),
            controls=escape(control_text),
        ))

    html_out = REPORT_TEMPLATE.substitute(
        account_id=escape(account_id),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        summary_cards=summary_cards or '<div class="card"><div class="n">0</div><div>No findings</div></div>',
        finding_count=len(findings_sorted),
        rows="\n".join(rows) if rows else '<tr><td colspan="6">No findings.</td></tr>',
    )
    report_path = os.path.join(out_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(html_out)
    return report_path
