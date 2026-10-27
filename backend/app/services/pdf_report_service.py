import os
import json
import html
from typing import Dict, Any
from app.services.audit_log_service import AuditLogService


class PDFReportService:

    @classmethod
    def generate_report(cls, scan_id: str, workspace_path: str, final_output: Dict[str, Any]) -> Dict[str, str]:
        AuditLogService.log_event(
            scan_id=scan_id,
            stage="REPORT_GENERATION",
            event_type="STAGE_START",
            message="Rendering HTML audit report template and building downloadable PDF..."
        )

        findings = final_output.get("findings", [])
        raw_findings = final_output.get("raw_findings", [])
        rejected_findings = final_output.get("rejected_findings", [])
        unresolved_findings = final_output.get("unresolved_findings", [])
        verification_matrix = final_output.get("verification_matrix", {})
        chains = final_output.get("chains", [])

        findings_html_rows = ""
        for f in findings:
            findings_html_rows += f"""
            <div class="finding-card severity-{f.get('severity', 'LOW').lower()}">
                <div class="finding-header">
                    <span class="badge badge-{f.get('severity', 'LOW').lower()}">{f.get('severity')}</span>
                    <h3>{f.get('title')}</h3>
                </div>
                <p><strong>File:</strong> <code>{f.get('file_path')}</code> (Line {f.get('line_number')})</p>
                <p><strong>CVSS Vector:</strong> <code>{f.get('cvss_vector', 'N/A')}</code></p>
                <p><strong>Summary:</strong> {f.get('severity_summary')}</p>
                <div class="evidence-box">
                    <strong>Evidence / Code Snippet:</strong>
                    <pre><code>{chr(10).join(f.get('evidence', []))}</code></pre>
                </div>
                <p><strong>Remediation:</strong> {f.get('remediation', 'N/A')}</p>
            </div>
            """

        def review_rows(items, decision):
            if not items:
                return "<p>No entries.</p>"
            rows = ""
            for item in items:
                rows += f"""
                <div class=\"finding-card\">
                    <div class=\"finding-header\">
                        <span class=\"badge badge-low\">{html.escape(decision)}</span>
                        <h3>{html.escape(str(item.get('title', 'Untitled scanner result')))}</h3>
                    </div>
                    <p><strong>Source:</strong> {html.escape(str(item.get('source', 'scanner')))} | <strong>Severity:</strong> {html.escape(str(item.get('severity', 'UNKNOWN')))}</p>
                    <p><strong>File:</strong> <code>{html.escape(str(item.get('file_path', 'N/A')))}</code> (Line {html.escape(str(item.get('line_number', 'N/A')))})</p>
                    <p><strong>Verification rationale:</strong> {html.escape(str(item.get('reasoning', item.get('severity_summary', 'Scanner evidence retained for review.'))))}</p>
                </div>
                """
            return rows

        matrix_html = f"""
        <div class=\"summary-grid\">
            <div class=\"stat-card\"><div>RAW SCANNER RESULTS</div><div class=\"number\">{verification_matrix.get('raw_total', len(raw_findings))}</div></div>
            <div class=\"stat-card\"><div>CONFIRMED</div><div class=\"number\">{verification_matrix.get('confirmed_total', len(findings))}</div></div>
            <div class=\"stat-card\"><div>FALSE POSITIVES</div><div class=\"number\">{verification_matrix.get('false_positive_total', len(rejected_findings))}</div></div>
            <div class=\"stat-card\"><div>UNRESOLVED</div><div class=\"number\">{verification_matrix.get('unresolved_total', len(unresolved_findings))}</div></div>
        </div>
        """

        chains_html_rows = ""
        for c in chains:
            chains_html_rows += f"""
            <div class="chain-card">
                <h4>🔗 {c.get('title')} <span class="badge badge-critical">{c.get('severity')}</span></h4>
                <p>{c.get('impact')}</p>
                <p><strong>Linked Finding IDs:</strong> {', '.join(c.get('linked_finding_ids', []))}</p>
            </div>
            """

        policy_comp = final_output.get("policy_compliance", {})
        policy_checks = policy_comp.get("checks", [])
        sector_name = policy_comp.get("sector", "general_saas").upper()

        policy_html_rows = ""
        for pc in policy_checks:
            policy_status = pc.get("status", "UNKNOWN").upper()
            status_style = {
                "FAIL": ("badge-critical", "#ef4444"),
                "PASS": ("badge-medium", "#10b981"),
                "PARTIAL": ("badge-high", "#f97316"),
                "UNKNOWN": ("badge-low", "#64748b"),
                "NOT_APPLICABLE": ("badge-low", "#64748b"),
            }
            verdict_badge_class, border_color = status_style.get(policy_status, status_style["UNKNOWN"])

            file_info = f"<code>{pc.get('file_path')}</code> (Line {pc.get('line_number')})" if pc.get('file_path') else "N/A"
            policy_html_rows += f"""
            <div class="finding-card" style="border-left-color: {border_color};">
                <div class="finding-header">
                    <span class="badge {verdict_badge_class}">{policy_status}</span>
                    <h3>{pc.get('rule')}</h3>
                </div>
                <p><strong>Location:</strong> {file_info}</p>
                <div class="evidence-box">
                    <strong>Evidence:</strong>
                    <pre><code>{pc.get('evidence')}</code></pre>
                </div>
            </div>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelAI Security Audit Report - {scan_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; padding: 40px; }}
        .header {{ border-bottom: 3px solid #3b82f6; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ color: #0f172a; margin: 0; font-size: 28px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }}
        .stat-card .number {{ font-size: 32px; font-weight: bold; margin-top: 5px; }}
        .stat-card.critical .number {{ color: #ef4444; }}
        .stat-card.high .number {{ color: #f97316; }}
        .stat-card.medium .number {{ color: #eab308; }}
        .stat-card.low .number {{ color: #3b82f6; }}
        .finding-card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 6px solid #cbd5e1; }}
        .finding-card.severity-critical {{ border-left-color: #ef4444; }}
        .finding-card.severity-high {{ border-left-color: #f97316; }}
        .finding-card.severity-medium {{ border-left-color: #eab308; }}
        .badge {{ padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; display: inline-block; }}
        .badge-critical {{ background: #ef4444; }}
        .badge-high {{ background: #f97316; }}
        .badge-medium {{ background: #10b981; }}
        .badge-low {{ background: #3b82f6; }}
        .evidence-box {{ background: #0f172a; color: #f8fafc; padding: 12px; border-radius: 6px; font-size: 13px; margin: 10px 0; overflow-x: auto; }}
        .chain-card {{ background: #f1f5f9; border: 1px solid #cbd5e1; padding: 15px; border-radius: 8px; margin-bottom: 15px; }}
        .flex-container {{ display: flex; gap: 20px; }}
        .col-half {{ flex: 1; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>SentinelAI Security & Policy Audit Report</h1>
            <p>Scan Reference ID: <code>{scan_id}</code> | Sector Baseline: <strong>{sector_name}</strong></p>
        </div>
    </div>

    <h2>Executive Summary</h2>
    <p>This report retains scanner evidence and verification decisions. A result is only listed as a confirmed vulnerability after Stage 3 review.</p>
    <div class="summary-grid">
        <div class="stat-card critical">
            <div>CRITICAL</div>
            <div class="number">{final_output.get('critical_count', 0)}</div>
        </div>
        <div class="stat-card high">
            <div>HIGH</div>
            <div class="number">{final_output.get('high_count', 0)}</div>
        </div>
        <div class="stat-card medium">
            <div>MEDIUM</div>
            <div class="number">{final_output.get('medium_count', 0)}</div>
        </div>
        <div class="stat-card low">
            <div>LOW</div>
            <div class="number">{final_output.get('low_count', 0)}</div>
        </div>
    </div>

    <h2>Scanner Verification Summary</h2>
    {matrix_html}

    <h2>Vulnerability Attack Chains</h2>
    {chains_html_rows if chains_html_rows else "<p>No complex multi-stage attack chains detected.</p>"}

    <div class="flex-container">
        <div class="col-half">
            <h2>Detailed Security Vulnerabilities</h2>
            {findings_html_rows if findings_html_rows else "<p>No confirmed vulnerabilities. Scanner evidence and review decisions are retained below.</p>"}
        </div>
        <div class="col-half">
            <h2>Sector & Policy Jurisdiction Checks ({sector_name})</h2>
            {policy_html_rows if policy_html_rows else "<p>No policy checks evaluated.</p>"}
        </div>
    </div>
    <h2>Raw Scanner Findings</h2>
    {review_rows(raw_findings, 'RAW SCANNER RESULT')}
    <h2>LLM Verification Decisions — False Positives</h2>
    {review_rows(rejected_findings, 'FALSE POSITIVE')}
    <h2>LLM Verification Decisions — Unresolved</h2>
    {review_rows(unresolved_findings, 'HUMAN REVIEW REQUIRED')}
</body>
</html>
"""


        html_path = f"{workspace_path}/report.html"
        pdf_path = f"{workspace_path}/report.pdf"

        try:
            # 1. Write HTML Report
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            # 2. Build real binary PDF file using ReportLab (%PDF-1.x)
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

            doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=22,
                leading=26,
                textColor=colors.HexColor('#0f172a'),
                fontName='Helvetica-Bold'
            )
            subtitle_style = ParagraphStyle(
                'ReportSubTitle',
                parent=styles['Normal'],
                fontSize=11,
                leading=14,
                textColor=colors.HexColor('#475569')
            )
            heading2_style = ParagraphStyle(
                'SectionHeading',
                parent=styles['Heading2'],
                fontSize=14,
                leading=18,
                textColor=colors.HexColor('#0f172a'),
                fontName='Helvetica-Bold',
                spaceBefore=12,
                spaceAfter=6
            )
            body_style = ParagraphStyle(
                'BodyTextCustom',
                parent=styles['Normal'],
                fontSize=10,
                leading=14,
                textColor=colors.HexColor('#1e293b')
            )

            # Header
            story.append(Paragraph("SentinelAI Security & Compliance Audit Report", title_style))
            story.append(Paragraph(f"Scan ID: <b>{scan_id}</b> | Sector: <b>{sector_name}</b> | Generated by LLM Engine", subtitle_style))
            story.append(Spacer(1, 12))
            story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3b82f6'), spaceAfter=12))

            # Executive Summary Table
            story.append(Paragraph("Executive Summary", heading2_style))
            summary_data = [
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CONFIRMED"],
                [
                    str(final_output.get('critical_count', 0)),
                    str(final_output.get('high_count', 0)),
                    str(final_output.get('medium_count', 0)),
                    str(final_output.get('low_count', 0)),
                    str(final_output.get('total_findings', 0))
                ]
            ]
            summary_table = Table(summary_data, colWidths=[100, 100, 100, 100, 140])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, 1), colors.HexColor('#f8fafc')),
                ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#ef4444')),
                ('TEXTCOLOR', (1, 1), (1, 1), colors.HexColor('#f97316')),
                ('TEXTCOLOR', (2, 1), (2, 1), colors.HexColor('#eab308')),
                ('TEXTCOLOR', (3, 1), (3, 1), colors.HexColor('#3b82f6')),
                ('FONTSIZE', (0, 1), (-1, 1), 14),
                ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 16))

            story.append(Paragraph("Scanner Verification Summary", heading2_style))
            verification_data = [
                ["RAW", "CONFIRMED", "FALSE POSITIVES", "UNRESOLVED"],
                [
                    str(verification_matrix.get('raw_total', len(raw_findings))),
                    str(verification_matrix.get('confirmed_total', len(findings))),
                    str(verification_matrix.get('false_positive_total', len(rejected_findings))),
                    str(verification_matrix.get('unresolved_total', len(unresolved_findings))),
                ],
            ]
            verification_table = Table(verification_data, colWidths=[135, 135, 135, 135])
            verification_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#475569')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cbd5e1')),
            ]))
            story.append(verification_table)
            story.append(Paragraph("Scanner findings are retained below even when no issue is confirmed. False positives are not vulnerabilities; unresolved entries require human review.", body_style))
            story.append(Spacer(1, 12))

            # Attack Chains
            story.append(Paragraph("Vulnerability Attack Chains", heading2_style))
            if chains:
                for c in chains:
                    story.append(Paragraph(f"<b>[ATTACK CHAIN] {c.get('title')}</b> [{c.get('severity')}]", ParagraphStyle('ChainTitle', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor('#ef4444'))))
                    story.append(Paragraph(c.get('impact', ''), body_style))
                    story.append(Paragraph(f"<i>Linked Findings: {', '.join(c.get('linked_finding_ids', []))}</i>", body_style))
                    story.append(Spacer(1, 6))
            else:
                story.append(Paragraph("No complex multi-stage attack chains detected.", body_style))


            story.append(Spacer(1, 12))

            # Detailed Findings
            story.append(Paragraph("Detailed Security Findings", heading2_style))
            if findings:
                for f_item in findings:
                    sev_color = '#ef4444' if f_item.get('severity') == 'CRITICAL' else '#f97316' if f_item.get('severity') == 'HIGH' else '#eab308'
                    story.append(Paragraph(f"<b>[{f_item.get('severity')}] {f_item.get('title')} ({f_item.get('finding_id')})</b>", ParagraphStyle('FTitle', parent=body_style, fontName='Helvetica-Bold', textColor=colors.HexColor(sev_color))))
                    story.append(Paragraph(f"<b>File:</b> <code>{f_item.get('file_path')}</code> : Line {f_item.get('line_number')} | <b>CVSS:</b> {f_item.get('cvss_vector', 'N/A')}", body_style))
                    story.append(Paragraph(f"<b>Summary:</b> {f_item.get('severity_summary')}", body_style))
                    if f_item.get('evidence'):
                        ev_text = "<br/>".join(f_item.get('evidence', []))
                        story.append(Paragraph(f"<b>Evidence:</b> <font face='Courier' color='#0f172a'>{ev_text}</font>", body_style))
                    if f_item.get('remediation'):
                        story.append(Paragraph(f"<b>Remediation:</b> {f_item.get('remediation')}", body_style))
                    story.append(Spacer(1, 8))
            else:
                story.append(Paragraph("No confirmed vulnerabilities. Refer to the raw scanner and verification-decision sections for the evidence reviewed in this scan.", body_style))

            for section_title, items, label in [
                ("Raw Scanner Findings", raw_findings, "RAW"),
                ("Verification Decisions — False Positives", rejected_findings, "FALSE POSITIVE"),
                ("Verification Decisions — Unresolved", unresolved_findings, "HUMAN REVIEW REQUIRED"),
            ]:
                story.append(Spacer(1, 10))
                story.append(Paragraph(section_title, heading2_style))
                if not items:
                    story.append(Paragraph("No entries.", body_style))
                    continue
                for item in items:
                    story.append(Paragraph(f"<b>[{label}] {item.get('title', 'Untitled scanner result')}</b>", body_style))
                    story.append(Paragraph(f"Source: {item.get('source', 'scanner')} | Severity: {item.get('severity', 'UNKNOWN')} | File: {item.get('file_path', 'N/A')} : Line {item.get('line_number', 'N/A')}", body_style))
                    story.append(Paragraph(f"Rationale: {item.get('reasoning', item.get('severity_summary', 'Scanner evidence retained for review.'))}", body_style))
                    story.append(Spacer(1, 5))

            doc.build(story)
            print(f"[PDFReportService] Successfully compiled ReportLab PDF at {pdf_path}")
        except Exception as e:
            print(f"[PDFReportService] Error building PDF report: {e}")

        AuditLogService.log_event(
            scan_id=scan_id,
            stage="REPORT_GENERATION",
            event_type="STAGE_COMPLETE",
            message=f"Report generation complete. Created report.html and binary PDF report.pdf in workspace."
        )

        return {
            "html_report": html_path,
            "pdf_report": pdf_path
        }
