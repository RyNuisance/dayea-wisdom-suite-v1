"""
reporter.py — Debrief: Professional PDF Report Generator

This is Module 4 — the final piece of the toolkit.

Think of Debrief as a professional writer who takes all the
raw notes from the Recon, Intel, and Breach, and turns
them into a beautifully formatted document you can hand to a client,
a manager, or a board of directors.

The report includes:
  - Cover page with branding and scan metadata
  - Executive Summary — a plain-English overview for non-technical readers
  - Risk Score — a simple A-F grade based on findings
  - Severity breakdown — how many Critical/High/Medium/Low issues
  - Full findings table — every issue with details and fix guidance
  - Per-module sections — Recon, Intel, and Breach results
  - Recommendations — prioritised list of what to fix first

The PDF is designed to look professional enough to share with
clients and management — not just a raw data dump.
"""

import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm, cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas


# ── Colour Palette ────────────────────────────────────────────────
# Think of these like the paint colours used throughout the report
DARK_BG      = colors.HexColor('#161d30')   # Near-black background
ACCENT_GREEN = colors.HexColor('#2a7de0')   # Dayea Wisdom Suite green
ACCENT_CYAN  = colors.HexColor('#1565c0')   # Cyan accent
TEXT_LIGHT   = colors.HexColor('#e2e8f4')   # Light text on dark
TEXT_MID     = colors.HexColor('#7a9cc4')   # Mid-grey text

# Severity colours — used consistently throughout the report
SEV_CRITICAL = colors.HexColor('#ff3d5a')   # Red
SEV_HIGH     = colors.HexColor('#ff6b35')   # Orange
SEV_MEDIUM   = colors.HexColor('#ffaa00')   # Amber
SEV_LOW      = colors.HexColor('#1565c0')   # Cyan
SEV_INFO     = colors.HexColor('#7a9cc4')   # Grey

# Map severity names to colours
SEVERITY_COLORS = {
    'critical': SEV_CRITICAL,
    'high':     SEV_HIGH,
    'medium':   SEV_MEDIUM,
    'low':      SEV_LOW,
    'info':     SEV_INFO
}

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


# ── Page dimensions (A4) ──────────────────────────────────────────
PAGE_W, PAGE_H = A4
MARGIN = 20 * mm


class ReportBuilder:
    """
    Assembles and renders the complete penetration test report as a PDF.
    
    Uses ReportLab's Platypus (Page Layout and Typography Using Scripts)
    system — a high-level layout engine that handles page breaks,
    text flow, and table rendering automatically.
    
    Think of Platypus like a desktop publisher — you give it a list
    of content "building blocks" (paragraphs, tables, images) and it
    arranges them across pages beautifully.
    """

    def __init__(self, logger):
        self.logger = logger
        self.styles = self._build_styles()

    # ══════════════════════════════════════════════════════════════
    # MAIN BUILD METHOD
    # ══════════════════════════════════════════════════════════════

    def build(self, scan_data: dict, output_path: str) -> str:
        """
        Build the complete PDF report.
        
        Args:
            scan_data:   Dictionary containing all scan results
                         (from Recon, Intel, Breach or combined)
            output_path: Where to save the PDF file
            
        Returns:
            str: Path to the saved PDF file
        """
        self.logger.info(f"Building PDF report → {output_path}")

        # Create the PDF document with page templates (header/footer)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=MARGIN,
            bottomMargin=MARGIN + 10*mm,
            title="Penetration Test Report",
            author="Dayea Wisdom Suite v1.0",
            subject="Security Assessment Report",
            creator="Dayea Wisdom Suite — Professional Security Testing Framework"
        )

        # Collect all the "story" — ordered list of content blocks
        story = []

        # ── Cover Page ───────────────────────────────────────────
        story += self._build_cover_page(scan_data)
        story.append(PageBreak())

        # ── Executive Summary ────────────────────────────────────
        story += self._build_executive_summary(scan_data)
        story.append(PageBreak())

        # ── Findings Overview ────────────────────────────────────
        story += self._build_findings_overview(scan_data)

        # ── Detailed Findings ────────────────────────────────────
        all_findings = scan_data.get('all_findings', [])
        if all_findings:
            story.append(PageBreak())
            story += self._build_detailed_findings(all_findings)

        # ── Recommendations ──────────────────────────────────────
        story.append(PageBreak())
        story += self._build_recommendations(all_findings)

        # ── Appendix: Scan Metadata ──────────────────────────────
        story.append(PageBreak())
        story += self._build_appendix(scan_data)

        # Render to PDF with header/footer on each page
        doc.build(
            story,
            onFirstPage=self._draw_cover_decorations,
            onLaterPages=self._draw_page_header_footer
        )

        self.logger.info(f"PDF report saved: {output_path}")
        return output_path

    # ══════════════════════════════════════════════════════════════
    # COVER PAGE
    # ══════════════════════════════════════════════════════════════

    def _build_cover_page(self, scan_data: dict) -> list:
        """
        Creates the cover page — the first impression of the report.
        Professional, branded, and clear.
        """
        story = []

        # Large vertical spacer to push content towards center
        story.append(Spacer(1, 50*mm))

        # Company / Tool branding
        story.append(Paragraph(
            "🛡️",
            self.styles['cover_icon']
        ))
        story.append(Spacer(1, 5*mm))

        story.append(Paragraph(
            "DAYEA WISDOM SUITE",
            self.styles['cover_brand']
        ))

        story.append(Paragraph(
            "Professional Security Assessment Report",
            self.styles['cover_subtitle']
        ))

        story.append(Spacer(1, 8*mm))
        story.append(HRFlowable(
            width="100%",
            thickness=2,
            color=ACCENT_GREEN,
            spaceAfter=8*mm
        ))

        # Scan metadata table on cover
        meta = scan_data.get('meta', {})
        scope_str = ', '.join(scan_data.get('scope', ['Not defined']))

        meta_data = [
            ['Assessment Date',  meta.get('date', datetime.now().strftime('%Y-%m-%d'))],
            ['Assessment Scope', scope_str],
            ['Modules Run',      meta.get('modules_run', 'Recon, Intel, Breach')],
            ['Total Findings',   str(scan_data.get('total_findings', 0))],
            ['Risk Rating',      self._calculate_risk_grade(scan_data)],
            ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M UTC')],
        ]

        meta_table = Table(meta_data, colWidths=[55*mm, 110*mm])
        meta_table.setStyle(TableStyle([
            ('FONTNAME',    (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE',    (0, 0), (-1, -1), 10),
            ('FONTNAME',    (0, 0), (0, -1),  'Helvetica-Bold'),
            ('TEXTCOLOR',   (0, 0), (0, -1),  ACCENT_GREEN),
            ('TEXTCOLOR',   (1, 0), (1, -1),  colors.HexColor('#e2e8f4')),
            ('BACKGROUND',  (0, 0), (-1, -1), colors.HexColor('#0f1526')),
            ('ROWBACKGROUNDS', (0, 0), (-1, -1),
             [colors.HexColor('#0f1526'), colors.HexColor('#161d30')]),
            ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#1e2d4a')),
            ('PADDING',     (0, 0), (-1, -1), 8),
            ('TOPPADDING',  (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        story.append(meta_table)

        story.append(Spacer(1, 10*mm))

        # Legal disclaimer on cover
        story.append(Paragraph(
            "CONFIDENTIAL — This report contains sensitive security information. "
            "Distribute only to authorised personnel. Unauthorised disclosure may "
            "increase security risk to the assessed systems.",
            self.styles['disclaimer']
        ))

        return story

    def _draw_cover_decorations(self, canv, doc):
        """
        Draws the dark background and decorative elements on the cover page.
        Called by ReportLab for the first page only.
        
        Canvas drawing happens UNDER the content — like drawing on the
        paper before placing text on top.
        """
        canv.saveState()

        # Full dark background
        canv.setFillColor(DARK_BG)
        canv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)

        # Green accent bar at top
        canv.setFillColor(ACCENT_GREEN)
        canv.rect(0, PAGE_H - 8*mm, PAGE_W, 8*mm, fill=1, stroke=0)

        # Subtle grid pattern
        canv.setStrokeColor(colors.HexColor('#1e2740'))
        canv.setLineWidth(0.3)
        for x in range(0, int(PAGE_W), 20):
            canv.line(x, 0, x, PAGE_H)
        for y in range(0, int(PAGE_H), 20):
            canv.line(0, y, PAGE_W, y)

        # Green accent bar at bottom
        canv.setFillColor(colors.HexColor('#0f1526'))
        canv.rect(0, 0, PAGE_W, 15*mm, fill=1, stroke=0)
        canv.setFillColor(ACCENT_GREEN)
        canv.setFont('Helvetica', 8)
        canv.drawString(MARGIN, 6*mm, "Dayea Wisdom Suite v1.0 — Confidential Security Report")
        canv.drawRightString(PAGE_W - MARGIN, 6*mm,
                            datetime.now().strftime('%Y-%m-%d'))

        canv.restoreState()

    def _draw_page_header_footer(self, canv, doc):
        """
        Draws the header and footer on every page AFTER the cover.
        """
        canv.saveState()

        # ── Header ──
        canv.setFillColor(colors.HexColor('#0f1526'))
        canv.rect(0, PAGE_H - 12*mm, PAGE_W, 12*mm, fill=1, stroke=0)

        canv.setFillColor(ACCENT_GREEN)
        canv.rect(0, PAGE_H - 12*mm, 3*mm, 12*mm, fill=1, stroke=0)

        canv.setFillColor(TEXT_LIGHT)
        canv.setFont('Helvetica-Bold', 9)
        canv.drawString(MARGIN, PAGE_H - 7*mm, "🛡️  DAYEA WISDOM SUITE — SECURITY ASSESSMENT REPORT")

        canv.setFillColor(TEXT_MID)
        canv.setFont('Helvetica', 8)
        canv.drawRightString(PAGE_W - MARGIN, PAGE_H - 7*mm, "CONFIDENTIAL")

        # ── Footer ──
        canv.setFillColor(colors.HexColor('#161d30'))
        canv.rect(0, 0, PAGE_W, 10*mm, fill=1, stroke=0)

        canv.setFillColor(colors.HexColor('#7a9cc4'))
        canv.setFont('Helvetica', 7)
        canv.drawString(MARGIN, 4*mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC")
        canv.drawCentredString(PAGE_W / 2, 4*mm, "CONFIDENTIAL — AUTHORISED RECIPIENTS ONLY")
        canv.drawRightString(PAGE_W - MARGIN, 4*mm, f"Page {doc.page}")

        canv.restoreState()

    # ══════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ══════════════════════════════════════════════════════════════

    def _build_executive_summary(self, scan_data: dict) -> list:
        """
        The Executive Summary is written for non-technical readers —
        managers, directors, board members.
        
        It answers: "How bad is it? What are the top 3 things we must fix?"
        in plain English without technical jargon.
        """
        story = []
        story.append(Paragraph("Executive Summary", self.styles['section_title']))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=ACCENT_GREEN, spaceAfter=5*mm))

        all_findings = scan_data.get('all_findings', [])
        sev_counts   = self._count_severities(all_findings)
        grade        = self._calculate_risk_grade(scan_data)
        scope        = scan_data.get('scope', [])

        # Risk grade display
        grade_color = {
            'A': ACCENT_GREEN, 'B': colors.HexColor('#2a7de0'),
            'C': SEV_MEDIUM,   'D': SEV_HIGH,
            'F': SEV_CRITICAL
        }.get(grade[0], SEV_MEDIUM)

        grade_data = [['OVERALL RISK RATING', grade]]
        grade_table = Table(grade_data, colWidths=[120*mm, 45*mm])
        grade_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, -1), colors.HexColor('#0f1526')),
            ('TEXTCOLOR',    (0, 0), (0, 0),   TEXT_LIGHT),
            ('TEXTCOLOR',    (1, 0), (1, 0),   grade_color),
            ('FONTNAME',     (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (0, 0),   12),
            ('FONTSIZE',     (1, 0), (1, 0),   22),
            ('ALIGN',        (1, 0), (1, 0),   'CENTER'),
            ('GRID',         (0, 0), (-1, -1), 1, grade_color),
            ('PADDING',      (0, 0), (-1, -1), 10),
        ]))
        story.append(grade_table)
        story.append(Spacer(1, 5*mm))

        # Plain English summary paragraph
        critical_n = sev_counts.get('critical', 0)
        high_n     = sev_counts.get('high', 0)
        medium_n   = sev_counts.get('medium', 0)
        low_n      = sev_counts.get('low', 0)
        total_n    = len(all_findings)

        if critical_n > 0:
            urgency = (f"The assessment identified <b>{critical_n} CRITICAL</b> vulnerabilities "
                      f"requiring <b>immediate remediation</b>. Critical findings represent issues "
                      f"that could be exploited right now to cause significant damage, data loss, "
                      f"or system compromise.")
        elif high_n > 0:
            urgency = (f"The assessment identified <b>{high_n} HIGH severity</b> vulnerabilities. "
                      f"These should be addressed as a priority within the next 30 days.")
        else:
            urgency = ("No critical or high severity vulnerabilities were identified during this assessment.")

        intro_text = (
            f"A security assessment was conducted against the following scope: "
            f"<b>{', '.join(scope) if scope else 'as defined'}</b>. "
            f"The assessment used three scanning modules: network discovery, vulnerability "
            f"inspection, and web application testing. "
            f"A total of <b>{total_n} security finding(s)</b> were identified across all modules. "
            f"{urgency}"
        )
        story.append(Paragraph(intro_text, self.styles['body_text']))
        story.append(Spacer(1, 5*mm))

        # Findings summary table
        story.append(Paragraph("Findings by Severity", self.styles['subsection_title']))

        sev_data = [
            ['Severity', 'Count', 'Priority', 'Suggested Timeline'],
            ['CRITICAL', str(sev_counts.get('critical', 0)), 'P1 — Immediate',    'Within 24 hours'],
            ['HIGH',     str(sev_counts.get('high', 0)),     'P2 — Urgent',       'Within 7 days'],
            ['MEDIUM',   str(sev_counts.get('medium', 0)),   'P3 — Important',    'Within 30 days'],
            ['LOW',      str(sev_counts.get('low', 0)),      'P4 — Informational','Within 90 days'],
        ]

        sev_table = Table(sev_data, colWidths=[35*mm, 20*mm, 50*mm, 60*mm])
        sev_style = TableStyle([
            # Header row
            ('BACKGROUND',   (0, 0), (-1, 0),  colors.HexColor('#1e2740')),
            ('TEXTCOLOR',    (0, 0), (-1, 0),  ACCENT_GREEN),
            ('FONTNAME',     (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, -1), 9),
            ('ALIGN',        (1, 0), (1, -1),  'CENTER'),
            ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#1e2d4a')),
            ('PADDING',      (0, 0), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#0f1526'), colors.HexColor('#161d30')]),
            # Severity colours in first column
            ('TEXTCOLOR',    (0, 1), (0, 1),  SEV_CRITICAL),
            ('TEXTCOLOR',    (0, 2), (0, 2),  SEV_HIGH),
            ('TEXTCOLOR',    (0, 3), (0, 3),  SEV_MEDIUM),
            ('TEXTCOLOR',    (0, 4), (0, 4),  SEV_LOW),
            ('FONTNAME',     (0, 1), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR',    (1, 1), (1, -1), TEXT_LIGHT),
            ('TEXTCOLOR',    (2, 1), (2, -1), TEXT_MID),
            ('TEXTCOLOR',    (3, 1), (3, -1), TEXT_MID),
        ])
        sev_table.setStyle(sev_style)
        story.append(sev_table)
        story.append(Spacer(1, 5*mm))

        # Top 3 most critical findings
        critical_findings = [f for f in all_findings
                           if f.get('severity') in ['critical', 'high']][:3]

        if critical_findings:
            story.append(Paragraph("Top Priority Issues", self.styles['subsection_title']))
            story.append(Paragraph(
                "The following findings represent the highest priority items requiring immediate attention:",
                self.styles['body_text']
            ))
            story.append(Spacer(1, 3*mm))

            for i, finding in enumerate(critical_findings, 1):
                sev   = finding.get('severity', 'info')
                color = SEVERITY_COLORS.get(sev, SEV_INFO)
                rec   = finding.get('recommendation', 'See detailed findings section.')

                item_data = [[
                    f"#{i}",
                    f"{finding['title']}\n{rec[:120]}{'...' if len(rec) > 120 else ''}"
                ]]
                item_table = Table(item_data, colWidths=[12*mm, 153*mm])
                item_table.setStyle(TableStyle([
                    ('BACKGROUND',   (0, 0), (0, 0),  color),
                    ('BACKGROUND',   (1, 0), (1, 0),  colors.HexColor('#0f1526')),
                    ('TEXTCOLOR',    (0, 0), (0, 0),  colors.HexColor('#161d30')),
                    ('TEXTCOLOR',    (1, 0), (1, 0),  TEXT_LIGHT),
                    ('FONTNAME',     (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE',     (0, 0), (-1, -1), 9),
                    ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
                    ('ALIGN',        (0, 0), (0, 0),   'CENTER'),
                    ('PADDING',      (0, 0), (-1, -1), 8),
                    ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#1e2d4a')),
                ]))
                story.append(item_table)
                story.append(Spacer(1, 2*mm))

        return story

    # ══════════════════════════════════════════════════════════════
    # FINDINGS OVERVIEW — Charts and module summaries
    # ══════════════════════════════════════════════════════════════

    def _build_findings_overview(self, scan_data: dict) -> list:
        """
        A visual overview page showing findings by module and severity.
        """
        story = []
        story.append(Paragraph("Findings Overview", self.styles['section_title']))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=ACCENT_GREEN, spaceAfter=5*mm))

        modules_data = scan_data.get('modules', {})

        for module_name, module_results in modules_data.items():
            if not module_results:
                continue

            findings    = module_results.get('findings', [])
            sev_counts  = self._count_severities(findings)
            total       = len(findings)

            module_labels = {
                'scout':      ('🗺️  Recon',      'Network Scanner',          ACCENT_CYAN),
                'inspector':  ('🔍 Intel',    'Vulnerability Assessment', SEV_MEDIUM),
                'web_tester': ('🌐 Breach',       'OWASP Top 10 Scanner',     ACCENT_GREEN),
            }
            label, subtitle, color = module_labels.get(
                module_name, (module_name, '', ACCENT_GREEN))

            # Module header
            module_header = [[f"{label}", subtitle, f"{total} finding(s)"]]
            header_table  = Table(module_header, colWidths=[70*mm, 80*mm, 35*mm])
            header_table.setStyle(TableStyle([
                ('BACKGROUND',   (0, 0), (-1, -1), colors.HexColor('#0f1526')),
                ('TEXTCOLOR',    (0, 0), (0, 0),   color),
                ('TEXTCOLOR',    (1, 0), (1, 0),   TEXT_MID),
                ('TEXTCOLOR',    (2, 0), (2, 0),   TEXT_LIGHT),
                ('FONTNAME',     (0, 0), (0, 0),   'Helvetica-Bold'),
                ('FONTNAME',     (1, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE',     (0, 0), (0, 0),   12),
                ('FONTSIZE',     (1, 0), (-1, -1), 9),
                ('ALIGN',        (2, 0), (2, 0),   'RIGHT'),
                ('PADDING',      (0, 0), (-1, -1), 8),
                ('LINEBELOW',    (0, 0), (-1, -1), 1, color),
            ]))
            story.append(KeepTogether([header_table, Spacer(1, 2*mm)]))

            # Mini severity bar
            if total > 0:
                bar_data = [[
                    f"Critical: {sev_counts.get('critical', 0)}",
                    f"High: {sev_counts.get('high', 0)}",
                    f"Medium: {sev_counts.get('medium', 0)}",
                    f"Low: {sev_counts.get('low', 0)}"
                ]]
                bar_table = Table(bar_data, colWidths=[41*mm, 41*mm, 41*mm, 42*mm])
                bar_table.setStyle(TableStyle([
                    ('BACKGROUND',  (0, 0), (0, 0), colors.HexColor('#2d0a12') if sev_counts.get('critical', 0) > 0 else colors.HexColor('#161d30')),
                    ('BACKGROUND',  (1, 0), (1, 0), colors.HexColor('#2d1800') if sev_counts.get('high', 0) > 0 else colors.HexColor('#161d30')),
                    ('BACKGROUND',  (2, 0), (2, 0), colors.HexColor('#2d2200') if sev_counts.get('medium', 0) > 0 else colors.HexColor('#161d30')),
                    ('BACKGROUND',  (3, 0), (3, 0), colors.HexColor('#0a1a2d') if sev_counts.get('low', 0) > 0 else colors.HexColor('#161d30')),
                    ('TEXTCOLOR',   (0, 0), (0, 0), SEV_CRITICAL if sev_counts.get('critical', 0) > 0 else TEXT_MID),
                    ('TEXTCOLOR',   (1, 0), (1, 0), SEV_HIGH     if sev_counts.get('high', 0) > 0 else TEXT_MID),
                    ('TEXTCOLOR',   (2, 0), (2, 0), SEV_MEDIUM   if sev_counts.get('medium', 0) > 0 else TEXT_MID),
                    ('TEXTCOLOR',   (3, 0), (3, 0), SEV_LOW      if sev_counts.get('low', 0) > 0 else TEXT_MID),
                    ('FONTNAME',    (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE',    (0, 0), (-1, -1), 9),
                    ('ALIGN',       (0, 0), (-1, -1), 'CENTER'),
                    ('GRID',        (0, 0), (-1, -1), 0.5, colors.HexColor('#1e2d4a')),
                    ('PADDING',     (0, 0), (-1, -1), 6),
                ]))
                story.append(bar_table)

            story.append(Spacer(1, 6*mm))

        return story

    # ══════════════════════════════════════════════════════════════
    # DETAILED FINDINGS
    # ══════════════════════════════════════════════════════════════

    def _build_detailed_findings(self, findings: list) -> list:
        """
        Builds the detailed findings section — one entry per finding,
        sorted by severity (Critical first).
        
        Each finding includes:
          - Severity badge
          - Title
          - Affected host/URL
          - Technical description
          - Recommendation (how to fix it)
          - CVE references (if any)
        """
        story = []
        story.append(Paragraph("Detailed Findings", self.styles['section_title']))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=ACCENT_GREEN, spaceAfter=3*mm))
        story.append(Paragraph(
            f"All {len(findings)} finding(s) are listed below, ordered by severity. "
            "Each finding includes a description and recommended remediation action.",
            self.styles['body_text']
        ))
        story.append(Spacer(1, 5*mm))

        # Sort by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get('severity', 'info'), 4)
        )

        for i, finding in enumerate(sorted_findings, 1):
            sev     = finding.get('severity', 'info').upper()
            color   = SEVERITY_COLORS.get(sev.lower(), SEV_INFO)
            title   = finding.get('title', 'Untitled Finding')
            host    = finding.get('host', finding.get('url', 'N/A'))
            detail  = finding.get('detail', 'No detail provided.')
            rec     = finding.get('recommendation', 'Consult security documentation.')
            cves    = finding.get('cve_refs', [])
            source  = finding.get('source', '')
            owasp   = finding.get('owasp', '')

            # Finding card — uses KeepTogether to avoid awkward page breaks
            card_elements = []

            # Title bar
            title_row = [[f"#{i:02d}", f"[{sev}]  {title}", host]]
            title_table = Table(title_row, colWidths=[12*mm, 130*mm, 23*mm])
            title_table.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (0, 0),  color),
                ('BACKGROUND',  (1, 0), (-1, -1), colors.HexColor('#1e2740')),
                ('TEXTCOLOR',   (0, 0), (0, 0),  colors.HexColor('#161d30')),
                ('TEXTCOLOR',   (1, 0), (1, 0),  TEXT_LIGHT),
                ('TEXTCOLOR',   (2, 0), (2, 0),  ACCENT_CYAN),
                ('FONTNAME',    (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, -1), 9),
                ('ALIGN',       (0, 0), (0, 0),  'CENTER'),
                ('ALIGN',       (2, 0), (2, 0),  'RIGHT'),
                ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING',     (0, 0), (-1, -1), 7),
            ]))
            card_elements.append(title_table)

            # Detail rows
            detail_rows = [['Description', detail]]
            detail_rows.append(['Fix / Recommendation', rec])

            if cves:
                detail_rows.append(['CVE References', '  '.join(cves)])
            if owasp:
                detail_rows.append(['OWASP Category', owasp])
            if source:
                detail_rows.append(['Detection Source', source])

            detail_table = Table(detail_rows, colWidths=[40*mm, 125*mm])
            detail_table.setStyle(TableStyle([
                ('BACKGROUND',   (0, 0), (-1, -1), colors.HexColor('#161d30')),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                 [colors.HexColor('#161d30'), colors.HexColor('#0f1526')]),
                ('TEXTCOLOR',    (0, 0), (0, -1),  ACCENT_GREEN),
                ('TEXTCOLOR',    (1, 0), (1, -1),  TEXT_LIGHT),
                ('FONTNAME',     (0, 0), (0, -1),  'Helvetica-Bold'),
                ('FONTNAME',     (1, 0), (1, -1),  'Helvetica'),
                ('FONTSIZE',     (0, 0), (-1, -1), 8.5),
                ('VALIGN',       (0, 0), (-1, -1), 'TOP'),
                ('PADDING',      (0, 0), (-1, -1), 7),
                ('GRID',         (0, 0), (-1, -1), 0.3, colors.HexColor('#1e2d4a')),
                # Highlight the Fix row
                ('TEXTCOLOR',    (1, 1), (1, 1),   SEV_MEDIUM),
            ]))
            card_elements.append(detail_table)
            card_elements.append(Spacer(1, 4*mm))

            story.append(KeepTogether(card_elements))

        return story

    # ══════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ══════════════════════════════════════════════════════════════

    def _build_recommendations(self, findings: list) -> list:
        """
        A prioritised, actionable remediation roadmap.
        Groups fixes by priority so the team knows exactly what to do first.
        """
        story = []
        story.append(Paragraph("Remediation Roadmap", self.styles['section_title']))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=ACCENT_GREEN, spaceAfter=3*mm))
        story.append(Paragraph(
            "The following prioritised action plan is recommended based on the findings. "
            "Address items in order — Critical issues first, then work down by severity.",
            self.styles['body_text']
        ))
        story.append(Spacer(1, 5*mm))

        priority_groups = [
            ('CRITICAL — Immediate Action (Within 24 Hours)', 'critical', SEV_CRITICAL),
            ('HIGH — Urgent (Within 7 Days)',                  'high',     SEV_HIGH),
            ('MEDIUM — Important (Within 30 Days)',            'medium',   SEV_MEDIUM),
            ('LOW — Informational (Within 90 Days)',           'low',      SEV_LOW),
        ]

        for group_title, severity, color in priority_groups:
            group_findings = [f for f in findings
                            if f.get('severity', 'info') == severity]

            if not group_findings:
                continue

            story.append(Paragraph(group_title, self.styles['priority_header']))

            for finding in group_findings:
                rec  = finding.get('recommendation', 'Review and address this finding.')
                host = finding.get('host', '')

                rec_data = [[
                    f"● {finding['title'][:60]}{'...' if len(finding['title']) > 60 else ''}",
                    f"Host: {host}\n{rec[:200]}{'...' if len(rec) > 200 else ''}"
                ]]
                rec_table = Table(rec_data, colWidths=[65*mm, 100*mm])
                rec_table.setStyle(TableStyle([
                    ('BACKGROUND',  (0, 0), (0, 0), colors.HexColor('#0f1526')),
                    ('BACKGROUND',  (1, 0), (1, 0), colors.HexColor('#161d30')),
                    ('TEXTCOLOR',   (0, 0), (0, 0), color),
                    ('TEXTCOLOR',   (1, 0), (1, 0), TEXT_LIGHT),
                    ('FONTNAME',    (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTNAME',    (0, 0), (0, 0),   'Helvetica-Bold'),
                    ('FONTSIZE',    (0, 0), (-1, -1), 8.5),
                    ('VALIGN',      (0, 0), (-1, -1), 'TOP'),
                    ('PADDING',     (0, 0), (-1, -1), 7),
                    ('GRID',        (0, 0), (-1, -1), 0.3, colors.HexColor('#1e2d4a')),
                ]))
                story.append(rec_table)
                story.append(Spacer(1, 2*mm))

            story.append(Spacer(1, 4*mm))

        return story

    # ══════════════════════════════════════════════════════════════
    # APPENDIX
    # ══════════════════════════════════════════════════════════════

    def _build_appendix(self, scan_data: dict) -> list:
        """Scan metadata, scope, and methodology notes"""
        story = []
        story.append(Paragraph("Appendix — Scan Metadata", self.styles['section_title']))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=ACCENT_GREEN, spaceAfter=5*mm))

        meta = scan_data.get('meta', {})
        rows = [
            ['Field', 'Value'],
            ['Scan Date',       meta.get('date', 'N/A')],
            ['Scope',           ', '.join(scan_data.get('scope', []))],
            ['Modules Used',    meta.get('modules_run', 'N/A')],
            ['Total Findings',  str(scan_data.get('total_findings', 0))],
            ['Recon Duration',  meta.get('scout_duration', 'N/A')],
            ['Intel Duration', meta.get('inspector_duration', 'N/A')],
            ['Breach Duration', meta.get('web_duration', 'N/A')],
            ['Report Generated', datetime.now().isoformat()],
            ['Tool Version',    'Dayea Wisdom Suite v1.0'],
            ['Data Sources',    'Local DB, NVD API, Banner Analysis, Active Probing'],
        ]

        meta_table = Table(rows, colWidths=[65*mm, 100*mm])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0),  colors.HexColor('#1e2740')),
            ('TEXTCOLOR',    (0, 0), (-1, 0),  ACCENT_GREEN),
            ('FONTNAME',     (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTNAME',     (0, 1), (0, -1),  'Helvetica-Bold'),
            ('TEXTCOLOR',    (0, 1), (0, -1),  ACCENT_CYAN),
            ('TEXTCOLOR',    (1, 0), (1, -1),  TEXT_LIGHT),
            ('FONTSIZE',     (0, 0), (-1, -1), 9),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.HexColor('#0f1526'), colors.HexColor('#161d30')]),
            ('GRID',         (0, 0), (-1, -1), 0.5, colors.HexColor('#1e2d4a')),
            ('PADDING',      (0, 0), (-1, -1), 7),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 6*mm))

        # Methodology note
        story.append(Paragraph("Methodology", self.styles['subsection_title']))
        story.append(Paragraph(
            "This assessment was performed using Dayea Wisdom Suite v1.0, a professional "
            "penetration testing framework. The assessment covers three layers: "
            "(1) Network scanning using TCP socket connections and ICMP ping sweep; "
            "(2) Vulnerability assessment using the NVD/CVE database, banner analysis, "
            "and service-specific checks; "
            "(3) Web application testing against OWASP Top 10 categories using "
            "passive and active probing techniques. "
            "All testing was performed within the authorised scope and in accordance "
            "with responsible disclosure practices.",
            self.styles['body_text']
        ))

        story.append(Spacer(1, 6*mm))
        story.append(Paragraph(
            "This report was generated automatically. Findings should be reviewed "
            "and validated by a qualified security professional before remediation. "
            "False positives may be present — especially for low and medium severity items.",
            self.styles['disclaimer']
        ))

        return story

    # ══════════════════════════════════════════════════════════════
    # STYLE DEFINITIONS
    # ══════════════════════════════════════════════════════════════

    def _build_styles(self) -> dict:
        """
        Define all the text styles used throughout the report.
        
        Think of these like paragraph styles in Microsoft Word —
        each style defines font, size, colour, spacing, and alignment.
        """
        base = getSampleStyleSheet()
        styles = {}

        # Cover page styles
        styles['cover_icon'] = ParagraphStyle('cover_icon',
            fontName='Helvetica-Bold', fontSize=48,
            textColor=ACCENT_GREEN, alignment=TA_CENTER, spaceAfter=3*mm)

        styles['cover_brand'] = ParagraphStyle('cover_brand',
            fontName='Helvetica-Bold', fontSize=36,
            textColor=TEXT_LIGHT, alignment=TA_CENTER,
            letterSpacing=8, spaceAfter=2*mm)

        styles['cover_subtitle'] = ParagraphStyle('cover_subtitle',
            fontName='Helvetica', fontSize=14,
            textColor=TEXT_MID, alignment=TA_CENTER, spaceAfter=8*mm)

        # Section headings
        styles['section_title'] = ParagraphStyle('section_title',
            fontName='Helvetica-Bold', fontSize=16,
            textColor=ACCENT_GREEN, spaceAfter=2*mm, spaceBefore=4*mm)

        styles['subsection_title'] = ParagraphStyle('subsection_title',
            fontName='Helvetica-Bold', fontSize=11,
            textColor=ACCENT_CYAN, spaceAfter=3*mm, spaceBefore=3*mm)

        styles['priority_header'] = ParagraphStyle('priority_header',
            fontName='Helvetica-Bold', fontSize=10,
            textColor=TEXT_LIGHT,
            backColor=colors.HexColor('#0f1526'),
            borderPad=6, spaceAfter=3*mm, spaceBefore=5*mm)

        # Body text
        styles['body_text'] = ParagraphStyle('body_text',
            fontName='Helvetica', fontSize=9.5,
            textColor=TEXT_LIGHT, leading=14,
            spaceAfter=3*mm, alignment=TA_JUSTIFY)

        styles['disclaimer'] = ParagraphStyle('disclaimer',
            fontName='Helvetica-Oblique', fontSize=8,
            textColor=TEXT_MID, leading=12,
            borderPad=4, spaceAfter=3*mm)

        return styles

    # ══════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════

    def _count_severities(self, findings: list) -> dict:
        """Count findings by severity level"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in findings:
            sev = f.get('severity', 'info').lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _calculate_risk_grade(self, scan_data: dict) -> str:
        """
        Calculate an overall risk grade (A through F) based on findings.
        
        Simple grading:
          F = Any critical findings
          D = Multiple high findings
          C = High findings or many mediums
          B = Only medium/low findings
          A = Minimal or no findings
        """
        findings  = scan_data.get('all_findings', [])
        counts    = self._count_severities(findings)
        critical  = counts.get('critical', 0)
        high      = counts.get('high', 0)
        medium    = counts.get('medium', 0)

        if critical >= 1:   return 'F — Critical Risk'
        if high >= 3:       return 'D — High Risk'
        if high >= 1:       return 'C — Elevated Risk'
        if medium >= 5:     return 'C — Elevated Risk'
        if medium >= 1:     return 'B — Moderate Risk'
        return 'A — Low Risk'


# ══════════════════════════════════════════════════════════════════
# REPORT COORDINATOR — loads scan data and triggers the build
# ══════════════════════════════════════════════════════════════════

class Debrief:
    """
    Top-level coordinator for report generation.
    
    Loads scan results from the reports/ folder, merges them,
    and hands everything to ReportBuilder to create the PDF.
    """

    def __init__(self, settings: dict, logger,
                 progress_callback=None, finding_callback=None):
        self.settings    = settings
        self.logger      = logger
        self.progress_cb = progress_callback or (lambda p, m: None)
        self.finding_cb  = finding_callback  or (lambda f: None)
        self.builder     = ReportBuilder(logger)

    def run(self, specific_files: list = None) -> str:
        """
        Generate a PDF report from scan results.
        
        Args:
            specific_files: Optional list of specific JSON report files to include.
                           If None, uses all reports in the reports/ folder.
        
        Returns:
            str: Path to the generated PDF
        """
        self.logger.section("DEBRIEF — PDF REPORT GENERATION")
        self.progress_cb(5, "📂 Loading scan results from reports folder...")

        # Load all scan results
        scan_data = self._load_scan_data(specific_files)

        if not scan_data.get('all_findings'):
            self.logger.warning("No findings loaded — report will be empty")
        else:
            self.logger.info(f"Loaded {len(scan_data['all_findings'])} total findings")

        self.progress_cb(30, f"📊 Loaded {len(scan_data.get('all_findings', []))} findings — building PDF...")

        # Generate output path
        os.makedirs("reports", exist_ok=True)
        timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"reports/pentest_report_{timestamp}.pdf"

        self.progress_cb(50, "🎨 Rendering cover page and executive summary...")

        # Build the PDF
        try:
            pdf_path = self.builder.build(scan_data, output_path)
            self.progress_cb(100, f"✅ Report saved: {pdf_path}")
            self.logger.info(f"PDF report generated: {pdf_path}")
            return pdf_path
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            raise

    def _load_scan_data(self, specific_files: list = None) -> dict:
        """
        Loads and merges all JSON scan reports into one unified structure.
        """
        reports_dir  = "reports"
        all_findings = []
        modules      = {}
        scope        = set()
        module_durations = {}

        # Find JSON report files
        if specific_files:
            json_files = specific_files
        else:
            if not os.path.exists(reports_dir):
                return self._empty_scan_data()
            json_files = [
                os.path.join(reports_dir, f)
                for f in os.listdir(reports_dir)
                if f.endswith('.json')
            ]

        if not json_files:
            self.logger.warning("No JSON report files found")
            return self._empty_scan_data()

        self.logger.info(f"Loading {len(json_files)} report file(s)...")

        for filepath in sorted(json_files):
            try:
                with open(filepath, 'r') as f:
                    report = json.load(f)

                module_name = report.get('module', 'unknown')
                findings    = report.get('findings', [])

                # Add source module label to each finding
                for finding in findings:
                    finding['_report_source'] = module_name

                all_findings.extend(findings)
                modules[module_name] = report

                # Collect scope entries
                for s in report.get('scope', []):
                    scope.add(s)

                # Track durations
                duration = report.get('duration_seconds', 'N/A')
                module_durations[f'{module_name}_duration'] = f"{duration}s"

                self.logger.info(f"  Loaded {module_name}: {len(findings)} findings")

            except Exception as e:
                self.logger.error(f"Could not load {filepath}: {e}")

        return {
            'all_findings':  all_findings,
            'modules':       modules,
            'total_findings': len(all_findings),
            'scope':         list(scope),
            'meta': {
                'date':        datetime.now().strftime('%Y-%m-%d'),
                'modules_run': ', '.join(modules.keys()) or 'None',
                **module_durations
            }
        }

    def _empty_scan_data(self) -> dict:
        """Returns an empty scan data structure when no reports are found"""
        return {
            'all_findings':   [],
            'modules':        {},
            'total_findings': 0,
            'scope':          self.settings.get('scope', []),
            'meta': {
                'date':        datetime.now().strftime('%Y-%m-%d'),
                'modules_run': 'None'
            }
        }
