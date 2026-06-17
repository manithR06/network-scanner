from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
import os

# ── Custom Colors ─────────────────────────────────────────────────
COLOR_BG_DARK = colors.HexColor('#0d1117')
COLOR_PRIMARY = colors.HexColor('#238636')
COLOR_DANGER = colors.HexColor('#da3633')
COLOR_WARNING = colors.HexColor('#d29922')
COLOR_INFO = colors.HexColor('#1f6feb')
COLOR_TEXT = colors.HexColor('#24292f')
COLOR_MUTED = colors.HexColor('#57606a')
COLOR_BORDER = colors.HexColor('#d0d7de')
COLOR_HEADER_BG = colors.HexColor('#161b22')
COLOR_CRITICAL = colors.HexColor('#da3633')
COLOR_HIGH = colors.HexColor('#fd7e14')
COLOR_MEDIUM = colors.HexColor('#d29922')
COLOR_LOW = colors.HexColor('#238636')


def get_risk_color(risk_level):
    """Return color based on risk level string."""
    return {
        'critical': COLOR_CRITICAL,
        'high':     COLOR_HIGH,
        'medium':   COLOR_MEDIUM,
        'low':      COLOR_LOW,
    }.get(risk_level.lower(), COLOR_MUTED)


def get_styles():
    """Build and return all paragraph styles used in the report."""
    base = getSampleStyleSheet()

    styles = {
        'title': ParagraphStyle(
            'ReportTitle',
            fontSize=28,
            fontName='Helvetica-Bold',
            textColor=COLOR_TEXT,
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        'subtitle': ParagraphStyle(
            'Subtitle',
            fontSize=13,
            fontName='Helvetica',
            textColor=COLOR_MUTED,
            alignment=TA_CENTER,
            spaceAfter=4,
        ),
        'section_heading': ParagraphStyle(
            'SectionHeading',
            fontSize=14,
            fontName='Helvetica-Bold',
            textColor=COLOR_TEXT,
            spaceBefore=18,
            spaceAfter=8,
            borderPad=4,
        ),
        'body': ParagraphStyle(
            'Body',
            fontSize=10,
            fontName='Helvetica',
            textColor=COLOR_TEXT,
            spaceAfter=4,
            leading=16,
        ),
        'body_bold': ParagraphStyle(
            'BodyBold',
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=COLOR_TEXT,
            spaceAfter=4,
        ),
        'small': ParagraphStyle(
            'Small',
            fontSize=8,
            fontName='Helvetica',
            textColor=COLOR_MUTED,
            spaceAfter=2,
        ),
        'risk_critical': ParagraphStyle(
            'RiskCritical',
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=COLOR_CRITICAL,
        ),
        'risk_high': ParagraphStyle(
            'RiskHigh',
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=COLOR_HIGH,
        ),
        'risk_medium': ParagraphStyle(
            'RiskMedium',
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=COLOR_MEDIUM,
        ),
        'risk_low': ParagraphStyle(
            'RiskLow',
            fontSize=10,
            fontName='Helvetica-Bold',
            textColor=COLOR_LOW,
        ),
        'footer': ParagraphStyle(
            'Footer',
            fontSize=8,
            fontName='Helvetica',
            textColor=COLOR_MUTED,
            alignment=TA_CENTER,
        ),
        'center': ParagraphStyle(
            'Center',
            fontSize=10,
            fontName='Helvetica',
            textColor=COLOR_TEXT,
            alignment=TA_CENTER,
        ),
    }
    return styles


# ── PAGE TEMPLATE (header/footer on every page) ───────────────────

def make_page_template(canvas, doc):
    """Draws header and footer on every page."""
    canvas.saveState()
    width, height = A4

    # ── Top header bar ──
    canvas.setFillColor(COLOR_BG_DARK)
    canvas.rect(0, height - 50, width, 50, fill=1, stroke=0)

    canvas.setFillColor(colors.white)
    canvas.setFont('Helvetica-Bold', 14)
    canvas.drawString(40, height - 32, '🔒 NetScanner')

    canvas.setFont('Helvetica', 9)
    canvas.setFillColor(colors.HexColor('#8b949e'))
    canvas.drawRightString(width - 40, height - 32,
                           'Network Security Assessment Report')

    # ── Bottom footer bar ──
    canvas.setFillColor(colors.HexColor('#f6f8fa'))
    canvas.rect(0, 0, width, 35, fill=1, stroke=0)

    canvas.setFillColor(COLOR_MUTED)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(
        40, 13, f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}')
    canvas.drawCentredString(
        width / 2, 13, 'CONFIDENTIAL — For authorized personnel only')
    canvas.drawRightString(width - 40, 13, f'Page {doc.page}')

    # ── Green accent line under header ──
    canvas.setStrokeColor(COLOR_PRIMARY)
    canvas.setLineWidth(2)
    canvas.line(0, height - 51, width, height - 51)

    canvas.restoreState()


# ── HELPER: Build a styled table ─────────────────────────────────

def styled_table(data, col_widths, header_bg=None):
    """Create a styled ReportLab table with alternating row colors."""
    if header_bg is None:
        header_bg = colors.HexColor('#f6f8fa')

    table = Table(data, colWidths=col_widths, repeatRows=1)
    style = TableStyle([
        # Header row
        ('BACKGROUND',  (0, 0), (-1, 0), header_bg),
        ('TEXTCOLOR',   (0, 0), (-1, 0), COLOR_TEXT),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, 0), 9),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('TOPPADDING',    (0, 0), (-1, 0), 8),

        # Data rows
        ('FONTNAME',    (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 1), (-1, -1), 9),
        ('TOPPADDING',  (0, 1), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.white, colors.HexColor('#f6f8fa')]),

        # Borders
        ('GRID',        (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('LINEBELOW',   (0, 0), (-1, 0), 1.5, COLOR_PRIMARY),

        # Padding
        ('LEFTPADDING',  (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ('VALIGN',       (0, 0), (-1, -1), 'MIDDLE'),
    ])
    table.setStyle(style)
    return table


# ── SECTION BUILDERS ─────────────────────────────────────────────

def build_cover_page(scan, styles):
    """Build the cover/title page elements."""
    elements = []
    width, height = A4

    elements.append(Spacer(1, 1.5 * inch))

    # Title
    elements.append(
        Paragraph('Network Security Assessment Report', styles['title']))
    elements.append(Spacer(1, 0.1 * inch))

    # Divider
    elements.append(HRFlowable(
        width='80%', thickness=2,
        color=COLOR_PRIMARY, hAlign='CENTER'
    ))
    elements.append(Spacer(1, 0.2 * inch))

    # Target info
    elements.append(Paragraph(f'Target: {scan.target}', styles['subtitle']))
    elements.append(Paragraph(
        f'Scan Type: {scan.scan_type.capitalize()}',
        styles['subtitle']
    ))
    elements.append(Paragraph(
        f'Date: {scan.started_at.strftime("%B %d, %Y")}',
        styles['subtitle']
    ))
    elements.append(Spacer(1, 0.4 * inch))

    # Risk score box
    risk_color = get_risk_color(
        'critical' if scan.risk_score >= 8
        else 'high' if scan.risk_score >= 5
        else 'medium' if scan.risk_score >= 2
        else 'low'
    )

    score_data = [
        ['OVERALL RISK SCORE'],
        [f'{scan.risk_score:.1f} / 10'],
    ]
    score_table = Table(score_data, colWidths=[3 * inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0), risk_color),
        ('TEXTCOLOR',     (0, 0), (-1, 0), colors.white),
        ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0), 10),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('BACKGROUND',    (0, 1), (-1, 1), colors.HexColor('#f6f8fa')),
        ('TEXTCOLOR',     (0, 1), (-1, 1), risk_color),
        ('FONTNAME',      (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 1), (-1, 1), 32),
        ('TOPPADDING',    (0, 1), (-1, 1), 12),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 12),
        ('BOX',           (0, 0), (-1, -1), 1.5, risk_color),
    ]))

    # Center the score table
    wrapper = Table([[score_table]], colWidths=[A4[0] - 2 * inch])
    wrapper.setStyle(TableStyle([('ALIGN', (0, 0), (-1, -1), 'CENTER')]))
    elements.append(wrapper)
    elements.append(Spacer(1, 0.5 * inch))

    # Confidentiality notice
    elements.append(HRFlowable(width='60%', thickness=0.5,
                    color=COLOR_BORDER, hAlign='CENTER'))
    elements.append(Spacer(1, 0.15 * inch))
    elements.append(Paragraph(
        'CONFIDENTIAL — This report contains sensitive security information.',
        styles['footer']
    ))
    elements.append(Paragraph(
        'Unauthorized disclosure is prohibited. For authorized personnel only.',
        styles['footer']
    ))

    elements.append(PageBreak())
    return elements


def build_executive_summary(scan, styles):
    """Build the executive summary section."""
    elements = []

    elements.append(Paragraph('1. Executive Summary',
                    styles['section_heading']))
    elements.append(HRFlowable(
        width='100%', thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 0.15 * inch))

    # Count risk levels
    critical = sum(1 for h in scan.hosts if h.risk_level == 'critical')
    high = sum(1 for h in scan.hosts if h.risk_level == 'high')
    medium = sum(1 for h in scan.hosts if h.risk_level == 'medium')
    low = sum(1 for h in scan.hosts if h.risk_level == 'low')
    total_ports = sum(len(h.ports) for h in scan.hosts)

    # Summary paragraph
    duration = ''
    if scan.completed_at and scan.started_at:
        secs = int((scan.completed_at - scan.started_at).total_seconds())
        duration = f'{secs} seconds'

    elements.append(Paragraph(
        f'A {scan.scan_type} network security scan was conducted against target '
        f'<b>{scan.target}</b> on {scan.started_at.strftime("%B %d, %Y at %H:%M UTC")}. '
        f'The scan completed in {duration} and identified <b>{scan.total_hosts} live host(s)</b> '
        f'with a total of <b>{total_ports} open port(s)</b>. '
        f'The overall network risk score is <b>{scan.risk_score:.1f}/10</b>.',
        styles['body']
    ))
    elements.append(Spacer(1, 0.2 * inch))

    # Summary stats table
    summary_data = [
        ['Metric', 'Value'],
        ['Target',          scan.target],
        ['Scan Type',       scan.scan_type.capitalize()],
        ['Scan Started',    scan.started_at.strftime('%Y-%m-%d %H:%M UTC')],
        ['Scan Completed',  scan.completed_at.strftime(
            '%Y-%m-%d %H:%M UTC') if scan.completed_at else 'N/A'],
        ['Duration',        duration or 'N/A'],
        ['Live Hosts Found', str(scan.total_hosts)],
        ['Open Ports Found', str(total_ports)],
        ['Overall Risk Score', f'{scan.risk_score:.1f} / 10'],
    ]

    width = A4[0] - 2 * inch
    table = styled_table(summary_data, [width * 0.4, width * 0.6])
    elements.append(table)
    elements.append(Spacer(1, 0.25 * inch))

    # Risk breakdown table
    elements.append(Paragraph('Risk Level Breakdown', styles['body_bold']))
    elements.append(Spacer(1, 0.1 * inch))

    risk_data = [
        ['Risk Level', 'Host Count', 'Description'],
        ['CRITICAL', str(critical), 'Immediate action required'],
        ['HIGH',     str(high),     'Address within 24 hours'],
        ['MEDIUM',   str(medium),   'Address within 7 days'],
        ['LOW',      str(low),      'Monitor and review'],
    ]

    risk_table = Table(risk_data, colWidths=[
                       width * 0.25, width * 0.2, width * 0.55])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (-1, 0), colors.HexColor('#f6f8fa')),
        ('FONTNAME',    (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('GRID',        (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ('LINEBELOW',   (0, 0), (-1, 0), 1.5, COLOR_PRIMARY),
        ('ALIGN',       (1, 0), (1, -1), 'CENTER'),
        ('TOPPADDING',  (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('VALIGN',      (0, 0), (-1, -1), 'MIDDLE'),
        # Color the risk level cells
        ('TEXTCOLOR',   (0, 1), (0, 1), COLOR_CRITICAL),
        ('TEXTCOLOR',   (0, 2), (0, 2), COLOR_HIGH),
        ('TEXTCOLOR',   (0, 3), (0, 3), COLOR_MEDIUM),
        ('TEXTCOLOR',   (0, 4), (0, 4), COLOR_LOW),
        ('FONTNAME',    (0, 1), (0, -1), 'Helvetica-Bold'),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1),
         [colors.white, colors.HexColor('#f6f8fa')]),
    ]))
    elements.append(risk_table)
    elements.append(PageBreak())
    return elements


def build_host_details(scan, styles):
    """Build detailed findings for each host."""
    elements = []

    elements.append(Paragraph('2. Detailed Findings',
                    styles['section_heading']))
    elements.append(HRFlowable(
        width='100%', thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 0.15 * inch))

    if not scan.hosts:
        elements.append(
            Paragraph('No live hosts were discovered during this scan.', styles['body']))
        return elements

    width = A4[0] - 2 * inch

    for i, host in enumerate(scan.hosts, 1):
        risk_color = get_risk_color(host.risk_level)

        # Host header bar
        host_header_data = [[
            f'Host {i}: {host.ip_address}',
            f'{host.risk_level.upper()}  Score: {host.risk_score:.1f}'
        ]]
        host_header = Table(host_header_data, colWidths=[
                            width * 0.65, width * 0.35])
        host_header.setStyle(TableStyle([
            ('BACKGROUND',  (0, 0), (-1, -1), colors.HexColor('#f6f8fa')),
            ('FONTNAME',    (0, 0), (0, 0),   'Helvetica-Bold'),
            ('FONTNAME',    (1, 0), (1, 0),   'Helvetica-Bold'),
            ('FONTSIZE',    (0, 0), (-1, -1), 10),
            ('TEXTCOLOR',   (0, 0), (0, 0),   COLOR_TEXT),
            ('TEXTCOLOR',   (1, 0), (1, 0),   risk_color),
            ('ALIGN',       (1, 0), (1, 0),   'RIGHT'),
            ('TOPPADDING',  (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ('LINEBELOW',   (0, 0), (-1, 0),  2, risk_color),
            ('BOX',         (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ]))
        elements.append(host_header)
        elements.append(Spacer(1, 0.08 * inch))

        # Host info row
        info_items = [
            ['Hostname', host.hostname or 'N/A'],
            ['OS',       host.os_name or 'Not detected'],
            ['Status',   host.status.upper()],
            ['Open Ports', str(len(host.ports))],
        ]
        info_data = [[item[0] for item in info_items],
                     [item[1] for item in info_items]]
        info_table = Table(info_data, colWidths=[width / 4] * 4)
        info_table.setStyle(TableStyle([
            ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#f6f8fa')),
            ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',     (0, 0), (-1, -1), 8),
            ('TEXTCOLOR',    (0, 0), (-1, 0), COLOR_MUTED),
            ('ALIGN',        (0, 0), (-1, -1), 'CENTER'),
            ('TOPPADDING',   (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('GRID',         (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 0.1 * inch))

        # Ports table
        if host.ports:
            port_data = [['Port', 'Protocol', 'Service', 'Version', 'Risk']]
            for port in host.ports:
                port_data.append([
                    str(port.port_number),
                    port.protocol.upper(),
                    port.service_name or '—',
                    (port.service_version or '—')[:35],
                    port.risk_level.upper(),
                ])

            port_table = Table(
                port_data,
                colWidths=[
                    width * 0.10,
                    width * 0.12,
                    width * 0.18,
                    width * 0.40,
                    width * 0.20,
                ]
            )

            # Build base style
            ts = TableStyle([
                ('BACKGROUND',   (0, 0), (-1, 0), colors.HexColor('#f6f8fa')),
                ('FONTNAME',     (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE',     (0, 0), (-1, -1), 8),
                ('GRID',         (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ('LINEBELOW',    (0, 0), (-1, 0),  1, COLOR_PRIMARY),
                ('TOPPADDING',   (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING',  (0, 0), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [colors.white, colors.HexColor('#f6f8fa')]),
            ])

            # Color each risk cell in the last column
            for row_idx, port in enumerate(host.ports, start=1):
                rc = get_risk_color(port.risk_level)
                ts.add('TEXTCOLOR',  (4, row_idx), (4, row_idx), rc)
                ts.add('FONTNAME',   (4, row_idx),
                       (4, row_idx), 'Helvetica-Bold')

            port_table.setStyle(ts)
            elements.append(port_table)
        else:
            elements.append(
                Paragraph('No open ports found on this host.', styles['small']))

        elements.append(Spacer(1, 0.25 * inch))

    return elements


def build_recommendations(scan, styles):
    """Build the recommendations section based on findings."""
    elements = []

    elements.append(PageBreak())
    elements.append(Paragraph('3. Recommendations', styles['section_heading']))
    elements.append(HRFlowable(
        width='100%', thickness=0.5, color=COLOR_BORDER))
    elements.append(Spacer(1, 0.15 * inch))

    # Collect all unique risky ports found
    found_ports = set()
    for host in scan.hosts:
        for port in host.ports:
            if port.risk_level in ('critical', 'high', 'medium'):
                found_ports.add(
                    (port.port_number, port.service_name, port.risk_level))

    recommendations = {
        23:   ('CRITICAL', 'Disable Telnet immediately',
               'Telnet transmits data in plain text. Replace with SSH (port 22) for all remote access.'),
        445:  ('CRITICAL', 'Review SMB exposure',
               'SMB (port 445) is a common ransomware target. Disable if not needed or restrict with firewall rules.'),
        3389: ('CRITICAL', 'Secure RDP access',
               'RDP is a common brute-force target. Enable Network Level Authentication, use VPN, and restrict by IP.'),
        3306: ('CRITICAL', 'Restrict MySQL access',
               'Database ports should never be exposed publicly. Bind to localhost or use a firewall to restrict access.'),
        1433: ('CRITICAL', 'Restrict MSSQL access',
               'Database ports should never be exposed publicly. Use firewall rules to limit access.'),
        5432: ('CRITICAL', 'Restrict PostgreSQL access',
               'Database ports should never be exposed publicly. Restrict with pg_hba.conf and firewall rules.'),
        6379: ('CRITICAL', 'Secure Redis immediately',
               'Redis often has no authentication by default. Add requirepass in redis.conf and bind to localhost.'),
        27017: ('CRITICAL', 'Secure MongoDB immediately',
                'MongoDB often has no authentication. Enable auth and bind to localhost immediately.'),
        21:   ('HIGH', 'Replace FTP with SFTP',
               'FTP transmits credentials in plain text. Switch to SFTP (port 22) or FTPS for secure file transfer.'),
        5900: ('HIGH', 'Secure VNC access',
               'VNC traffic is often unencrypted. Use SSH tunneling for VNC or switch to a more secure remote desktop solution.'),
        135:  ('HIGH', 'Restrict Windows RPC',
               'Windows RPC (port 135) is a common attack vector. Block at the firewall if not required externally.'),
        139:  ('HIGH', 'Restrict NetBIOS',
               'NetBIOS (port 139) can expose Windows shares. Disable or restrict at the firewall.'),
        22:   ('MEDIUM', 'Harden SSH configuration',
               'Disable password authentication, use SSH keys only. Consider changing from default port 22.'),
        80:   ('LOW', 'Consider redirecting HTTP to HTTPS',
               'Serve web content over HTTPS (port 443) only. Redirect all HTTP traffic to HTTPS.'),
    }

    added = []
    for port_num, service, risk_level in sorted(found_ports, key=lambda x: x[2]):
        if port_num in recommendations:
            priority, title, detail = recommendations[port_num]
            added.append((priority, port_num, service, title, detail))

    if added:
        rec_data = [['Priority', 'Port', 'Service', 'Recommendation']]
        for priority, port_num, service, title, detail in added:
            rc = get_risk_color(priority.lower())
            rec_data.append(
                [priority, str(port_num), service or '—', f'{title}\n{detail}'])

        width = A4[0] - 2 * inch
        rec_table = Table(
            rec_data,
            colWidths=[width * 0.15, width * 0.08, width * 0.15, width * 0.62]
        )

        ts = TableStyle([
            ('BACKGROUND',    (0, 0), (-1, 0), colors.HexColor('#f6f8fa')),
            ('FONTNAME',      (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, -1), 8),
            ('GRID',          (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ('LINEBELOW',     (0, 0), (-1, 0),  1.5, COLOR_PRIMARY),
            ('TOPPADDING',    (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING',   (0, 0), (-1, -1), 8),
            ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f6f8fa')]),
        ])

        for i, (priority, *_) in enumerate(added, start=1):
            rc = get_risk_color(priority.lower())
            ts.add('TEXTCOLOR', (0, i), (0, i), rc)
            ts.add('FONTNAME',  (0, i), (0, i), 'Helvetica-Bold')

        rec_table.setStyle(ts)
        elements.append(rec_table)
    else:
        elements.append(Paragraph(
            'No specific recommendations — no high risk services detected.',
            styles['body']
        ))

    elements.append(Spacer(1, 0.3 * inch))

    # General recommendations
    elements.append(
        Paragraph('General Security Best Practices', styles['body_bold']))
    elements.append(Spacer(1, 0.1 * inch))

    general = [
        'Keep all operating systems and software updated with security patches.',
        'Implement a firewall and restrict access to only required ports.',
        'Use strong, unique passwords and enable multi-factor authentication.',
        'Conduct regular security scans to detect new vulnerabilities.',
        'Monitor logs for suspicious activity and unauthorized access attempts.',
        'Follow the principle of least privilege — only expose what is necessary.',
    ]

    for item in general:
        elements.append(Paragraph(f'• {item}', styles['body']))

    return elements


# ── MAIN FUNCTION ─────────────────────────────────────────────────

def generate_pdf_report(scan, output_path=None):
    """
    Generate a full PDF security report for a scan.

    scan        : Scan database object (with .hosts and .ports loaded)
    output_path : where to save the PDF (defaults to /tmp/report_<id>.pdf)

    Returns the file path of the generated PDF.
    """
    if output_path is None:
        output_path = f'/tmp/report_scan_{scan.id}.pdf'

    # Create PDF document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=1 * inch,
        leftMargin=1 * inch,
        topMargin=1.2 * inch,
        bottomMargin=0.8 * inch,
    )

    styles = get_styles()
    elements = []

    # Build sections
    elements += build_cover_page(scan, styles)
    elements += build_executive_summary(scan, styles)
    elements += build_host_details(scan, styles)
    elements += build_recommendations(scan, styles)

    # Build PDF
    doc.build(elements, onFirstPage=make_page_template,
              onLaterPages=make_page_template)

    print(f"[+] PDF report generated: {output_path}")
    return output_path
