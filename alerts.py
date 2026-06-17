import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


def send_alert(app, scan, high_risk_hosts):
    """
    Send an email alert when a scan finds high/critical risk hosts.

    app            : Flask app (needed for config)
    scan           : Scan database object
    high_risk_hosts: list of Host objects with risk_level high/critical
    """
    if not high_risk_hosts:
        return False

    mail_user = app.config.get('MAIL_USERNAME')
    mail_pass = app.config.get('MAIL_PASSWORD')
    alert_email = app.config.get('ALERT_EMAIL')

    if not all([mail_user, mail_pass, alert_email]):
        print("[!] Email not configured — skipping alert")
        return False

    # ── Build email subject ───────────────────────────
    critical_count = sum(
        1 for h in high_risk_hosts if h.risk_level == 'critical')
    high_count = sum(1 for h in high_risk_hosts if h.risk_level == 'high')

    subject = f"[NetScanner Alert] {critical_count} Critical, {high_count} High Risk Hosts — {scan.target}"

    # ── Build email body (HTML) ───────────────────────
    rows = ""
    for host in high_risk_hosts:
        color = "#dc3545" if host.risk_level == 'critical' else "#fd7e14"
        open_ports = ", ".join(str(p.port_number) for p in host.ports)
        rows += f"""
        <tr>
            <td style="padding:8px; border:1px solid #333;">{host.ip_address}</td>
            <td style="padding:8px; border:1px solid #333;">{host.hostname or '—'}</td>
            <td style="padding:8px; border:1px solid #333; color:{color}; font-weight:bold;">
                {host.risk_level.upper()}
            </td>
            <td style="padding:8px; border:1px solid #333;">{host.risk_score}</td>
            <td style="padding:8px; border:1px solid #333;">{open_ports}</td>
        </tr>
        """

    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background:#0d1117; color:#c9d1d9; padding:20px;">
        <div style="max-width:700px; margin:0 auto;">

            <h2 style="color:#dc3545;">
                ⚠️ Security Alert — NetScanner
            </h2>

            <p>A scan has detected <strong style="color:#dc3545;">{len(high_risk_hosts)} high/critical risk host(s)</strong>
            on your network.</p>

            <table style="width:100%; border-collapse:collapse; margin:20px 0;">
                <tr style="background:#161b22;">
                    <th style="padding:8px; border:1px solid #333; text-align:left;">IP Address</th>
                    <th style="padding:8px; border:1px solid #333; text-align:left;">Hostname</th>
                    <th style="padding:8px; border:1px solid #333; text-align:left;">Risk Level</th>
                    <th style="padding:8px; border:1px solid #333; text-align:left;">Score</th>
                    <th style="padding:8px; border:1px solid #333; text-align:left;">Open Ports</th>
                </tr>
                {rows}
            </table>

            <hr style="border-color:#30363d;">
            <p style="font-size:12px; color:#666;">
                Scan Target: {scan.target} |
                Scan Type: {scan.scan_type} |
                Completed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
            </p>
            <p style="font-size:11px; color:#444;">
                Sent by NetScanner — For authorized use only
            </p>
        </div>
    </body>
    </html>
    """

    # ── Send via Gmail SMTP ───────────────────────────
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = mail_user
        msg['To'] = alert_email
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(mail_user, mail_pass)
            server.sendmail(mail_user, alert_email, msg.as_string())

        print(f"[+] Alert email sent to {alert_email}")
        return True

    except Exception as e:
        print(f"[!] Failed to send alert email: {e}")
        return False
