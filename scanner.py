import nmap
import json
from datetime import datetime
from models import db, Scan, Host, Port

# -------------------------------------------------------------------
# RISK SCORING
# Ports considered dangerous and why
# -------------------------------------------------------------------
RISKY_PORTS = {
    21:   ('high',     'FTP — unencrypted file transfer'),
    22:   ('medium',   'SSH — brute force target'),
    23:   ('critical', 'Telnet — completely unencrypted'),
    25:   ('high',     'SMTP — mail relay abuse'),
    53:   ('medium',   'DNS — amplification attacks'),
    80:   ('low',      'HTTP — unencrypted web'),
    110:  ('medium',   'POP3 — unencrypted email'),
    135:  ('high',     'RPC — Windows vulnerability'),
    139:  ('high',     'NetBIOS — SMB attacks'),
    143:  ('medium',   'IMAP — unencrypted email'),
    443:  ('low',      'HTTPS — encrypted web'),
    445:  ('critical', 'SMB — ransomware target (EternalBlue)'),
    1433: ('critical', 'MSSQL — database exposed'),
    1521: ('critical', 'Oracle DB — database exposed'),
    3306: ('critical', 'MySQL — database exposed'),
    3389: ('critical', 'RDP — remote desktop, brute force target'),
    5432: ('critical', 'PostgreSQL — database exposed'),
    5900: ('high',     'VNC — remote desktop unencrypted'),
    6379: ('critical', 'Redis — often no auth required'),
    8080: ('low',      'HTTP Alternate — web proxy'),
    8443: ('low',      'HTTPS Alternate'),
    27017: ('critical', 'MongoDB — often no auth required'),
}

RISK_SCORE_MAP = {
    'low':      1,
    'medium':   3,
    'high':     7,
    'critical': 10,
}


def score_port(port_number):
    """Return (risk_level, description) for a port number."""
    if port_number in RISKY_PORTS:
        return RISKY_PORTS[port_number]
    return ('low', 'Unknown service')


def calculate_host_risk(ports):
    """Calculate overall risk score for a host based on its open ports."""
    if not ports:
        return 0.0, 'low'

    total = sum(RISK_SCORE_MAP.get(score_port(p)[0], 1) for p in ports)
    avg = total / len(ports)

    if avg >= 8:
        return round(avg, 1), 'critical'
    elif avg >= 5:
        return round(avg, 1), 'high'
    elif avg >= 2:
        return round(avg, 1), 'medium'
    else:
        return round(avg, 1), 'low'


# -------------------------------------------------------------------
# SCAN TYPES
# -------------------------------------------------------------------
SCAN_PROFILES = {
    'basic': {
        'args': '-sV -T4 --open',
        'description': 'Quick scan — open ports and service versions'
    },
    'full': {
        'args': '-sV -sC -O -T4 --open',
        'description': 'Full scan — services, scripts, OS detection'
    },
    'stealth': {
        'args': '-sS -sV -T2 --open',
        'description': 'Stealth SYN scan — slower, less detectable'
    },
    'ping': {
        'args': '-sn',
        'description': 'Ping sweep — find live hosts only, no port scan'
    },
}


# -------------------------------------------------------------------
# MAIN SCAN FUNCTION
# -------------------------------------------------------------------
def run_scan(scan_id, target, scan_type='basic'):
    """
    Run an Nmap scan and save results to the database.

    scan_id   : the database ID of the Scan record
    target    : IP, range, or CIDR (e.g. '192.168.1.1' or '192.168.1.0/24')
    scan_type : one of the keys in SCAN_PROFILES
    """
    from app import app  # import here to avoid circular imports

    with app.app_context():
        # 1. Mark scan as running
        scan = Scan.query.get(scan_id)
        scan.status = 'running'
        db.session.commit()

        try:
            # 2. Set up Nmap
            nm = nmap.PortScanner()
            args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES['basic'])['args']

            print(f"[*] Starting {scan_type} scan on {target}")
            print(f"[*] Nmap args: {args}")

            # 3. Run the scan (this is the slow part — could take minutes)
            nm.scan(hosts=target, arguments=args)

            # 4. Process results
            host_count = 0
            total_risk = 0.0

            for ip in nm.all_hosts():
                host_data = nm[ip]

                # Skip hosts that are down
                if host_data.state() != 'up':
                    continue

                # Get hostname
                hostnames = host_data.hostnames()
                hostname = hostnames[0]['name'] if hostnames else None

                # Get OS info (only available in full scan)
                os_name = None
                os_accuracy = None
                if 'osmatch' in host_data and host_data['osmatch']:
                    best_match = host_data['osmatch'][0]
                    os_name = best_match.get('name')
                    os_accuracy = int(best_match.get('accuracy', 0))

                # Create Host record
                host = Host(
                    scan_id=scan_id,
                    ip_address=ip,
                    hostname=hostname,
                    os_name=os_name,
                    os_accuracy=os_accuracy,
                    status='up',
                )
                db.session.add(host)
                db.session.flush()  # get host.id without full commit

                # 5. Process open ports
                open_port_numbers = []

                for proto in host_data.all_protocols():
                    ports = host_data[proto].keys()

                    for port_num in ports:
                        port_info = host_data[proto][port_num]

                        if port_info['state'] != 'open':
                            continue

                        risk_level, _ = score_port(port_num)

                        port = Port(
                            host_id=host.id,
                            port_number=port_num,
                            protocol=proto,
                            state=port_info['state'],
                            service_name=port_info.get('name', ''),
                            service_version=f"{port_info.get('product', '')} {port_info.get('version', '')}".strip(
                            ),
                            risk_level=risk_level,
                        )
                        db.session.add(port)
                        open_port_numbers.append(port_num)

                # 6. Calculate host risk
                risk_score, risk_level = calculate_host_risk(open_port_numbers)
                host.risk_score = risk_score
                host.risk_level = risk_level

                host_count += 1
                total_risk += risk_score

            # 7. Update scan summary
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.total_hosts = host_count
            scan.risk_score = round(
                total_risk / host_count, 1) if host_count > 0 else 0.0
            db.session.commit()

            print(f"[+] Scan complete. Found {host_count} hosts.")

            # Send alert if high/critical hosts found
            try:
                from alerts import send_alert
                high_risk = [h for h in scan.hosts if h.risk_level in (
                    'critical', 'high')]
                if high_risk:
                    send_alert(app, scan, high_risk)
            except Exception as e:
                print(f"[!] Alert error (non-fatal): {e}")

            return True

        except Exception as e:
            # If anything goes wrong, mark scan as failed
            scan.status = 'failed'
            db.session.commit()
            print(f"[!] Scan failed: {str(e)}")
            return False


def get_scan_summary(scan_id):
    """Return a plain dict summary of a completed scan."""
    scan = Scan.query.get(scan_id)
    if not scan:
        return None
    return scan.to_dict()
