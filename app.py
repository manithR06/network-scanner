from scheduler import start_scheduler, stop_scheduler
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
from config import Config
from models import db, Scan, Host, Port
from datetime import datetime
import threading
import atexit

app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

with app.app_context():
    db.create_all()
    print("[+] Database ready")

# Start background scheduler
start_scheduler()
atexit.register(stop_scheduler)


# ── PAGE ROUTES ───────────────────────────────────────────────────

@app.route('/')
def index():
    recent_scans = Scan.query.order_by(Scan.started_at.desc()).limit(5).all()
    return render_template('index.html', recent_scans=recent_scans)


@app.route('/history')
def history():
    all_scans = Scan.query.order_by(Scan.started_at.desc()).all()
    return render_template('history.html', scans=all_scans)


@app.route('/results/<int:scan_id>')
def results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return render_template('results.html', scan=scan)


@app.route('/schedule')
def schedule_page():
    from scheduler import get_scheduled_scans
    scheduled = get_scheduled_scans()
    return render_template('schedule.html', scheduled=scheduled)


# ── PDF REPORT ROUTES ─────────────────────────────────────────────

@app.route('/report/<int:scan_id>')
def download_report(scan_id):
    """Download PDF report for a scan."""
    scan = Scan.query.get_or_404(scan_id)

    if scan.status != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400

    from reports import generate_pdf_report
    output_path = generate_pdf_report(scan)

    return send_file(
        output_path,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'security_report_{scan.target.replace("/", "_")}_{scan.id}.pdf'
    )


@app.route('/report/<int:scan_id>/view')
def view_report(scan_id):
    """View PDF report in browser."""
    scan = Scan.query.get_or_404(scan_id)

    if scan.status != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400

    from reports import generate_pdf_report
    output_path = generate_pdf_report(scan)

    return send_file(
        output_path,
        mimetype='application/pdf',
        as_attachment=False,
    )


# ── SCAN API ROUTES ───────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'basic')

    if not target:
        return jsonify({'error': 'Target IP or range is required'}), 400

    scan = Scan(target=target, scan_type=scan_type, status='pending')
    db.session.add(scan)
    db.session.commit()

    from scanner import run_scan
    thread = threading.Thread(
        target=run_scan, args=(scan.id, target, scan_type))
    thread.daemon = True
    thread.start()

    return jsonify({
        'message':  'Scan started',
        'scan_id':  scan.id,
        'redirect': url_for('results', scan_id=scan.id)
    })


@app.route('/api/scan/<int:scan_id>/status')
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({
        'status':      scan.status,
        'total_hosts': scan.total_hosts,
        'risk_score':  scan.risk_score,
    })


@app.route('/api/scan/<int:scan_id>/data')
def scan_data(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


@app.route('/api/scan/<int:scan_id>/delete', methods=['DELETE'])
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'message': 'Scan deleted'})


@app.route('/api/stats')
def stats():
    total_scans = Scan.query.count()
    total_hosts = Host.query.count()
    total_ports = Port.query.count()
    critical = Host.query.filter_by(risk_level='critical').count()
    high = Host.query.filter_by(risk_level='high').count()
    medium = Host.query.filter_by(risk_level='medium').count()
    low = Host.query.filter_by(risk_level='low').count()

    return jsonify({
        'total_scans':  total_scans,
        'total_hosts':  total_hosts,
        'total_ports':  total_ports,
        'risk_breakdown': {
            'critical': critical,
            'high':     high,
            'medium':   medium,
            'low':      low,
        }
    })


# ── CVE API ROUTES ────────────────────────────────────────────────

@app.route('/api/cve/<service_name>')
def cve_lookup(service_name):
    version = request.args.get('version', None)
    from cve_lookup import lookup_cves
    cves = lookup_cves(service_name, version)
    return jsonify({'service': service_name, 'cves': cves})


@app.route('/api/scan/<int:scan_id>/cves')
def scan_cves(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    from cve_lookup import get_cves_for_scan
    cves = get_cves_for_scan(scan)
    return jsonify({'scan_id': scan_id, 'vulnerabilities': cves})


# ── SCHEDULER API ROUTES ──────────────────────────────────────────

@app.route('/api/schedule', methods=['POST'])
def add_schedule():
    data = request.get_json()
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'basic')
    interval_hours = int(data.get('interval_hours', 24))

    if not target:
        return jsonify({'error': 'Target is required'}), 400

    from scheduler import add_scheduled_scan
    job_id = add_scheduled_scan(target, scan_type, interval_hours, app)
    return jsonify({'message': 'Scheduled scan added', 'job_id': job_id})


@app.route('/api/schedule/<job_id>/delete', methods=['DELETE'])
def delete_schedule(job_id):
    from scheduler import remove_scheduled_scan
    success = remove_scheduled_scan(job_id)
    if success:
        return jsonify({'message': 'Scheduled scan removed'})
    return jsonify({'error': 'Job not found'}), 404


@app.route('/api/schedule/list')
def list_schedules():
    from scheduler import get_scheduled_scans
    return jsonify({'scheduled': get_scheduled_scans()})


# ── RUN ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
