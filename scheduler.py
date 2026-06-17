from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime

scheduler = BackgroundScheduler()

# Store scheduled scan targets in memory
# In production you'd store these in the database
scheduled_targets = []


def run_scheduled_scan(target, scan_type, app):
    """Run a scan on a schedule — called automatically by APScheduler."""
    print(f"[*] Scheduled scan starting: {target} at {datetime.utcnow()}")

    with app.app_context():
        from models import db, Scan
        from scanner import run_scan

        # Create scan record
        scan = Scan(
            target=target,
            scan_type=scan_type,
            status='pending'
        )
        db.session.add(scan)
        db.session.commit()

        # Run the scan
        run_scan(scan.id, target, scan_type)

        # Send alert if needed
        scan = Scan.query.get(scan.id)
        if scan and scan.hosts:
            from alerts import send_alert
            high_risk = [h for h in scan.hosts if h.risk_level in (
                'critical', 'high')]
            if high_risk:
                send_alert(app, scan, high_risk)

    print(f"[+] Scheduled scan complete: {target}")


def add_scheduled_scan(target, scan_type='basic', interval_hours=24, app=None):
    """
    Add a new scheduled scan.

    target         : IP or range to scan
    scan_type      : basic / full / ping / stealth
    interval_hours : how often to scan (default every 24 hours)
    app            : Flask app instance
    """
    job_id = f"scan_{target.replace('/', '_').replace('.', '_')}"

    # Remove existing job for same target if any
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    scheduler.add_job(
        func=run_scheduled_scan,
        trigger=IntervalTrigger(hours=interval_hours),
        id=job_id,
        args=[target, scan_type, app],
        name=f"Scheduled scan: {target}",
        replace_existing=True
    )

    scheduled_targets.append({
        'job_id':         job_id,
        'target':         target,
        'scan_type':      scan_type,
        'interval_hours': interval_hours,
    })

    print(f"[+] Scheduled scan added: {target} every {interval_hours}h")
    return job_id


def remove_scheduled_scan(job_id):
    """Remove a scheduled scan by job ID."""
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
        global scheduled_targets
        scheduled_targets = [
            t for t in scheduled_targets if t['job_id'] != job_id]
        return True
    return False


def get_scheduled_scans():
    """Return list of all scheduled scans."""
    return scheduled_targets


def start_scheduler():
    """Start the background scheduler."""
    if not scheduler.running:
        scheduler.start()
        print("[+] Scheduler started")


def stop_scheduler():
    """Stop the scheduler cleanly."""
    if scheduler.running:
        scheduler.shutdown()
        print("[+] Scheduler stopped")
