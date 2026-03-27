"""
NetGuard – Network Security Monitoring System
Flask Application  |  Phase 7: Email Notifications

Endpoints
─────────
GET  /                              Dashboard (HTML)
GET  /api/devices                   List devices  [?risk=high|medium|low] [?status=online|offline|new|known] [?search=]
GET  /api/devices/<mac>             Device detail
POST /api/devices/<mac>/approve     Mark device known
PUT  /api/devices/<mac>/name        Rename device
DELETE /api/devices/<mac>           Delete device
GET  /api/scan                      Trigger full network scan
GET  /api/scan/status               Scan state + scheduler info
GET  /api/scan/security/<mac>       Run nmap security scan on one device
GET  /api/scan/history              Recent scan history  [?limit=N]
GET  /api/stats                     Dashboard statistics
GET  /api/scheduler/status          Scheduler jobs + next run times
POST /api/scheduler/pause           Pause automatic scanning
POST /api/scheduler/resume          Resume automatic scanning
POST /api/email/test                Send a test email to verify SMTP config
"""

import logging
import re
import threading
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from config import Config
from scanner import NetworkScanner
from database import Database
from security_scanner import SecurityScanner
from email_notifier import EmailNotifier

# ============================================================================
# Logging
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)

# ============================================================================
# Application & module init
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY

network_scanner  = NetworkScanner(interface=Config.NETWORK_INTERFACE)
db               = Database(Config.DATABASE_PATH)
security_scanner = SecurityScanner(sudo=True)

email_notifier = EmailNotifier(db)

# ── Background scheduler (APScheduler) ───────────────────────────────────
scheduler = BackgroundScheduler(
    job_defaults={
        'coalesce':    True,   # merge missed runs into one
        'max_instances': 1,    # never run the same job twice at once
    },
    timezone='UTC',
)

# ── Scan lock: prevents concurrent network scans ──────────────────────────
_scan_lock        = threading.Lock()
_scan_running     = False
_last_scan_start  = None   # datetime of most-recent scan start
_scheduler_paused = False  # manual pause flag

# ============================================================================
# Helpers
# ============================================================================

MAC_RE = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')


def valid_mac(mac: str) -> bool:
    """Return True if *mac* matches xx:xx:xx:xx:xx:xx format."""
    return bool(MAC_RE.match(mac))


def ok(data=None, message: str = 'OK', **extra):
    """Build a successful JSON response."""
    body = {'success': True, 'message': message}
    if data is not None:
        body['data'] = data
    body.update(extra)
    return jsonify(body)


def err(message: str, status: int = 400, **extra):
    """Build an error JSON response."""
    body = {'success': False, 'message': message}
    body.update(extra)
    return jsonify(body), status


def _run_network_scan_workflow(triggered_by: str = 'manual') -> dict:
    """
    Core scan workflow.
    Acquires the scan lock internally so it is safe to call from
    both the API handler and the APScheduler background thread.

    Args:
        triggered_by: 'manual' | 'scheduler' | 'startup'

    Returns a summary dict (or raises on hard failure).
    """
    global _scan_running, _last_scan_start

    if not _scan_lock.acquire(blocking=False):
        logger.warning(f"Scan skipped ({triggered_by}) – another scan is in progress")
        return {}   # return empty dict so scheduler doesn't crash

    _scan_running    = True
    _last_scan_start = datetime.now()
    logger.info(f"🔍 Network scan started  [triggered_by={triggered_by}]")

    try:
        devices         = network_scanner.scan_network()
        new_count       = 0
        high_risk_count = 0

        # Mark all offline; upsert re-marks discovered ones as online.
        db.mark_all_offline()

        for device in devices:
            success, is_new = db.upsert_device(
                mac_address=device['mac'],
                ip_address=device['ip'],
                vendor=device.get('vendor'),
                hostname=device.get('hostname'),
            )

            if is_new:
                new_count += 1
                logger.info(f"  ↳ New device: {device['mac']} ({device['ip']}) – {device.get('vendor','?')}")

                if Config.SECURITY_SCAN_ENABLED:
                    try:
                        sec = security_scanner.scan_device(device['ip'])
                        db.update_security_scan(
                            mac_address=device['mac'],
                            risk_level=sec['risk_level'],
                            open_ports=sec['open_ports'],
                            vulnerabilities=security_scanner.get_vulnerabilities_summary(sec),
                        )
                        if sec['risk_level'] == 'high':
                            high_risk_count += 1
                        logger.info(
                            f"  ↳ Security scan {device['mac']}: "
                            f"{sec['risk_level'].upper()} (score {sec['risk_score']})"
                        )
                    except Exception as exc:
                        logger.error(f"  ↳ Security scan failed for {device['mac']}: {exc}")

                # Phase 7 – send email alerts for new / high-risk devices
                if email_notifier.is_enabled:
                    fresh = db.get_device(device['mac'])
                    if fresh:
                        if is_new:
                            email_notifier.notify_new_device(fresh)
                        elif fresh.get('risk_level', '').upper() == 'HIGH':
                            email_notifier.notify_high_risk(fresh)

        db.add_scan_history(
            devices_found=len(devices),
            new_devices=new_count,
            high_risk_devices=high_risk_count,
        )

        summary = {
            'devices_found': len(devices),
            'new_devices':   new_count,
            'high_risk':     high_risk_count,
            'triggered_by':  triggered_by,
            'timestamp':     _last_scan_start.isoformat(),
        }
        logger.info(
            f"✅ Scan complete [{triggered_by}] – "
            f"{len(devices)} found, {new_count} new, {high_risk_count} high-risk"
        )
        return summary

    except Exception as exc:
        logger.error(f"❌ Scan workflow error [{triggered_by}]: {exc}", exc_info=True)
        raise

    finally:
        _scan_running = False
        _scan_lock.release()


def _scheduled_scan_job():
    """Entry point called by APScheduler every SCAN_INTERVAL seconds."""
    if _scheduler_paused:
        logger.info("⏸  Scheduled scan skipped – scheduler is paused")
        return
    try:
        _run_network_scan_workflow(triggered_by='scheduler')
    except Exception as exc:
        # Must not raise – APScheduler would remove the job on repeated errors
        logger.error(f"Scheduled scan job error: {exc}", exc_info=True)


# ============================================================================
# Request / response hooks
# ============================================================================

@app.after_request
def add_cors_headers(response):
    """Add permissive CORS headers for local dev."""
    response.headers['Access-Control-Allow-Origin']  = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
    return response


@app.before_request
def log_request():
    """Lightweight request logging."""
    if not request.path.startswith('/static'):
        logger.debug(f"→ {request.method} {request.path}")


# ============================================================================
# HTML page
# ============================================================================

@app.route('/')
def index():
    """Serve the main dashboard."""
    return render_template('index.html')


# ============================================================================
# Device endpoints
# ============================================================================

@app.route('/api/devices', methods=['GET'])
def get_devices():
    """
    List all tracked devices.

    Query parameters
    ----------------
    risk    – filter by risk level   : high | medium | low
    status  – filter by device status: online | offline | new | known | unknown
    search  – case-insensitive search across ip, mac, vendor, friendly_name, hostname
    """
    try:
        devices = db.get_all_devices()

        # ── Filtering ─────────────────────────────────────────────────
        risk_filter   = request.args.get('risk',   '').strip().lower()
        status_filter = request.args.get('status', '').strip().lower()
        search_term   = request.args.get('search', '').strip().lower()

        if risk_filter in ('high', 'medium', 'low'):
            devices = [d for d in devices if d.get('risk_level') == risk_filter]

        if status_filter == 'online':
            devices = [d for d in devices if d.get('is_online')]
        elif status_filter == 'offline':
            devices = [d for d in devices if not d.get('is_online')]
        elif status_filter in ('new', 'known', 'unknown'):
            devices = [d for d in devices if d.get('status') == status_filter]

        if search_term:
            def matches(d):
                haystack = ' '.join(filter(None, [
                    d.get('ip_address', ''),
                    d.get('mac_address', ''),
                    d.get('vendor', ''),
                    d.get('friendly_name', ''),
                    d.get('hostname', ''),
                ])).lower()
                return search_term in haystack
            devices = [d for d in devices if matches(d)]

        logger.info(
            f"GET /api/devices → {len(devices)} result(s) "
            f"[risk={risk_filter or '*'} status={status_filter or '*'} search={search_term or '*'}]"
        )
        return jsonify(devices)

    except Exception as exc:
        logger.error(f"GET /api/devices error: {exc}", exc_info=True)
        return err(str(exc), 500)


@app.route('/api/devices/<mac>', methods=['GET'])
def get_device(mac):
    """Return full details for one device."""
    if not valid_mac(mac):
        return err('Invalid MAC address format', 422)

    try:
        device = db.get_device(mac)
        if not device:
            return err('Device not found', 404)
        return jsonify(device)

    except Exception as exc:
        logger.error(f"GET /api/devices/{mac} error: {exc}", exc_info=True)
        return err(str(exc), 500)


@app.route('/api/devices/<mac>/approve', methods=['POST'])
def approve_device(mac):
    """Mark a device as known/trusted."""
    if not valid_mac(mac):
        return err('Invalid MAC address format', 422)

    try:
        if not db.device_exists(mac):
            return err('Device not found', 404)

        db.mark_device_known(mac)
        logger.info(f"Device approved: {mac}")
        return ok(message='Device marked as known')

    except Exception as exc:
        logger.error(f"POST /approve error: {exc}", exc_info=True)
        return err(str(exc), 500)


@app.route('/api/devices/<mac>/name', methods=['PUT'])
def update_device_name(mac):
    """
    Rename a device.

    Request body (JSON): { "name": "My Router" }
    """
    if not valid_mac(mac):
        return err('Invalid MAC address format', 422)

    try:
        body = request.get_json(silent=True) or {}
        name = body.get('name', '').strip()

        if not name:
            return err('Field "name" is required', 422)
        if len(name) > 64:
            return err('Name must be 64 characters or fewer', 422)

        if not db.device_exists(mac):
            return err('Device not found', 404)

        db.set_device_name(mac, name)
        logger.info(f"Device renamed: {mac} → {name}")
        return ok(message='Device name updated', name=name)

    except Exception as exc:
        logger.error(f"PUT /name error: {exc}", exc_info=True)
        return err(str(exc), 500)


@app.route('/api/devices/<mac>', methods=['DELETE'])
def delete_device(mac):
    """Remove a device from tracking."""
    if not valid_mac(mac):
        return err('Invalid MAC address format', 422)

    try:
        if not db.device_exists(mac):
            return err('Device not found', 404)

        db.delete_device(mac)
        logger.info(f"Device deleted: {mac}")
        return ok(message='Device deleted')

    except Exception as exc:
        logger.error(f"DELETE /api/devices/{mac} error: {exc}", exc_info=True)
        return err(str(exc), 500)


# ============================================================================
# Scan endpoints
# ============================================================================

@app.route('/api/scan', methods=['GET'])
def trigger_scan():
    """
    Trigger a manual full network scan.
    Returns 409 if a scan is already in progress.
    """
    if _scan_running:
        return jsonify({
            'success':     False,
            'message':     'A scan is already in progress',
            'scan_running': True,
        }), 409

    try:
        logger.info("Manual network scan triggered via API")
        summary = _run_network_scan_workflow(triggered_by='manual')
        return jsonify({
            'success': True,
            'message': f"Scan complete: {summary['devices_found']} device(s) found",
            **summary,
        })

    except Exception as exc:
        logger.error(f"Scan error: {exc}", exc_info=True)
        return err(f'Scan failed: {str(exc)}', 500)


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Return scan state and scheduler details."""
    job  = scheduler.get_job('periodic_scan')
    next_run = None
    if job and job.next_run_time:
        next_run = job.next_run_time.isoformat()

    return jsonify({
        'scan_running':       _scan_running,
        'scheduler_running':  scheduler.running,
        'scheduler_paused':   _scheduler_paused,
        'scan_interval_sec':  Config.SCAN_INTERVAL,
        'next_scheduled_run': next_run,
        'last_scan_start':    _last_scan_start.isoformat() if _last_scan_start else None,
        'last_scan_db':       db.get_last_scan_time(),
    })


@app.route('/api/scheduler/status', methods=['GET'])
def scheduler_status():
    """List all scheduler jobs with their next run times."""
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id':           job.id,
            'name':         job.name,
            'next_run':     job.next_run_time.isoformat() if job.next_run_time else None,
            'trigger':      str(job.trigger),
        })
    return jsonify({
        'scheduler_running': scheduler.running,
        'scheduler_paused':  _scheduler_paused,
        'scan_interval_sec': Config.SCAN_INTERVAL,
        'jobs':              jobs,
    })


@app.route('/api/scheduler/pause', methods=['POST'])
def scheduler_pause():
    """Pause automatic periodic scanning (scheduler keeps running, jobs are skipped)."""
    global _scheduler_paused
    _scheduler_paused = True
    logger.info("⏸  Automatic scanning paused via API")
    return ok(message='Automatic scanning paused')


@app.route('/api/scheduler/resume', methods=['POST'])
def scheduler_resume():
    """Resume automatic periodic scanning."""
    global _scheduler_paused
    _scheduler_paused = False
    logger.info("▶️  Automatic scanning resumed via API")
    return ok(message='Automatic scanning resumed')


# ============================================================================
# EMAIL
# ============================================================================

@app.route('/api/email/test', methods=['POST'])
def email_test():
    """
    POST /api/email/test
    Send a test email to verify SMTP configuration.
    Returns 200 on success, 503 if email is disabled/misconfigured.
    """
    if not email_notifier.is_enabled:
        return err(
            'Email alerts are disabled. Configure SMTP_USERNAME, SMTP_PASSWORD and EMAIL_TO in .env',
            503,
        )

    sent = email_notifier.send_test_email()
    if sent:
        return ok(
            data={'recipient': Config.EMAIL_TO},
            message=f'Test email sent to {Config.EMAIL_TO}',
        )
    return err('Failed to send test email. Check server logs for SMTP errors.', 502)


@app.route('/api/scan/security/<mac>', methods=['GET'])
def trigger_security_scan(mac):
    """
    Run an nmap security scan on a specific device and persist results.
    """
    if not valid_mac(mac):
        return err('Invalid MAC address format', 422)

    try:
        device = db.get_device(mac)
        if not device:
            return err('Device not found', 404)

        ip = device.get('ip_address')
        if not ip:
            return err('Device has no IP address recorded', 400)

        logger.info(f"Security scan triggered: {mac} ({ip})")

        result     = security_scanner.scan_device(ip)
        vulns_text = security_scanner.get_vulnerabilities_summary(result)

        db.update_security_scan(
            mac_address=mac,
            risk_level=result['risk_level'],
            open_ports=result['open_ports'],
            vulnerabilities=vulns_text,
        )

        if result['risk_level'] == 'high':
            db.add_scan_history(devices_found=0, new_devices=0, high_risk_devices=1)

        logger.info(
            f"Security scan done: {mac} → {result['risk_level'].upper()} "
            f"(score {result['risk_score']}) ports={result['open_ports']}"
        )

        return jsonify({
            'success':         True,
            'mac':             mac,
            'ip':              ip,
            'risk_level':      result['risk_level'],
            'risk_score':      result['risk_score'],
            'open_ports':      result['open_ports'],
            'vulnerabilities': result['vulnerabilities'],
            'scanned_at':      result['scanned_at'],
        })

    except Exception as exc:
        logger.error(f"Security scan error for {mac}: {exc}", exc_info=True)
        return err(str(exc), 500)


@app.route('/api/scan/history', methods=['GET'])
def scan_history():
    """
    Return recent scan history.

    Query parameters
    ----------------
    limit – number of records to return (default 20, max 100)
    """
    try:
        try:
            limit = min(int(request.args.get('limit', 20)), 100)
        except ValueError:
            limit = 20

        history = db.get_scan_history(limit=limit)
        return jsonify(history)

    except Exception as exc:
        logger.error(f"GET /api/scan/history error: {exc}", exc_info=True)
        return err(str(exc), 500)


# ============================================================================
# Statistics endpoint
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return dashboard summary statistics."""
    try:
        stats = db.get_device_stats()

        # Augment with live scan status
        stats['scan_running'] = _scan_running

        return jsonify(stats)

    except Exception as exc:
        logger.error(f"GET /api/stats error: {exc}", exc_info=True)
        return err(str(exc), 500)


# ============================================================================
# Error handlers
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return err('Endpoint not found', 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return err('Method not allowed', 405)


@app.errorhandler(500)
def internal_error(e):
    return err('Internal server error', 500)


# ============================================================================
# Application startup
# ============================================================================

def initialize_app() -> bool:
    """
    Bootstrap all NetGuard components.

    Returns True on success, False on unrecoverable error.
    """
    global _scan_running

    logger.info("🚀 Initializing NetGuard...")

    # Config
    Config.display()
    if not Config.validate():
        logger.warning("⚠️  Configuration warnings detected")

    # Database
    logger.info("📊 Initializing database...")
    if not db.initialize():
        logger.error("❌ Database initialization failed – aborting")
        return False

    info = db.get_database_info()
    logger.info(
        f"✅ Database ready – "
        f"{info.get('device_count', 0)} device(s), "
        f"{info.get('scan_history_count', 0)} scan(s)"
    )

    # Network interface
    logger.info(f"📡 Validating interface: {Config.NETWORK_INTERFACE}")
    if network_scanner.validate_interface():
        logger.info(f"✅ Interface {Config.NETWORK_INTERFACE} OK")
    else:
        available = ', '.join(NetworkScanner.get_available_interfaces())
        logger.warning(
            f"⚠️  Interface {Config.NETWORK_INTERFACE} not found. "
            f"Available: {available}"
        )

    # Initial network scan
    logger.info("🔍 Performing initial network scan...")
    try:
        summary = _run_network_scan_workflow(triggered_by='startup')
        if summary:
            logger.info(
                f"✅ Initial scan done – "
                f"{summary['devices_found']} found, "
                f"{summary['new_devices']} new, "
                f"{summary['high_risk']} high-risk"
            )
    except Exception as exc:
        logger.error(f"⚠️  Initial scan failed: {exc}")

    # ── Background scheduler ─────────────────────────────────────────────
    logger.info(
        f"⏱  Starting background scheduler "
        f"(interval: {Config.SCAN_INTERVAL}s / "
        f"{Config.SCAN_INTERVAL // 60}m {Config.SCAN_INTERVAL % 60}s)"
    )
    scheduler.add_job(
        func=_scheduled_scan_job,
        trigger=IntervalTrigger(seconds=Config.SCAN_INTERVAL),
        id='periodic_scan',
        name='Periodic Network Scan',
        replace_existing=True,
    )
    scheduler.start()

    job = scheduler.get_job('periodic_scan')
    if job and job.next_run_time:
        logger.info(f"✅ Scheduler running – next scan at {job.next_run_time.strftime('%H:%M:%S UTC')}")
    else:
        logger.info("✅ Scheduler running")

    logger.info("✅ NetGuard ready")
    return True


# ============================================================================
# Entry point
# ============================================================================

if __name__ == '__main__':
    try:
        if not initialize_app():
            raise SystemExit("Initialization failed")

        logger.info(f"🌐 Dashboard → http://localhost:{Config.PORT}")

        app.run(
            host='0.0.0.0',
            port=Config.PORT,
            debug=Config.DEBUG,
            use_reloader=False,   # reloader conflicts with APScheduler
        )

    except KeyboardInterrupt:
        logger.info("\n👋 NetGuard shutting down...")
        if scheduler.running:
            scheduler.shutdown(wait=False)
            logger.info("Scheduler stopped")
    except Exception as exc:
        logger.error(f"❌ Fatal: {exc}", exc_info=True)
        if scheduler.running:
            scheduler.shutdown(wait=False)
