"""
Email Notifier Module for NetGuard
Sends alerts via SMTP for new devices and high-risk findings.

Anti-spam:
  - Checks device['notified'] flag before sending
  - Calls db.mark_device_notified(mac) immediately after a successful send
  - Never re-alerts for the same device unless it goes offline and reconnects as 'new'

Config used:
  SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
  EMAIL_FROM, EMAIL_TO
  EMAIL_ALERTS_ENABLED
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Optional

from config import Config

logger = logging.getLogger(__name__)


class EmailNotifier:
    """
    Sends email alerts for NetGuard security events.

    Usage:
        notifier = EmailNotifier(db)
        notifier.notify_new_device(device_dict)
        notifier.notify_high_risk(device_dict)
    """

    def __init__(self, db=None):
        """
        Initialise the notifier.

        Args:
            db: DatabaseManager instance (optional — pass to enable anti-spam marking)
        """
        self.db = db
        self.enabled = (
            (Config.SEND_NEW_DEVICE_ALERTS or Config.SEND_HIGH_RISK_ALERTS)
            and bool(Config.SMTP_USERNAME)
            and bool(Config.SMTP_PASSWORD)
            and bool(Config.EMAIL_TO)
        )

        if self.enabled:
            logger.info(
                f"EmailNotifier ready — SMTP {Config.SMTP_SERVER}:{Config.SMTP_PORT} "
                f"→ {Config.EMAIL_TO}"
            )
        else:
            logger.info("EmailNotifier disabled (SMTP credentials not configured)")

    # -----------------------------------------------------------------------
    # PUBLIC API
    # -----------------------------------------------------------------------

    def notify_new_device(self, device: dict) -> bool:
        """
        Send a 'New Device Detected' alert if not already notified.

        Args:
            device: Device dict from database (must include 'mac', 'notified')

        Returns:
            True if email was sent, False otherwise
        """
        if not self.enabled:
            return False
        if not Config.SEND_NEW_DEVICE_ALERTS:
            return False
        if device.get('notified'):
            logger.debug(f"Skipping new-device alert for {device.get('mac_address')} — already notified")
            return False

        subject = f"🆕 New Device Detected: {device.get('vendor', 'Unknown Vendor')}"
        body = self._build_new_device_body(device)
        sent = self._send(subject, body)

        if sent:
            self._mark_notified(device.get('mac_address'))

        return sent

    def notify_high_risk(self, device: dict) -> bool:
        """
        Send a 'HIGH RISK Device' alert if not already notified.

        Args:
            device: Device dict from database (must include 'mac', 'notified', 'risk_level')

        Returns:
            True if email was sent, False otherwise
        """
        if not self.enabled:
            return False
        if not Config.SEND_HIGH_RISK_ALERTS:
            return False

        if device.get('risk_level', '').upper() != 'HIGH':
            return False

        if device.get('notified'):
            logger.debug(f"Skipping high-risk alert for {device.get('mac_address')} — already notified")
            return False

        subject = f"🚨 HIGH RISK Device Detected! — {device.get('ip_address', 'Unknown IP')}"
        body = self._build_high_risk_body(device)
        sent = self._send(subject, body)

        if sent:
            self._mark_notified(device.get('mac_address'))

        return sent

    def send_test_email(self) -> bool:
        """
        Send a test email to verify SMTP configuration.

        Returns:
            True on success, False on failure
        """
        subject = "✅ NetGuard Email Test"
        body = self._build_test_body()
        return self._send(subject, body)

    # -----------------------------------------------------------------------
    # EMAIL BODY BUILDERS
    # -----------------------------------------------------------------------

    def _build_new_device_body(self, device: dict) -> str:
        """Build HTML body for new device alert."""
        mac     = device.get('mac_address', 'Unknown')
        ip      = device.get('ip_address', 'Unknown')
        vendor  = device.get('vendor', 'Unknown')
        host    = device.get('hostname', 'N/A')
        seen_at = device.get('first_seen', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        risk    = device.get('risk_level', 'UNKNOWN').upper()
        risk_color = _risk_color(risk)

        return f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">

  <div style="background: #2563eb; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
    <h1 style="margin: 0; font-size: 24px;">🆕 New Device Detected</h1>
    <p style="margin: 5px 0 0; opacity: 0.9;">NetGuard Network Monitor</p>
  </div>

  <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-top: none; padding: 20px; border-radius: 0 0 8px 8px;">

    <table style="width: 100%; border-collapse: collapse;">
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;
                   font-weight: bold; width: 140px; color: #64748b;">MAC Address</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;
                   font-family: monospace;">{mac}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #f8fafc; border-bottom: 1px solid #e2e8f0;
                   font-weight: bold; color: #64748b;">IP Address</td>
        <td style="padding: 8px 12px; background: #f8fafc; border-bottom: 1px solid #e2e8f0;">{ip}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;
                   font-weight: bold; color: #64748b;">Vendor</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;">{vendor}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #f8fafc; border-bottom: 1px solid #e2e8f0;
                   font-weight: bold; color: #64748b;">Hostname</td>
        <td style="padding: 8px 12px; background: #f8fafc; border-bottom: 1px solid #e2e8f0;">{host}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;
                   font-weight: bold; color: #64748b;">First Seen</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #e2e8f0;">{seen_at}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #f8fafc; font-weight: bold; color: #64748b;">Risk Level</td>
        <td style="padding: 8px 12px; background: #f8fafc;">
          <span style="background: {risk_color}; color: white; padding: 2px 10px;
                       border-radius: 12px; font-size: 12px; font-weight: bold;">{risk}</span>
        </td>
      </tr>
    </table>

    <div style="margin-top: 20px; padding: 12px; background: #eff6ff; border-radius: 6px;
                border-left: 4px solid #2563eb;">
      <strong>Action Required:</strong> Review this device in the
      <a href="http://localhost:5000" style="color: #2563eb;">NetGuard Dashboard</a>
      and approve it if it is a known device.
    </div>

    <p style="margin-top: 20px; color: #94a3b8; font-size: 12px;">
      Sent by NetGuard · {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>

  </div>
</body>
</html>
"""

    def _build_high_risk_body(self, device: dict) -> str:
        """Build HTML body for high-risk device alert."""
        mac   = device.get('mac_address', 'Unknown')
        ip    = device.get('ip_address', 'Unknown')
        vendor = device.get('vendor', 'Unknown')
        host  = device.get('hostname', 'N/A')
        score = device.get('risk_score', 0)
        vulns = device.get('vulnerabilities', 'No details available')
        ports = device.get('open_ports', '')
        risk  = device.get('risk_level', 'HIGH').upper()
        risk_color = _risk_color(risk)

        # Format vulnerabilities as bullet list
        if isinstance(vulns, str) and vulns:
            vuln_lines = [v.strip() for v in vulns.split('\n') if v.strip()]
            vuln_html = ''.join(f'<li style="margin: 4px 0;">{v}</li>' for v in vuln_lines)
        else:
            vuln_html = '<li>No specific vulnerabilities recorded</li>'

        return f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">

  <div style="background: #dc2626; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
    <h1 style="margin: 0; font-size: 24px;">🚨 HIGH RISK Device Detected!</h1>
    <p style="margin: 5px 0 0; opacity: 0.9;">NetGuard Security Alert</p>
  </div>

  <div style="background: #fef2f2; border: 1px solid #fecaca; border-top: none; padding: 20px; border-radius: 0 0 8px 8px;">

    <div style="background: #dc2626; color: white; padding: 12px 16px; border-radius: 6px;
                margin-bottom: 20px; font-weight: bold;">
      ⚠️  Risk Score: {score} — Immediate attention recommended
    </div>

    <table style="width: 100%; border-collapse: collapse;">
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;
                   font-weight: bold; width: 140px; color: #64748b;">MAC Address</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;
                   font-family: monospace;">{mac}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fef2f2; border-bottom: 1px solid #fecaca;
                   font-weight: bold; color: #64748b;">IP Address</td>
        <td style="padding: 8px 12px; background: #fef2f2; border-bottom: 1px solid #fecaca;">{ip}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;
                   font-weight: bold; color: #64748b;">Vendor</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;">{vendor}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fef2f2; border-bottom: 1px solid #fecaca;
                   font-weight: bold; color: #64748b;">Hostname</td>
        <td style="padding: 8px 12px; background: #fef2f2; border-bottom: 1px solid #fecaca;">{host}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;
                   font-weight: bold; color: #64748b;">Open Ports</td>
        <td style="padding: 8px 12px; background: #fff; border-bottom: 1px solid #fecaca;
                   font-family: monospace;">{ports or 'None detected'}</td>
      </tr>
      <tr>
        <td style="padding: 8px 12px; background: #fef2f2; font-weight: bold; color: #64748b;">Risk Level</td>
        <td style="padding: 8px 12px; background: #fef2f2;">
          <span style="background: {risk_color}; color: white; padding: 2px 10px;
                       border-radius: 12px; font-size: 12px; font-weight: bold;">{risk}</span>
        </td>
      </tr>
    </table>

    <div style="margin-top: 20px;">
      <strong style="color: #dc2626;">Vulnerabilities Found:</strong>
      <ul style="margin: 8px 0; padding-left: 20px; color: #374151;">
        {vuln_html}
      </ul>
    </div>

    <div style="margin-top: 20px; padding: 12px; background: #fff; border-radius: 6px;
                border-left: 4px solid #dc2626;">
      <strong>Action Required:</strong> Investigate this device immediately using the
      <a href="http://localhost:5000" style="color: #dc2626;">NetGuard Dashboard</a>.
      Consider isolating it from the network until it can be verified.
    </div>

    <p style="margin-top: 20px; color: #94a3b8; font-size: 12px;">
      Sent by NetGuard · {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>

  </div>
</body>
</html>
"""

    def _build_test_body(self) -> str:
        """Build HTML body for the test email."""
        return f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background: #16a34a; color: white; padding: 20px; border-radius: 8px 8px 0 0;">
    <h1 style="margin: 0; font-size: 24px;">✅ NetGuard Email Test</h1>
  </div>
  <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-top: none; padding: 20px; border-radius: 0 0 8px 8px;">
    <p>Your SMTP configuration is working correctly.</p>
    <table style="width: 100%; border-collapse: collapse; margin-top: 12px;">
      <tr>
        <td style="padding: 6px 10px; font-weight: bold; color: #64748b; width: 140px;">SMTP Server</td>
        <td style="padding: 6px 10px; font-family: monospace;">{Config.SMTP_SERVER}:{Config.SMTP_PORT}</td>
      </tr>
      <tr>
        <td style="padding: 6px 10px; font-weight: bold; color: #64748b;">From</td>
        <td style="padding: 6px 10px;">{Config.EMAIL_FROM}</td>
      </tr>
      <tr>
        <td style="padding: 6px 10px; font-weight: bold; color: #64748b;">To</td>
        <td style="padding: 6px 10px;">{Config.EMAIL_TO}</td>
      </tr>
    </table>
    <p style="margin-top: 20px; color: #94a3b8; font-size: 12px;">
      Sent by NetGuard · {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>
  </div>
</body>
</html>
"""

    # -----------------------------------------------------------------------
    # SMTP SEND
    # -----------------------------------------------------------------------

    def _send(self, subject: str, html_body: str) -> bool:
        """
        Send an HTML email via SMTP with TLS.

        Args:
            subject:   Email subject line
            html_body: Full HTML body string

        Returns:
            True on success, False on any error
        """
        if not self.enabled:
            logger.debug(f"Email suppressed (disabled): {subject}")
            return False

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = Config.EMAIL_FROM or Config.SMTP_USERNAME
        msg['To']      = Config.EMAIL_TO

        # Attach HTML part
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        try:
            with smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(Config.SMTP_USERNAME, Config.SMTP_PASSWORD)
                server.sendmail(
                    msg['From'],
                    [Config.EMAIL_TO],
                    msg.as_string(),
                )

            logger.info(f"✉️  Email sent: {subject} → {Config.EMAIL_TO}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed — check SMTP_USERNAME / SMTP_PASSWORD in .env")
            return False
        except smtplib.SMTPConnectError:
            logger.error(f"Cannot connect to SMTP server {Config.SMTP_SERVER}:{Config.SMTP_PORT}")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error sending '{subject}': {e}")
            return False
        except OSError as e:
            logger.error(f"Network error sending email: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email: {e}", exc_info=True)
            return False

    # -----------------------------------------------------------------------
    # HELPERS
    # -----------------------------------------------------------------------

    def _mark_notified(self, mac: Optional[str]) -> None:
        """Mark a device as notified in the database (anti-spam)."""
        if mac and self.db:
            try:
                self.db.mark_device_notified(mac)
                logger.debug(f"Marked device {mac} as notified")
            except Exception as e:
                logger.warning(f"Could not mark device {mac} as notified: {e}")

    @property
    def is_enabled(self) -> bool:
        """True if SMTP is fully configured and email alerts are active."""
        return self.enabled


# ---------------------------------------------------------------------------
# MODULE-LEVEL HELPERS
# ---------------------------------------------------------------------------

def _risk_color(risk_level: str) -> str:
    """Return a CSS hex color for a given risk level string."""
    return {
        'HIGH':    '#dc2626',
        'MEDIUM':  '#f59e0b',
        'LOW':     '#16a34a',
        'UNKNOWN': '#6b7280',
    }.get(risk_level.upper(), '#6b7280')
