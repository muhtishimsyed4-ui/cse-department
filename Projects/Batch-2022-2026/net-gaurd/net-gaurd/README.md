# NetGuard — Network Security Monitor

A real-time network scanning and security monitoring dashboard built with Flask, arp-scan, and nmap.

## Features

- **Automatic network discovery** via arp-scan (every 5 minutes)
- **Security scanning** via nmap with NSE scripts (vuln, banner, version detection)
- **Risk scoring** — HIGH / MEDIUM / LOW / UNKNOWN per device
- **Email alerts** — new device detected + high-risk device notifications (SMTP/TLS)
- **Live dashboard** — Bootstrap 5 UI, auto-refreshes every 30s
- **Device management** — rename, approve, delete devices
- **Scan scheduler** — pause/resume background auto-scan
- **Scan history** — per-run log of devices found, new devices, high-risk count

---

## Requirements

- Python 3.8+
- `arp-scan` (`apt install arp-scan`)
- `nmap` (`apt install nmap`)
- Sudo passwordless access for both tools (see below)

---

## Installation

```bash
# 1. Clone / copy project
cd /home/kali/Desktop/net_gaurd

# 2. Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install flask apscheduler

# 4. Configure sudoers (REQUIRED — arp-scan and nmap need root)
sudo visudo -f /etc/sudoers.d/netguard
```

Add this single line (adjust username if not kali):
```
kali ALL=(ALL) NOPASSWD: /usr/sbin/arp-scan, /usr/bin/nmap
```

Verify arp-scan path — it may differ:
```bash
which arp-scan          # might be /usr/sbin/arp-scan or /usr/bin/arp-scan
```

---

## Configuration

Edit `config.py` to set your network interface and optional email settings:

```python
# Network
NETWORK_INTERFACE = "eth0"   # or wlan0, etc.
SCAN_INTERVAL     = 300      # seconds between auto-scans

# Email alerts (optional)
SEND_NEW_DEVICE_ALERTS = False
SEND_HIGH_RISK_ALERTS  = False
SMTP_SERVER   = "smtp.gmail.com"
SMTP_PORT     = 587
SMTP_USERNAME = ""
SMTP_PASSWORD = ""
EMAIL_FROM    = ""
EMAIL_TO      = ""
```

---

## Running

```bash
cd /home/kali/Desktop/net_gaurd
source venv/bin/activate

# Foreground (development)
python app.py

# Background (production — won't get suspended)
python app.py > /tmp/netguard.log 2>&1 & disown
```

Open **http://localhost:5000** in your browser.

---

## Stopping

```bash
pkill -9 -f "python app.py"
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices (`?risk=high`, `?status=online`, `?search=text`) |
| GET | `/api/devices/<mac>` | Get single device detail |
| POST | `/api/devices/<mac>/approve` | Mark device as known |
| PUT | `/api/devices/<mac>/name` | Rename device `{"name": "..."}` |
| DELETE | `/api/devices/<mac>` | Delete device |
| GET | `/api/scan` | Trigger manual scan |
| GET | `/api/scan/status` | Current scan state + scheduler info |
| GET | `/api/scan/security/<mac>` | Run nmap security scan on one device |
| GET | `/api/scan/history` | Recent scan history (`?limit=N`) |
| GET | `/api/stats` | Dashboard stats (counts, risk breakdown) |
| GET | `/api/scheduler/status` | Scheduler jobs + next run time |
| POST | `/api/scheduler/pause` | Pause auto-scan |
| POST | `/api/scheduler/resume` | Resume auto-scan |
| POST | `/api/email/test` | Send test email (verifies SMTP config) |

---

## Project Structure

```
net_gaurd/
├── app.py               # Flask application, all API endpoints
├── config.py            # Configuration constants
├── database.py          # SQLite database layer (24 methods)
├── scanner.py           # arp-scan network discovery
├── security_scanner.py  # nmap security + risk scoring
├── email_notifier.py    # SMTP email alerts
├── netguard.db          # SQLite database (auto-created)
├── templates/
│   └── index.html       # Bootstrap 5 dashboard
├── static/
│   ├── css/style.css    # Custom design system
│   └── js/app.js        # Full frontend interactivity
└── venv/                # Python virtual environment
```

---

## Troubleshooting

### App gets suspended in background
The most common cause is `sudo` trying to read a password from the terminal.
Fix: ensure the sudoers rule uses the **exact binary path**:
```bash
which arp-scan   # note the path
which nmap
sudo visudo -f /etc/sudoers.d/netguard
```

### arp-scan finds no devices
- Check `NETWORK_INTERFACE` in `config.py` matches your active interface (`ip link`)
- Confirm sudoers rule path is correct
- Test manually: `sudo /usr/sbin/arp-scan --interface=eth0 --localnet`

### nmap security scan hangs
- Ensure `nmap` path in sudoers is correct (`which nmap`)
- Test manually: `sudo /usr/bin/nmap -sV 192.168.x.x`

### Email alerts not sending
- Set `SEND_NEW_DEVICE_ALERTS = True` in `config.py`
- Fill in all SMTP fields (server, port, username, password, from, to)
- Test via API: `curl -X POST http://localhost:5000/api/email/test`

---

## Implementation Phases

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | Project structure, config, schema | ✅ Complete |
| 2 | arp-scan network discovery | ✅ Complete |
| 3 | SQLite database layer | ✅ Complete |
| 4 | nmap security scanner + risk scoring | ✅ Complete |
| 5 | Flask REST API (15 endpoints) | ✅ Complete |
| 6 | APScheduler background scanning | ✅ Complete |
| 7 | Email notifier (SMTP TLS) | ✅ Complete |
| 8 | Bootstrap 5 dashboard UI | ✅ Complete |
| 9 | JavaScript interactivity | ✅ Complete |
| 10 | Testing & documentation | ✅ Complete |
