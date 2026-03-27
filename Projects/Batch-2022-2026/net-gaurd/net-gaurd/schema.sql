-- NetGuard Database Schema
-- SQLite database for device tracking and security monitoring

-- Table: devices
-- Stores all discovered network devices with security information
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac_address TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    vendor TEXT,
    friendly_name TEXT,
    status TEXT DEFAULT 'unknown',       -- 'known', 'unknown', 'new'
    is_online BOOLEAN DEFAULT 1,
    risk_level TEXT DEFAULT 'low',       -- 'high', 'medium', 'low'
    open_ports TEXT,                     -- JSON array: "[21, 22, 80]"
    vulnerabilities TEXT,                -- Text description of vulnerabilities
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_security_scan DATETIME,
    notified BOOLEAN DEFAULT 0           -- Has email alert been sent?
);

-- Table: scan_history
-- Tracks history of network scans for analytics
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    devices_found INTEGER DEFAULT 0,
    new_devices INTEGER DEFAULT 0,
    high_risk_devices INTEGER DEFAULT 0
);

-- Table: settings
-- Application settings and preferences
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_level);
CREATE INDEX IF NOT EXISTS idx_devices_online ON devices(is_online);
CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(scan_time);
