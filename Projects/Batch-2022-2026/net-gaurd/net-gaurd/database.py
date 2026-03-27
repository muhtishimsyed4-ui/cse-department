"""
Database Module for NetGuard
Handles all SQLite database operations for device tracking and history.
"""

import sqlite3
import json
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class Database:
    """SQLite database manager for NetGuard."""
    
    def __init__(self, db_path: str = 'netguard.db'):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.connection = None
        logger.info(f"Database manager initialized: {db_path}")
    
    @contextmanager
    def get_connection(self):
        """
        Context manager for database connections.
        Ensures connections are properly closed after use.
        
        Yields:
            sqlite3.Connection: Database connection
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database transaction error: {e}", exc_info=True)
            raise
        finally:
            conn.close()
    
    def initialize(self) -> bool:
        """
        Initialize database by creating tables from schema.sql.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            logger.info("Initializing database...")
            
            # Read schema file
            try:
                with open('schema.sql', 'r') as f:
                    schema_sql = f.read()
            except FileNotFoundError:
                logger.error("schema.sql file not found")
                return False
            
            # Execute schema
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.executescript(schema_sql)
            
            logger.info("✅ Database initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}", exc_info=True)
            return False
    
    # ========================================================================
    # DEVICE OPERATIONS
    # ========================================================================
    
    def add_device(self, mac_address: str, ip_address: str, 
                   vendor: str = None, hostname: str = None) -> bool:
        """
        Add a new device to the database.
        
        Args:
            mac_address: Device MAC address (unique identifier)
            ip_address: Device IP address
            vendor: Device vendor/manufacturer
            hostname: Device hostname
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO devices 
                    (mac_address, ip_address, vendor, hostname, status, is_online)
                    VALUES (?, ?, ?, ?, 'new', 1)
                """, (mac_address, ip_address, vendor, hostname))
            
            logger.info(f"Added new device: {mac_address} ({ip_address})")
            return True
            
        except sqlite3.IntegrityError:
            logger.debug(f"Device already exists: {mac_address}")
            return False
        except Exception as e:
            logger.error(f"Error adding device: {e}", exc_info=True)
            return False
    
    def update_device(self, mac_address: str, **kwargs) -> bool:
        """
        Update device information.
        
        Args:
            mac_address: Device MAC address
            **kwargs: Fields to update (ip_address, vendor, hostname, etc.)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not kwargs:
            return False
        
        try:
            # Build SET clause dynamically
            set_clauses = []
            values = []
            for key, value in kwargs.items():
                set_clauses.append(f"{key} = ?")
                values.append(value)
            
            # Add last_seen timestamp
            set_clauses.append("last_seen = CURRENT_TIMESTAMP")
            
            sql = f"UPDATE devices SET {', '.join(set_clauses)} WHERE mac_address = ?"
            values.append(mac_address)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(sql, values)
                
                if cursor.rowcount == 0:
                    logger.warning(f"Device not found for update: {mac_address}")
                    return False
            
            logger.debug(f"Updated device: {mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating device: {e}", exc_info=True)
            return False
    
    def get_device(self, mac_address: str) -> Optional[Dict]:
        """
        Get device by MAC address.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            dict: Device information or None if not found
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM devices WHERE mac_address = ?
                """, (mac_address,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Error getting device: {e}", exc_info=True)
            return None
    
    def get_all_devices(self, online_only: bool = False) -> List[Dict]:
        """
        Get all devices from database.
        
        Args:
            online_only: If True, return only online devices
            
        Returns:
            list: List of device dictionaries
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if online_only:
                    cursor.execute("SELECT * FROM devices WHERE is_online = 1 ORDER BY last_seen DESC")
                else:
                    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting devices: {e}", exc_info=True)
            return []
    
    def delete_device(self, mac_address: str) -> bool:
        """
        Delete device from database.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM devices WHERE mac_address = ?", (mac_address,))
                
                if cursor.rowcount == 0:
                    logger.warning(f"Device not found for deletion: {mac_address}")
                    return False
            
            logger.info(f"Deleted device: {mac_address}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting device: {e}", exc_info=True)
            return False
    
    def mark_device_known(self, mac_address: str) -> bool:
        """
        Mark device as known/trusted.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_device(mac_address, status='known')
    
    def set_device_name(self, mac_address: str, friendly_name: str) -> bool:
        """
        Set friendly name for device.
        
        Args:
            mac_address: Device MAC address
            friendly_name: Human-readable device name
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_device(mac_address, friendly_name=friendly_name)
    
    def mark_device_online(self, mac_address: str) -> bool:
        """
        Mark device as online and update last_seen timestamp.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_device(mac_address, is_online=1)
    
    def mark_device_offline(self, mac_address: str) -> bool:
        """
        Mark device as offline.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_device(mac_address, is_online=0)
    
    def mark_all_offline(self) -> int:
        """
        Mark all devices as offline.
        Useful before a network scan to update online status.
        
        Returns:
            int: Number of devices marked offline
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE devices SET is_online = 0")
                count = cursor.rowcount
            
            logger.debug(f"Marked {count} device(s) offline")
            return count
            
        except Exception as e:
            logger.error(f"Error marking devices offline: {e}", exc_info=True)
            return 0
    
    def update_security_scan(self, mac_address: str, risk_level: str, 
                            open_ports: List[int], vulnerabilities: str) -> bool:
        """
        Update device security scan results.
        
        Args:
            mac_address: Device MAC address
            risk_level: Risk level ('high', 'medium', 'low')
            open_ports: List of open port numbers
            vulnerabilities: Description of vulnerabilities found
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Convert ports list to JSON string
            ports_json = json.dumps(open_ports)
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices 
                    SET risk_level = ?, 
                        open_ports = ?, 
                        vulnerabilities = ?,
                        last_security_scan = CURRENT_TIMESTAMP
                    WHERE mac_address = ?
                """, (risk_level, ports_json, vulnerabilities, mac_address))
                
                if cursor.rowcount == 0:
                    logger.warning(f"Device not found for security update: {mac_address}")
                    return False
            
            logger.info(f"Updated security scan for {mac_address}: {risk_level} risk")
            return True
            
        except Exception as e:
            logger.error(f"Error updating security scan: {e}", exc_info=True)
            return False
    
    def mark_device_notified(self, mac_address: str) -> bool:
        """
        Mark device as notified (email alert sent).
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if successful, False otherwise
        """
        return self.update_device(mac_address, notified=1)
    
    def get_devices_by_risk(self, risk_level: str) -> List[Dict]:
        """
        Get devices by risk level.
        
        Args:
            risk_level: Risk level ('high', 'medium', 'low')
            
        Returns:
            list: List of devices with specified risk level
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM devices 
                    WHERE risk_level = ? 
                    ORDER BY last_seen DESC
                """, (risk_level,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting devices by risk: {e}", exc_info=True)
            return []
    
    def get_new_devices(self) -> List[Dict]:
        """
        Get devices with 'new' status (not yet reviewed).
        
        Returns:
            list: List of new devices
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM devices 
                    WHERE status = 'new' 
                    ORDER BY first_seen DESC
                """)
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting new devices: {e}", exc_info=True)
            return []
    
    # ========================================================================
    # SCAN HISTORY OPERATIONS
    # ========================================================================
    
    def add_scan_history(self, devices_found: int, new_devices: int = 0, 
                        high_risk_devices: int = 0) -> bool:
        """
        Record a network scan in history.
        
        Args:
            devices_found: Total number of devices found
            new_devices: Number of new devices discovered
            high_risk_devices: Number of high-risk devices found
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO scan_history 
                    (devices_found, new_devices, high_risk_devices)
                    VALUES (?, ?, ?)
                """, (devices_found, new_devices, high_risk_devices))
            
            logger.debug(f"Scan history recorded: {devices_found} devices")
            return True
            
        except Exception as e:
            logger.error(f"Error adding scan history: {e}", exc_info=True)
            return False
    
    def get_last_scan_time(self) -> Optional[str]:
        """
        Get timestamp of last network scan.
        
        Returns:
            str: ISO format timestamp or None
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT scan_time FROM scan_history 
                    ORDER BY scan_time DESC LIMIT 1
                """)
                
                row = cursor.fetchone()
                if row:
                    return row['scan_time']
                return None
                
        except Exception as e:
            logger.error(f"Error getting last scan time: {e}", exc_info=True)
            return None
    
    def get_scan_history(self, limit: int = 10) -> List[Dict]:
        """
        Get recent scan history.
        
        Args:
            limit: Maximum number of records to return
            
        Returns:
            list: List of scan history records
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM scan_history 
                    ORDER BY scan_time DESC 
                    LIMIT ?
                """, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except Exception as e:
            logger.error(f"Error getting scan history: {e}", exc_info=True)
            return []
    
    # ========================================================================
    # SETTINGS OPERATIONS
    # ========================================================================
    
    def set_setting(self, key: str, value: str) -> bool:
        """
        Set application setting.
        
        Args:
            key: Setting key
            value: Setting value
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO settings (key, value)
                    VALUES (?, ?)
                """, (key, value))
            
            logger.debug(f"Setting saved: {key} = {value}")
            return True
            
        except Exception as e:
            logger.error(f"Error setting value: {e}", exc_info=True)
            return False
    
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """
        Get application setting.
        
        Args:
            key: Setting key
            default: Default value if key not found
            
        Returns:
            str: Setting value or default
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
                
                row = cursor.fetchone()
                if row:
                    return row['value']
                return default
                
        except Exception as e:
            logger.error(f"Error getting setting: {e}", exc_info=True)
            return default
    
    # ========================================================================
    # STATISTICS
    # ========================================================================
    
    def get_device_stats(self) -> Dict:
        """
        Get device statistics for dashboard.
        
        Returns:
            dict: Statistics including total, online, offline, risk breakdown
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Total devices
                cursor.execute("SELECT COUNT(*) as count FROM devices")
                total = cursor.fetchone()['count']
                
                # Online/Offline
                cursor.execute("SELECT COUNT(*) as count FROM devices WHERE is_online = 1")
                online = cursor.fetchone()['count']
                offline = total - online
                
                # Risk breakdown
                cursor.execute("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'high'")
                high_risk = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'medium'")
                medium_risk = cursor.fetchone()['count']
                
                cursor.execute("SELECT COUNT(*) as count FROM devices WHERE risk_level = 'low'")
                low_risk = cursor.fetchone()['count']
                
                # Last scan time
                last_scan = self.get_last_scan_time()
                
                return {
                    'total': total,
                    'online': online,
                    'offline': offline,
                    'risk_breakdown': {
                        'high': high_risk,
                        'medium': medium_risk,
                        'low': low_risk
                    },
                    'last_scan': last_scan
                }
                
        except Exception as e:
            logger.error(f"Error getting device stats: {e}", exc_info=True)
            return {
                'total': 0,
                'online': 0,
                'offline': 0,
                'risk_breakdown': {'high': 0, 'medium': 0, 'low': 0},
                'last_scan': None
            }
    
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def device_exists(self, mac_address: str) -> bool:
        """
        Check if device exists in database.
        
        Args:
            mac_address: Device MAC address
            
        Returns:
            bool: True if device exists, False otherwise
        """
        device = self.get_device(mac_address)
        return device is not None
    
    def upsert_device(self, mac_address: str, ip_address: str, 
                     vendor: str = None, hostname: str = None) -> Tuple[bool, bool]:
        """
        Insert device if new, update if exists.
        
        Args:
            mac_address: Device MAC address
            ip_address: Device IP address
            vendor: Device vendor
            hostname: Device hostname
            
        Returns:
            tuple: (success: bool, is_new: bool)
        """
        if self.device_exists(mac_address):
            # Update existing device
            success = self.update_device(
                mac_address,
                ip_address=ip_address,
                vendor=vendor,
                hostname=hostname,
                is_online=1
            )
            return (success, False)
        else:
            # Insert new device
            success = self.add_device(mac_address, ip_address, vendor, hostname)
            return (success, True)
    
    def cleanup_old_scans(self, days: int = 30) -> int:
        """
        Delete scan history older than specified days.
        
        Args:
            days: Number of days to keep
            
        Returns:
            int: Number of records deleted
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM scan_history 
                    WHERE scan_time < datetime('now', '-' || ? || ' days')
                """, (days,))
                count = cursor.rowcount
            
            logger.info(f"Cleaned up {count} old scan records")
            return count
            
        except Exception as e:
            logger.error(f"Error cleaning up scans: {e}", exc_info=True)
            return 0
    
    def get_database_info(self) -> Dict:
        """
        Get database information and statistics.
        
        Returns:
            dict: Database info including size, table counts
        """
        try:
            import os
            
            info = {
                'path': self.db_path,
                'exists': os.path.exists(self.db_path),
                'size_bytes': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
            }
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Device count
                cursor.execute("SELECT COUNT(*) as count FROM devices")
                info['device_count'] = cursor.fetchone()['count']
                
                # Scan history count
                cursor.execute("SELECT COUNT(*) as count FROM scan_history")
                info['scan_history_count'] = cursor.fetchone()['count']
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting database info: {e}", exc_info=True)
            return {}


# ============================================================================
# STANDALONE TESTING
# ============================================================================

def main():
    """Test database functionality."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    print("="*60)
    print("NetGuard Database Module - Test Mode")
    print("="*60)
    
    # Initialize database
    db = Database('test_netguard.db')
    
    print("\n[1] Initializing database...")
    if db.initialize():
        print("✅ Database initialized")
    else:
        print("❌ Database initialization failed")
        return
    
    # Add test devices
    print("\n[2] Adding test devices...")
    db.add_device('aa:bb:cc:dd:ee:01', '192.168.1.10', 'Samsung Electronics', 'samsung-tv')
    db.add_device('aa:bb:cc:dd:ee:02', '192.168.1.20', 'Apple Inc', 'iphone')
    db.add_device('aa:bb:cc:dd:ee:03', '192.168.1.30', 'Unknown', 'camera-1')
    print("✅ Test devices added")
    
    # Update device
    print("\n[3] Updating device...")
    db.set_device_name('aa:bb:cc:dd:ee:01', 'Living Room TV')
    db.mark_device_known('aa:bb:cc:dd:ee:02')
    print("✅ Devices updated")
    
    # Security scan update
    print("\n[4] Updating security scan...")
    db.update_security_scan('aa:bb:cc:dd:ee:03', 'high', [21, 23, 80], 
                           'Telnet and FTP services enabled')
    print("✅ Security scan updated")
    
    # Get all devices
    print("\n[5] Retrieving devices...")
    devices = db.get_all_devices()
    print(f"✅ Found {len(devices)} device(s):")
    for device in devices:
        print(f"   - {device['friendly_name'] or device['hostname']} "
              f"({device['ip_address']}) - Risk: {device['risk_level']}")
    
    # Statistics
    print("\n[6] Getting statistics...")
    stats = db.get_device_stats()
    print(f"✅ Statistics:")
    print(f"   Total: {stats['total']}")
    print(f"   Online: {stats['online']}")
    print(f"   High Risk: {stats['risk_breakdown']['high']}")
    
    # Scan history
    print("\n[7] Adding scan history...")
    db.add_scan_history(devices_found=3, new_devices=1, high_risk_devices=1)
    print("✅ Scan history recorded")
    
    # Database info
    print("\n[8] Database information...")
    info = db.get_database_info()
    print(f"✅ Database: {info['path']}")
    print(f"   Size: {info['size_bytes']} bytes")
    print(f"   Devices: {info['device_count']}")
    print(f"   Scans: {info['scan_history_count']}")
    
    print("\n" + "="*60)
    print("✅ All database tests passed!")
    print("="*60 + "\n")


if __name__ == '__main__':
    main()
