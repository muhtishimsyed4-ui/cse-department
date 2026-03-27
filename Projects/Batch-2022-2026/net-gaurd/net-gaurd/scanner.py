"""
Network Scanner Module
Discovers devices on the local network using arp-scan.
"""

import subprocess
import re
import logging
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class NetworkScanner:
    """Network device discovery using arp-scan."""
    
    def __init__(self, interface: str = 'eth0'):
        """
        Initialize network scanner.
        
        Args:
            interface: Network interface to scan (e.g., eth0, wlan0)
        """
        self.interface = interface
        logger.info(f"NetworkScanner initialized for interface: {interface}")
    
    def scan_network(self) -> List[Dict[str, str]]:
        """
        Scan local network for all connected devices using arp-scan.
        
        Returns:
            List of devices with mac, ip, vendor information
            Example: [{'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.168.1.10', 'vendor': 'Samsung'}]
        """
        logger.info(f"Starting network scan on interface {self.interface}...")
        
        try:
            # Check if arp-scan is available
            if not self._check_arp_scan_installed():
                logger.error("arp-scan is not installed")
                return []
            
            # Run arp-scan command
            devices = self._run_arp_scan()
            
            logger.info(f"Network scan complete. Found {len(devices)} device(s)")
            return devices
            
        except Exception as e:
            logger.error(f"Error during network scan: {e}", exc_info=True)
            return []
    
    def _check_arp_scan_installed(self) -> bool:
        """
        Check if arp-scan is installed on the system.
        
        Returns:
            True if arp-scan is available, False otherwise
        """
        try:
            result = subprocess.run(
                ['which', 'arp-scan'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Error checking arp-scan installation: {e}")
            return False
    
    def _run_arp_scan(self) -> List[Dict[str, str]]:
        """
        Execute arp-scan command and parse output.
        
        Returns:
            List of discovered devices
        """
        # Build arp-scan command
        # --interface: specify network interface
        # --localnet: scan local network
        # --retry: number of packet retries (default 1, we use 2 for better detection)
        # --timeout: timeout in milliseconds (500ms)
        cmd = [
            'sudo', 'arp-scan',
            '--interface', self.interface,
            '--localnet',
            '--retry', '2',
            '--timeout', '500'
        ]
        
        try:
            # Run arp-scan with timeout
            # stdin=DEVNULL prevents sudo from prompting for a password on the tty
            result = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"arp-scan failed with exit code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                return []
            
            # Parse the output
            devices = self._parse_arp_scan_output(result.stdout)
            return devices
            
        except subprocess.TimeoutExpired:
            logger.error("arp-scan command timed out after 30 seconds")
            return []
        except FileNotFoundError:
            logger.error("arp-scan command not found. Is it installed?")
            return []
        except Exception as e:
            logger.error(f"Error running arp-scan: {e}", exc_info=True)
            return []
    
    def _parse_arp_scan_output(self, output: str) -> List[Dict[str, str]]:
        """
        Parse arp-scan output to extract device information.
        
        Example arp-scan output:
        192.168.1.1     00:11:22:33:44:55       TP-LINK TECHNOLOGIES CO.,LTD.
        192.168.1.10    aa:bb:cc:dd:ee:ff       Samsung Electronics Co.,Ltd
        
        Args:
            output: Raw arp-scan output
            
        Returns:
            List of parsed devices
        """
        devices = []
        
        # Split output into lines
        lines = output.strip().split('\n')
        
        for line in lines:
            # Skip empty lines and headers
            if not line.strip() or line.startswith('Interface:') or line.startswith('Starting'):
                continue
            
            # Regex pattern to match: IP MAC VENDOR
            # IP: \d+\.\d+\.\d+\.\d+
            # MAC: [0-9a-fA-F:]{17}
            # Vendor: everything else (optional)
            pattern = r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s*(.*)$'
            match = re.match(pattern, line)
            
            if match:
                ip_address = match.group(1)
                mac_address = match.group(2).lower()  # Normalize to lowercase
                vendor = match.group(3).strip() if match.group(3) else 'Unknown'
                
                # Clean vendor name (remove extra info in parentheses)
                vendor = self._clean_vendor_name(vendor)
                
                device = {
                    'ip': ip_address,
                    'mac': mac_address,
                    'vendor': vendor,
                    'hostname': None,  # Will be resolved separately if needed
                    'discovered_at': datetime.now().isoformat()
                }
                
                devices.append(device)
                logger.debug(f"Discovered device: {ip_address} ({mac_address}) - {vendor}")
        
        return devices
    
    def _clean_vendor_name(self, vendor: str) -> str:
        """
        Clean vendor name by removing extra information.
        
        Args:
            vendor: Raw vendor name from arp-scan
            
        Returns:
            Cleaned vendor name
        """
        if not vendor or vendor.strip() == '':
            return 'Unknown'
        
        # Remove text in parentheses
        vendor = re.sub(r'\s*\([^)]*\)', '', vendor)
        
        # Truncate very long vendor names
        if len(vendor) > 50:
            vendor = vendor[:47] + '...'
        
        return vendor.strip()
    
    def get_hostname(self, ip_address: str) -> Optional[str]:
        """
        Attempt to resolve hostname from IP address.
        
        Args:
            ip_address: IP address to resolve
            
        Returns:
            Hostname if resolved, None otherwise
        """
        try:
            # Use host command to resolve hostname
            result = subprocess.run(
                ['host', ip_address],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                # Parse output: "10.0.0.1.in-addr.arpa domain name pointer hostname.local."
                match = re.search(r'pointer\s+(.+?)\.?$', result.stdout)
                if match:
                    hostname = match.group(1)
                    logger.debug(f"Resolved {ip_address} to {hostname}")
                    return hostname
            
            return None
            
        except Exception as e:
            logger.debug(f"Could not resolve hostname for {ip_address}: {e}")
            return None
    
    def scan_with_hostnames(self) -> List[Dict[str, str]]:
        """
        Scan network and attempt to resolve hostnames for all devices.
        Note: This is slower due to DNS lookups.
        
        Returns:
            List of devices with hostname information
        """
        devices = self.scan_network()
        
        # Attempt to resolve hostnames
        for device in devices:
            if device['ip']:
                hostname = self.get_hostname(device['ip'])
                if hostname:
                    device['hostname'] = hostname
        
        return devices
    
    def validate_interface(self) -> bool:
        """
        Check if the specified network interface exists.
        
        Returns:
            True if interface exists, False otherwise
        """
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', self.interface],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                logger.info(f"Network interface {self.interface} is valid")
                return True
            else:
                logger.warning(f"Network interface {self.interface} not found")
                return False
                
        except Exception as e:
            logger.error(f"Error validating interface: {e}")
            return False
    
    @staticmethod
    def get_available_interfaces() -> List[str]:
        """
        Get list of available network interfaces on the system.
        
        Returns:
            List of interface names
        """
        try:
            result = subprocess.run(
                ['ip', '-o', 'link', 'show'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            interfaces = []
            for line in result.stdout.split('\n'):
                # Parse: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                match = re.match(r'^\d+:\s+([^:@]+)', line)
                if match:
                    interface = match.group(1).strip()
                    # Skip loopback
                    if interface != 'lo':
                        interfaces.append(interface)
            
            logger.info(f"Available interfaces: {', '.join(interfaces)}")
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return []


def main():
    """Test the network scanner."""
    # Configure logging for standalone testing
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("=" * 60)
    print("NetGuard Network Scanner - Test Mode")
    print("=" * 60)
    
    # Get available interfaces
    print("\n📡 Available Network Interfaces:")
    interfaces = NetworkScanner.get_available_interfaces()
    for idx, iface in enumerate(interfaces, 1):
        print(f"  {idx}. {iface}")
    
    # Use first available interface or default to eth0
    interface = interfaces[0] if interfaces else 'eth0'
    print(f"\n🔍 Using interface: {interface}")
    
    # Create scanner
    scanner = NetworkScanner(interface=interface)
    
    # Validate interface
    if not scanner.validate_interface():
        print(f"\n❌ Error: Interface {interface} is not valid")
        print("\nAvailable interfaces:")
        for iface in interfaces:
            print(f"  - {iface}")
        return
    
    # Run scan
    print(f"\n🚀 Scanning network on {interface}...")
    print("⏳ This may take 10-30 seconds...\n")
    
    devices = scanner.scan_network()
    
    # Display results
    print("\n" + "=" * 60)
    print(f"SCAN RESULTS: {len(devices)} device(s) found")
    print("=" * 60)
    
    if devices:
        for idx, device in enumerate(devices, 1):
            print(f"\n📱 Device #{idx}")
            print(f"   IP Address:  {device['ip']}")
            print(f"   MAC Address: {device['mac']}")
            print(f"   Vendor:      {device['vendor']}")
            if device.get('hostname'):
                print(f"   Hostname:    {device['hostname']}")
    else:
        print("\n⚠️  No devices found. This could mean:")
        print("   - No other devices on the network")
        print("   - Incorrect network interface selected")
        print("   - Permission issues (try running with sudo)")
        print("   - arp-scan not installed (run: sudo apt install arp-scan)")
    
    print("\n" + "=" * 60)


if __name__ == '__main__':
    main()
