"""
Test script for network scanner functionality.
Run this to verify the scanner module works correctly.
"""

from scanner import NetworkScanner
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_scanner():
    """Test basic scanner functionality."""
    print("\n" + "="*60)
    print("Testing NetworkScanner Module")
    print("="*60)
    
    # Test 1: Get available interfaces
    print("\n[Test 1] Getting available network interfaces...")
    interfaces = NetworkScanner.get_available_interfaces()
    print(f"✅ Found {len(interfaces)} interface(s): {', '.join(interfaces)}")
    
    if not interfaces:
        print("❌ No network interfaces found!")
        return False
    
    # Test 2: Initialize scanner
    print(f"\n[Test 2] Initializing scanner with interface: {interfaces[0]}")
    scanner = NetworkScanner(interface=interfaces[0])
    print("✅ Scanner initialized")
    
    # Test 3: Validate interface
    print(f"\n[Test 3] Validating interface...")
    if scanner.validate_interface():
        print("✅ Interface is valid")
    else:
        print("❌ Interface validation failed")
        return False
    
    # Test 4: Run network scan
    print(f"\n[Test 4] Running network scan...")
    print("⏳ This may take 10-30 seconds...")
    devices = scanner.scan_network()
    print(f"✅ Scan complete: {len(devices)} device(s) found")
    
    # Test 5: Display results
    if devices:
        print(f"\n[Test 5] Device details:")
        for idx, device in enumerate(devices[:5], 1):  # Show max 5 devices
            print(f"\n  Device {idx}:")
            print(f"    IP:     {device['ip']}")
            print(f"    MAC:    {device['mac']}")
            print(f"    Vendor: {device['vendor']}")
        
        if len(devices) > 5:
            print(f"\n  ... and {len(devices) - 5} more device(s)")
    
    print("\n" + "="*60)
    print("✅ All tests passed!")
    print("="*60 + "\n")
    
    return True

if __name__ == '__main__':
    test_scanner()
