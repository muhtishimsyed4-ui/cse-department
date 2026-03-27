"""
Security Scanner Module for NetGuard
Performs vulnerability assessment on network devices using nmap.

Scans ports: 21 (FTP), 22 (SSH), 23 (Telnet), 80 (HTTP),
             139/445 (SMB), 3389 (RDP), 8080 (HTTP-Alt)

Risk scoring:
  HIGH   (score >= 40) - Telnet, default creds, SMBv1/EternalBlue
  MEDIUM (score >= 15) - FTP, HTTP, weak SSH
  LOW    (score <  15) - No significant vulnerabilities
"""

import subprocess
import re
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

# ============================================================================
# CONSTANTS
# ============================================================================

# Ports to scan
TARGET_PORTS = [21, 22, 23, 80, 139, 445, 3389, 8080]
TARGET_PORTS_STR = ','.join(map(str, TARGET_PORTS))

# Risk point thresholds
RISK_HIGH_THRESHOLD   = 40
RISK_MEDIUM_THRESHOLD = 15

# Risk point values per finding
RISK_POINTS = {
    'telnet_open':          40,   # Port 23 open        → HIGH instantly
    'smbv1_enabled':        50,   # EternalBlue target  → HIGH instantly
    'eternal_blue':         60,   # MS17-010 confirmed  → HIGH instantly
    'ftp_anonymous':        30,   # Anonymous FTP login → HIGH
    'ftp_open':             20,   # FTP present         → MEDIUM
    'rdp_open':             15,   # RDP exposed         → MEDIUM
    'http_open':            10,   # Unencrypted HTTP    → MEDIUM
    'ssh_open':              5,   # SSH (generally ok)  → LOW/INFO
    'smb_open':             10,   # SMB detected        → check further
    'http_alt_open':        10,   # Port 8080 HTTP      → MEDIUM
}

# NSE scripts to run per condition
NSE_SCRIPTS = {
    'ftp':  'ftp-anon,ftp-syst',
    'ssh':  'ssh-auth-methods',
    'smb':  'smb-protocols,smb-vuln-ms17-010',
}


# ============================================================================
# SECURITY SCANNER CLASS
# ============================================================================

class SecurityScanner:
    """Performs vulnerability assessment using nmap."""

    def __init__(self, sudo: bool = True, timeout: int = 120):
        """
        Initialize security scanner.

        Args:
            sudo:    Run nmap with sudo (required for SYN/OS scans)
            timeout: Max seconds to wait for nmap per scan
        """
        self.sudo    = sudo
        self.timeout = timeout
        logger.info("SecurityScanner initialized")

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def scan_device(self, ip_address: str) -> Dict:
        """
        Full security assessment for one device.

        Args:
            ip_address: Target IP to scan

        Returns:
            dict with keys:
              risk_level      (str)  – 'high' | 'medium' | 'low'
              risk_score      (int)  – numeric score
              open_ports      (list) – [21, 22, …]
              vulnerabilities (list) – human-readable finding strings
              scan_details    (dict) – per-port service/version info
              scanned_at      (str)  – ISO timestamp
        """
        logger.info(f"Starting security scan: {ip_address}")

        result = {
            'ip_address':    ip_address,
            'risk_level':    'low',
            'risk_score':    0,
            'open_ports':    [],
            'vulnerabilities': [],
            'scan_details':  {},
            'scanned_at':    datetime.now().isoformat(),
        }

        try:
            # 1. Port scan + service version detection
            nmap_out = self._run_port_scan(ip_address)
            if not nmap_out:
                logger.warning(f"Port scan returned no output for {ip_address}")
                result['vulnerabilities'].append("Scan failed or host unreachable")
                return result

            # 2. Parse open ports & services
            open_ports, service_info = self._parse_port_scan(nmap_out)
            result['open_ports']    = open_ports
            result['scan_details']  = service_info

            # 3. Run targeted NSE scripts based on what's open
            nse_findings = self._run_nse_scripts(ip_address, open_ports)

            # 4. Score & classify findings
            score, vulns = self._calculate_risk(open_ports, service_info, nse_findings)

            result['risk_score']     = score
            result['risk_level']     = self._score_to_level(score)
            result['vulnerabilities'] = vulns

            logger.info(
                f"Scan complete for {ip_address}: "
                f"risk={result['risk_level'].upper()} "
                f"score={score} ports={open_ports}"
            )

        except Exception as e:
            logger.error(f"Security scan error for {ip_address}: {e}", exc_info=True)
            result['vulnerabilities'].append(f"Scan error: {str(e)}")

        return result

    # ------------------------------------------------------------------
    # NMAP EXECUTION
    # ------------------------------------------------------------------

    def _run_port_scan(self, ip: str) -> Optional[str]:
        """
        Run nmap port + version scan on target ports.

        Returns raw stdout string or None on failure.
        """
        cmd = self._build_cmd([
            '-p', TARGET_PORTS_STR,
            '-sV',                  # Service/version detection
            '--version-intensity', '5',
            '-T4',                  # Aggressive timing (faster)
            '--open',               # Only show open ports
            '--script', 'banner',   # Grab banners for all open ports
            ip,
        ])

        logger.debug(f"Port scan cmd: {' '.join(cmd)}")
        return self._execute(cmd)

    def _run_nse_scripts(self, ip: str, open_ports: List[int]) -> Dict[str, str]:
        """
        Run targeted NSE scripts only for services that are actually open.

        Returns dict mapping script-name → raw output snippet.
        """
        findings = {}

        # FTP checks
        if 21 in open_ports:
            out = self._run_nmap_script(ip, '21', NSE_SCRIPTS['ftp'])
            if out:
                findings['ftp'] = out

        # SSH checks
        if 22 in open_ports:
            out = self._run_nmap_script(ip, '22', NSE_SCRIPTS['ssh'])
            if out:
                findings['ssh'] = out

        # SMB checks (run if either SMB port is open)
        if 139 in open_ports or 445 in open_ports:
            smb_port = '445' if 445 in open_ports else '139'
            out = self._run_nmap_script(ip, smb_port, NSE_SCRIPTS['smb'])
            if out:
                findings['smb'] = out

        return findings

    def _run_nmap_script(self, ip: str, port: str, scripts: str) -> Optional[str]:
        """Run specific NSE scripts against one port."""
        cmd = self._build_cmd([
            '-p', port,
            '--script', scripts,
            '-T4',
            ip,
        ])
        logger.debug(f"NSE cmd: {' '.join(cmd)}")
        return self._execute(cmd, timeout=60)

    def _build_cmd(self, args: List[str]) -> List[str]:
        """Prepend sudo if needed."""
        base = ['sudo', 'nmap'] if self.sudo else ['nmap']
        return base + args

    def _execute(self, cmd: List[str], timeout: int = None) -> Optional[str]:
        """
        Execute a subprocess command and return stdout.

        Returns None on error or timeout.
        """
        t = timeout or self.timeout
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                stdin=subprocess.DEVNULL,
                text=True,
                timeout=t,
            )
            if proc.returncode not in (0, 1):   # nmap returns 1 for some warnings
                logger.warning(f"nmap exited {proc.returncode}: {proc.stderr[:200]}")
            return proc.stdout or None

        except subprocess.TimeoutExpired:
            logger.error(f"nmap timed out after {t}s for cmd: {' '.join(cmd[:6])}")
            return None
        except FileNotFoundError:
            logger.error("nmap not found. Install with: sudo apt install nmap")
            return None
        except Exception as e:
            logger.error(f"nmap execution error: {e}", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # OUTPUT PARSING
    # ------------------------------------------------------------------

    def _parse_port_scan(self, nmap_output: str) -> Tuple[List[int], Dict]:
        """
        Parse nmap port-scan output into a list of open ports and
        a service-info dictionary.

        Example nmap line:
          22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu
          80/tcp  open  http    Apache httpd 2.4.52

        Returns:
            open_ports  – [22, 80, ...]
            service_info – {22: {'protocol':'tcp','service':'ssh','version':'OpenSSH 8.9p1'}, ...}
        """
        open_ports   = []
        service_info = {}

        # Pattern: PORT/PROTO STATE SERVICE  VERSION_STRING
        pattern = re.compile(
            r'^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$',
            re.MULTILINE,
        )

        for match in pattern.finditer(nmap_output):
            port     = int(match.group(1))
            proto    = match.group(2)
            service  = match.group(3)
            version  = match.group(4).strip() if match.group(4) else ''

            open_ports.append(port)
            service_info[port] = {
                'protocol': proto,
                'service':  service,
                'version':  version,
            }
            logger.debug(f"  Open: {port}/{proto} {service} {version}")

        return sorted(open_ports), service_info

    # ------------------------------------------------------------------
    # RISK SCORING
    # ------------------------------------------------------------------

    def _calculate_risk(
        self,
        open_ports:   List[int],
        service_info: Dict,
        nse_findings: Dict[str, str],
    ) -> Tuple[int, List[str]]:
        """
        Calculate risk score and build vulnerability list.

        Returns:
            (score, vulnerabilities_list)
        """
        score  = 0
        vulns  = []

        # ── Port 23 – Telnet ─────────────────────────────────────────
        if 23 in open_ports:
            score += RISK_POINTS['telnet_open']
            version = service_info.get(23, {}).get('version', '')
            vulns.append(
                f"⚠️  CRITICAL: Telnet service open (port 23) – "
                f"unencrypted protocol, trivially interceptable"
                + (f" [{version}]" if version else "")
            )

        # ── Port 21 – FTP ────────────────────────────────────────────
        if 21 in open_ports:
            version = service_info.get(21, {}).get('version', '')

            # Check anonymous login via NSE
            if nse_findings.get('ftp') and self._check_ftp_anonymous(nse_findings['ftp']):
                score += RISK_POINTS['ftp_anonymous']
                vulns.append(
                    f"⚠️  HIGH: FTP anonymous login allowed (port 21) – "
                    f"anyone can read/write files without credentials"
                    + (f" [{version}]" if version else "")
                )
            else:
                score += RISK_POINTS['ftp_open']
                vulns.append(
                    f"⚠️  MEDIUM: FTP service open (port 21) – "
                    f"unencrypted file transfer protocol"
                    + (f" [{version}]" if version else "")
                )

        # ── Ports 139/445 – SMB ──────────────────────────────────────
        if 139 in open_ports or 445 in open_ports:
            smb_out  = nse_findings.get('smb', '')
            smb_port = 445 if 445 in open_ports else 139

            # Check EternalBlue (MS17-010)
            if self._check_eternal_blue(smb_out):
                score += RISK_POINTS['eternal_blue']
                vulns.append(
                    f"🔴 CRITICAL: EternalBlue (MS17-010) vulnerability detected "
                    f"(port {smb_port}) – remote code execution possible"
                )
            # Check SMBv1
            elif self._check_smbv1(smb_out):
                score += RISK_POINTS['smbv1_enabled']
                vulns.append(
                    f"⚠️  CRITICAL: SMBv1 protocol enabled (port {smb_port}) – "
                    f"vulnerable to EternalBlue / WannaCry ransomware"
                )
            else:
                score += RISK_POINTS['smb_open']
                version = service_info.get(smb_port, {}).get('version', '')
                vulns.append(
                    f"ℹ️  INFO: SMB service detected (port {smb_port})"
                    + (f" [{version}]" if version else "")
                )

        # ── Port 3389 – RDP ──────────────────────────────────────────
        if 3389 in open_ports:
            score += RISK_POINTS['rdp_open']
            version = service_info.get(3389, {}).get('version', '')
            vulns.append(
                f"⚠️  MEDIUM: RDP service exposed (port 3389) – "
                f"remote desktop open to network, brute-force risk"
                + (f" [{version}]" if version else "")
            )

        # ── Port 80 – HTTP ───────────────────────────────────────────
        if 80 in open_ports:
            score += RISK_POINTS['http_open']
            version = service_info.get(80, {}).get('version', '')
            vulns.append(
                f"ℹ️  LOW: Unencrypted HTTP service (port 80)"
                + (f" [{version}]" if version else "")
            )

        # ── Port 8080 – HTTP-Alt ─────────────────────────────────────
        if 8080 in open_ports:
            score += RISK_POINTS['http_alt_open']
            version = service_info.get(8080, {}).get('version', '')
            vulns.append(
                f"ℹ️  LOW: HTTP service on alternate port 8080"
                + (f" [{version}]" if version else "")
            )

        # ── Port 22 – SSH (informational) ────────────────────────────
        if 22 in open_ports:
            score += RISK_POINTS['ssh_open']
            version = service_info.get(22, {}).get('version', '')
            # Check for very old/weak SSH versions
            if version and self._check_weak_ssh(version):
                score += 15
                vulns.append(
                    f"⚠️  MEDIUM: Outdated SSH version detected – "
                    f"upgrade recommended [{version}]"
                )
            else:
                vulns.append(
                    f"ℹ️  INFO: SSH service open (port 22)"
                    + (f" [{version}]" if version else "")
                )

        # ── No open vulnerable ports ─────────────────────────────────
        if not open_ports:
            vulns.append("✅ No open ports detected on scanned range")

        return score, vulns

    # ------------------------------------------------------------------
    # NSE OUTPUT CHECKERS
    # ------------------------------------------------------------------

    def _check_ftp_anonymous(self, ftp_output: str) -> bool:
        """Return True if ftp-anon script confirms anonymous login."""
        indicators = [
            'anonymous ftp login allowed',
            'ftp-anon: anonymous ftp login allowed',
            'anonymous access allowed',
        ]
        out_lower = ftp_output.lower()
        return any(ind in out_lower for ind in indicators)

    def _check_smbv1(self, smb_output: str) -> bool:
        """Return True if SMBv1 is listed as supported."""
        indicators = [
            'smb1',
            'nt lm 0.12',          # SMBv1 dialect string
            'smb-protocols:\n  dialects:\n    nt',
        ]
        out_lower = smb_output.lower()
        # Positive pattern: protocol listing includes v1 / NT LM
        if 'smb-protocols' in out_lower:
            # Look for "NT LM 0.12" or "SMBv1" in dialect list
            if re.search(r'nt\s+lm\s+0\.12', out_lower) or 'smb1' in out_lower:
                return True
        return any(ind in out_lower for ind in indicators)

    def _check_eternal_blue(self, smb_output: str) -> bool:
        """Return True if MS17-010 (EternalBlue) vulnerability is confirmed."""
        indicators = [
            'vulnerable',
            'ms17-010',
            'eternalblue',
        ]
        out_lower = smb_output.lower()
        # Only flag if the script explicitly says "VULNERABLE"
        if 'smb-vuln-ms17-010' in out_lower and 'vulnerable' in out_lower:
            return True
        return False

    def _check_weak_ssh(self, version_string: str) -> bool:
        """Return True if SSH version string indicates an outdated release."""
        version_lower = version_string.lower()
        # Flag OpenSSH versions older than 7.x
        match = re.search(r'openssh[_ ](\d+)\.', version_lower)
        if match:
            major = int(match.group(1))
            if major < 7:
                return True
        # Flag Dropbear < 2020
        match = re.search(r'dropbear[_ ](\d{4})', version_lower)
        if match:
            year = int(match.group(1))
            if year < 2020:
                return True
        return False

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_level(score: int) -> str:
        """Convert numeric risk score to level string."""
        if score >= RISK_HIGH_THRESHOLD:
            return 'high'
        elif score >= RISK_MEDIUM_THRESHOLD:
            return 'medium'
        return 'low'

    @staticmethod
    def check_nmap_installed() -> bool:
        """Return True if nmap binary is available."""
        try:
            r = subprocess.run(['which', 'nmap'], capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def get_vulnerabilities_summary(self, scan_result: Dict) -> str:
        """
        Convert scan result vulnerabilities list to a single text string
        suitable for database storage.
        """
        vulns = scan_result.get('vulnerabilities', [])
        if not vulns:
            return 'No vulnerabilities detected'
        return '\n'.join(vulns)


# ============================================================================
# STANDALONE TEST / DEMO
# ============================================================================

def main():
    """Interactive test of the security scanner."""
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
    )

    print("=" * 65)
    print("NetGuard Security Scanner – Test Mode")
    print("=" * 65)

    # Check nmap
    if not SecurityScanner.check_nmap_installed():
        print("❌  nmap not found. Install: sudo apt install nmap")
        sys.exit(1)
    print("✅  nmap detected\n")

    # Target IP (from CLI arg or default)
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    print(f"🎯  Target: {target}")
    print("⏳  Scanning (this may take 30–120 seconds)...\n")

    scanner = SecurityScanner()
    result  = scanner.scan_device(target)

    # ── Display Results ────────────────────────────────────────────────
    print("=" * 65)
    risk_icons = {'high': '🔴', 'medium': '🟡', 'low': '🟢'}
    print(f"RISK LEVEL : {risk_icons.get(result['risk_level'], '⚪')} "
          f"{result['risk_level'].upper()}  (score: {result['risk_score']})")
    print(f"OPEN PORTS : {result['open_ports'] or 'None'}")
    print(f"SCANNED AT : {result['scanned_at'][:19]}")
    print()

    if result['vulnerabilities']:
        print("FINDINGS:")
        for v in result['vulnerabilities']:
            print(f"  {v}")
    else:
        print("✅  No vulnerabilities found")

    if result['scan_details']:
        print("\nSERVICE DETAILS:")
        for port, info in result['scan_details'].items():
            svc     = info.get('service', '')
            version = info.get('version', '')
            print(f"  {port:5}/tcp  {svc:<12}  {version}")

    print("=" * 65)


if __name__ == '__main__':
    main()
