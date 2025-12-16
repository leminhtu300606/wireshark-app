# -*- coding: utf-8 -*-
"""
Security Analyzer for intrusion detection.
Detects ARP spoofing, DoS/DDoS, Port scans and other network threats.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Callable
import threading


class ThreatSeverity(Enum):
    """Threat severity levels."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ThreatType(Enum):
    """Types of security threats."""
    ARP_SPOOFING = "ARP Spoofing"
    ARP_FLOOD = "ARP Flood"
    SYN_FLOOD = "SYN Flood"
    UDP_FLOOD = "UDP Flood"
    ICMP_FLOOD = "ICMP Flood"
    PORT_SCAN = "Port Scan"
    XMAS_SCAN = "XMAS Scan"
    NULL_SCAN = "NULL Scan"
    FIN_SCAN = "FIN Scan"
    DNS_AMPLIFICATION = "DNS Amplification"
    BRUTE_FORCE = "Brute Force"
    PACKET_FLOOD_ATTACK = "Packet Flood Attack"


@dataclass
class SecurityAlert:
    """Security alert data."""
    id: int
    timestamp: datetime
    threat_type: ThreatType
    severity: ThreatSeverity
    source_ip: str
    target_ip: Optional[str]
    description: str
    details: Dict = field(default_factory=dict)
    packet_count: int = 1


class SecurityAnalyzer:
    """
    Analyzes network traffic for security threats.
    Detects ARP spoofing, DoS attacks, port scans, etc.
    """
    
    def __init__(self):
        self._lock = threading.Lock()
        self._enabled = True
        self._alerts: List[SecurityAlert] = []
        self._alert_id = 0
        self._alert_callbacks: List[Callable[[SecurityAlert], None]] = []
        
        # ARP Spoofing Detection
        self._ip_mac_mapping: Dict[str, set] = defaultdict(set)  # IP -> set of MACs
        self._mac_ip_mapping: Dict[str, set] = defaultdict(set)  # MAC -> set of IPs
        self._trusted_mappings: Dict[str, str] = {}  # IP -> trusted MAC
        
        # DoS Detection - tracking packets per source
        self._packet_counts = defaultdict(lambda: {'syn': 0, 'udp': 0, 'icmp': 0, 'arp': 0, 'last_reset': datetime.now()})
        self._connection_attempts = defaultdict(set)  # src_ip -> set of (dst_ip, dst_port)
        
        # Port Scan Detection
        self._port_access = defaultdict(lambda: defaultdict(set))  # src_ip -> dst_ip -> set of ports
        self._port_scan_window = timedelta(seconds=10)
        self._last_port_reset = datetime.now()
        
        # Brute Force Detection - track connection attempts to auth services
        self._auth_attempts = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'last_reset': datetime.now()}))
        # Auth ports: SSH(22), FTP(21), Telnet(23), SMTP(25), POP3(110), IMAP(143)
        self._auth_ports = {21, 22, 23, 25, 110, 143, 3389, 5900}
        
        # Detection thresholds (configurable)
        self.thresholds = {
            'syn_flood_per_sec': 100,      # SYN packets per second
            'udp_flood_per_sec': 200,       # UDP packets per second
            'icmp_flood_per_sec': 50,       # ICMP packets per second
            'arp_flood_per_sec': 30,        # ARP packets per second
            'port_scan_ports': 20,          # Unique ports in window
            'port_scan_window': 10,         # Window in seconds
            'rate_window': 1,               # Rate calculation window in seconds
            'brute_force_attempts': 10,     # Auth attempts before alert
            'brute_force_window': 60,       # Window in seconds
        }
        
        self._last_rate_check = datetime.now()
    
    def set_enabled(self, enabled: bool):
        """Enable or disable security analysis."""
        self._enabled = enabled
    
    def is_enabled(self) -> bool:
        """Check if security analysis is enabled."""
        return self._enabled
    
    def add_alert_callback(self, callback: Callable[[SecurityAlert], None]):
        """Add callback for new alerts."""
        self._alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[SecurityAlert], None]):
        """Remove alert callback."""
        if callback in self._alert_callbacks:
            self._alert_callbacks.remove(callback)
    
    def analyze_packet(self, packet) -> Optional[SecurityAlert]:
        """
        Analyze a packet for security threats.
        
        Args:
            packet: Scapy packet
            
        Returns:
            SecurityAlert if threat detected, None otherwise
        """
        if not self._enabled:
            return None
        
        try:
            from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
            
            alert = None
            
            # Check for ARP-based attacks
            if ARP in packet:
                alert = self._analyze_arp(packet)
            
            # Check for DoS attacks
            if IP in packet or IPv6 in packet:
                dos_alert = self._analyze_dos(packet)
                if dos_alert:
                    alert = dos_alert
                
                # Check for port scans
                if TCP in packet:
                    scan_alert = self._analyze_port_scan(packet)
                    if scan_alert:
                        alert = scan_alert
                    
                    # Check for brute-force attempts on auth services
                    brute_alert = self._analyze_brute_force(packet)
                    if brute_alert:
                        alert = brute_alert
            
            return alert
            
        except Exception as e:
            print(f"Security analysis error: {e}")
            return None
    
    def _analyze_arp(self, packet) -> Optional[SecurityAlert]:
        """Analyze ARP packet for spoofing attacks."""
        from scapy.all import ARP
        
        arp = packet[ARP]
        src_mac = arp.hwsrc
        src_ip = arp.psrc
        
        # Track ARP flood
        with self._lock:
            self._packet_counts[src_ip]['arp'] += 1
            
            # Check for ARP flood
            rate = self._get_rate(src_ip, 'arp')
            if rate > self.thresholds['arp_flood_per_sec']:
                return self._create_alert(
                    ThreatType.ARP_FLOOD,
                    ThreatSeverity.MEDIUM,
                    src_ip, None,
                    f"ARP flood detected: {rate:.0f} ARP/sec from {src_ip}",
                    {'mac': src_mac, 'rate': rate}
                )
        
        # ARP Spoofing detection - check IP-MAC consistency
        with self._lock:
            # Track IP -> MAC mapping
            if src_ip not in self._ip_mac_mapping:
                self._ip_mac_mapping[src_ip].add(src_mac)
                self._mac_ip_mapping[src_mac].add(src_ip)
            else:
                if src_mac not in self._ip_mac_mapping[src_ip]:
                    # Different MAC for same IP - possible spoofing!
                    existing_macs = self._ip_mac_mapping[src_ip]
                    self._ip_mac_mapping[src_ip].add(src_mac)
                    
                    return self._create_alert(
                        ThreatType.ARP_SPOOFING,
                        ThreatSeverity.CRITICAL,
                        src_ip, None,
                        f"ARP Spoofing detected! IP {src_ip} has multiple MACs: {existing_macs} and {src_mac}",
                        {'existing_macs': list(existing_macs), 'new_mac': src_mac}
                    )
            
            # Check if MAC is claiming multiple IPs (also suspicious)
            if len(self._mac_ip_mapping[src_mac]) > 3:  # Allow some (routers, etc.)
                ips = self._mac_ip_mapping[src_mac]
                if len(ips) > 5:  # Definitely suspicious
                    return self._create_alert(
                        ThreatType.ARP_SPOOFING,
                        ThreatSeverity.HIGH,
                        src_ip, None,
                        f"Suspicious: MAC {src_mac} claims {len(ips)} IPs",
                        {'mac': src_mac, 'claimed_ips': list(ips)[:10]}
                    )
        
        return None
    
    def _analyze_dos(self, packet) -> Optional[SecurityAlert]:
        """Analyze packet for DoS/DDoS attacks."""
        from scapy.all import IP, IPv6, TCP, UDP, ICMP
        
        # Get source IP
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None
        
        with self._lock:
            now = datetime.now()
            
            # Reset counters periodically
            if (now - self._last_rate_check).total_seconds() > self.thresholds['rate_window']:
                self._reset_rate_counters()
                self._last_rate_check = now
            
            # SYN Flood detection
            if TCP in packet:
                tcp = packet[TCP]
                flags = tcp.flags
                
                # Check for SYN without ACK (potential SYN flood)
                if flags & 0x02 and not (flags & 0x10):  # SYN set, ACK not set
                    self._packet_counts[src_ip]['syn'] += 1
                    rate = self._get_rate(src_ip, 'syn')
                    
                    if rate > self.thresholds['syn_flood_per_sec']:
                        return self._create_alert(
                            ThreatType.SYN_FLOOD,
                            ThreatSeverity.CRITICAL,
                            src_ip, dst_ip,
                            f"SYN Flood detected: {rate:.0f} SYN/sec from {src_ip}",
                            {'rate': rate, 'target': dst_ip}
                        )
            
            # UDP Flood detection
            elif UDP in packet:
                self._packet_counts[src_ip]['udp'] += 1
                rate = self._get_rate(src_ip, 'udp')
                
                if rate > self.thresholds['udp_flood_per_sec']:
                    return self._create_alert(
                        ThreatType.UDP_FLOOD,
                        ThreatSeverity.HIGH,
                        src_ip, dst_ip,
                        f"UDP Flood detected: {rate:.0f} UDP/sec from {src_ip}",
                        {'rate': rate, 'target': dst_ip}
                    )
            
            # ICMP Flood detection
            elif ICMP in packet:
                self._packet_counts[src_ip]['icmp'] += 1
                rate = self._get_rate(src_ip, 'icmp')
                
                if rate > self.thresholds['icmp_flood_per_sec']:
                    return self._create_alert(
                        ThreatType.ICMP_FLOOD,
                        ThreatSeverity.MEDIUM,
                        src_ip, dst_ip,
                        f"ICMP Flood detected: {rate:.0f} ICMP/sec from {src_ip}",
                        {'rate': rate, 'target': dst_ip}
                    )
        
        return None
    
    def _analyze_port_scan(self, packet) -> Optional[SecurityAlert]:
        """Analyze packet for port scanning activity."""
        from scapy.all import IP, IPv6, TCP
        
        if TCP not in packet:
            return None
        
        # Get IPs
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None
        
        tcp = packet[TCP]
        dst_port = tcp.dport
        flags = tcp.flags
        
        with self._lock:
            now = datetime.now()
            
            # Reset port tracking periodically
            if (now - self._last_port_reset) > self._port_scan_window:
                self._port_access.clear()
                self._last_port_reset = now
            
            # Track port access
            self._port_access[src_ip][dst_ip].add(dst_port)
            
            ports_accessed = len(self._port_access[src_ip][dst_ip])
            
            # Detect different scan types based on flags
            scan_type = None
            severity = ThreatSeverity.MEDIUM
            
            # XMAS scan: FIN, PSH, URG flags set
            if (flags & 0x29) == 0x29:  # FIN, PSH, URG
                scan_type = ThreatType.XMAS_SCAN
                severity = ThreatSeverity.HIGH
            # NULL scan: No flags
            elif flags == 0:
                scan_type = ThreatType.NULL_SCAN
                severity = ThreatSeverity.HIGH
            # FIN scan: Only FIN flag
            elif flags == 0x01:
                scan_type = ThreatType.FIN_SCAN
                severity = ThreatSeverity.HIGH
            # Regular port scan: Many SYN to different ports
            elif flags & 0x02 and ports_accessed > self.thresholds['port_scan_ports']:
                scan_type = ThreatType.PORT_SCAN
                severity = ThreatSeverity.MEDIUM
            
            if scan_type:
                return self._create_alert(
                    scan_type,
                    severity,
                    src_ip, dst_ip,
                    f"{scan_type.value} detected: {src_ip} scanned {ports_accessed} ports on {dst_ip}",
                    {'ports_scanned': ports_accessed, 'flags': hex(flags)}
                )
        
        return None
    
    def _analyze_brute_force(self, packet) -> Optional[SecurityAlert]:
        """Analyze packet for brute-force login attempts on auth services."""
        from scapy.all import IP, IPv6, TCP
        
        if TCP not in packet:
            return None
        
        # Get IPs
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None
        
        tcp = packet[TCP]
        dst_port = tcp.dport
        flags = tcp.flags
        
        # Only check auth service ports and SYN packets (connection attempts)
        if dst_port not in self._auth_ports:
            return None
        
        # Check for SYN (connection attempt)
        if not (flags & 0x02):  # SYN flag
            return None
        
        with self._lock:
            now = datetime.now()
            key = (src_ip, dst_ip, dst_port)
            attempts = self._auth_attempts[key]
            
            # Reset if window expired
            if (now - attempts['last_reset']).total_seconds() > self.thresholds['brute_force_window']:
                attempts['count'] = 0
                attempts['last_reset'] = now
            
            attempts['count'] += 1
            
            # Check threshold
            if attempts['count'] >= self.thresholds['brute_force_attempts']:
                service_names = {
                    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
                    110: 'POP3', 143: 'IMAP', 3389: 'RDP', 5900: 'VNC'
                }
                service = service_names.get(dst_port, f'Port {dst_port}')
                
                # Reset to avoid repeated alerts
                old_count = attempts['count']
                attempts['count'] = 0
                
                return self._create_alert(
                    ThreatType.BRUTE_FORCE,
                    ThreatSeverity.HIGH,
                    src_ip, dst_ip,
                    f"Brute-force attack detected: {old_count} {service} login attempts from {src_ip} to {dst_ip}",
                    {'service': service, 'port': dst_port, 'attempts': old_count}
                )
        
        return None
    
    def _get_rate(self, ip: str, packet_type: str) -> float:
        """Calculate packet rate per second."""
        counts = self._packet_counts[ip]
        elapsed = (datetime.now() - counts['last_reset']).total_seconds()
        if elapsed < 0.1:
            elapsed = 0.1
        return counts[packet_type] / elapsed
    
    def _reset_rate_counters(self):
        """Reset rate counters for new window."""
        now = datetime.now()
        # Create copy of keys to avoid modification during iteration
        keys = list(self._packet_counts.keys())
        for ip in keys:
            self._packet_counts[ip] = {'syn': 0, 'udp': 0, 'icmp': 0, 'arp': 0, 'last_reset': now}
    
    def _create_alert(self, threat_type: ThreatType, severity: ThreatSeverity,
                      source_ip: str, target_ip: Optional[str],
                      description: str, details: Dict = None) -> SecurityAlert:
        """Create and register a new security alert."""
        with self._lock:
            self._alert_id += 1
            alert = SecurityAlert(
                id=self._alert_id,
                timestamp=datetime.now(),
                threat_type=threat_type,
                severity=severity,
                source_ip=source_ip,
                target_ip=target_ip,
                description=description,
                details=details or {}
            )
            self._alerts.append(alert)
            
            # Keep only last 1000 alerts
            if len(self._alerts) > 1000:
                self._alerts = self._alerts[-1000:]
        
        # Note: Callbacks removed - use Qt signals with QueuedConnection for 
        # thread-safe UI notification (callbacks were invoked from sniffer thread
        # which caused crashes when updating UI)
        
        return alert
    
    def get_alerts(self, threat_type: ThreatType = None,
                   severity: ThreatSeverity = None,
                   limit: int = 100) -> List[SecurityAlert]:
        """
        Get security alerts with optional filtering.
        
        Args:
            threat_type: Filter by threat type
            severity: Filter by severity
            limit: Maximum number of alerts to return
            
        Returns:
            List of SecurityAlert objects
        """
        with self._lock:
            alerts = self._alerts.copy()
        
        if threat_type:
            alerts = [a for a in alerts if a.threat_type == threat_type]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        
        return alerts[-limit:]
    
    def clear_alerts(self):
        """Clear all alerts."""
        with self._lock:
            self._alerts.clear()
    
    def reset(self):
        """Reset all security analyzer state."""
        with self._lock:
            self._alerts.clear()
            self._ip_mac_mapping.clear()
            self._mac_ip_mapping.clear()
            self._packet_counts.clear()
            self._port_access.clear()
            self._connection_attempts.clear()
    
    def get_statistics(self) -> Dict:
        """Get security analyzer statistics."""
        with self._lock:
            alert_counts = defaultdict(int)
            for alert in self._alerts:
                alert_counts[alert.threat_type.value] += 1
            
            return {
                'total_alerts': len(self._alerts),
                'alerts_by_type': dict(alert_counts),
                'ip_mac_mappings': len(self._ip_mac_mapping),
                'tracked_sources': len(self._packet_counts),
                'enabled': self._enabled
            }


# Global security analyzer instance
_global_analyzer = None


def get_security_analyzer() -> SecurityAnalyzer:
    """Get the global security analyzer instance."""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = SecurityAnalyzer()
    return _global_analyzer
