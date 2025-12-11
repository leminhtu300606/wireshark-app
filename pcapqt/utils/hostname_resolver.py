# -*- coding: utf-8 -*-
"""
Hostname/Device Name resolver supporting multiple protocols.

Supports:
- Computer/Client names: NetBIOS, DHCP, mDNS
- Network Infrastructure: LLDP (switch/router), CDP (Cisco), SNMP, UPnP
- DNS reverse lookups
- ARP resolution
"""

from scapy.all import Ether, IP, UDP, TCP, ARP, Raw, DNSQR, DNSRR, DNS
import re
from threading import Lock


class HostnameResolver:
    """Resolves device names/hostnames from various network protocols."""
    
    _instance = None
    _lock = Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super(HostnameResolver, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        self.hostnames = {}  # {ip: hostname}
        self.mac_to_hostname = {}  # {mac: hostname}
        self._initialized = True
    
    def add_hostname(self, ip, hostname):
        """Add IP to hostname mapping."""
        if ip and hostname and hostname.strip():
            self.hostnames[ip] = hostname.strip()
    
    def add_mac_hostname(self, mac, hostname):
        """Add MAC to hostname mapping."""
        if mac and hostname and hostname.strip():
            self.mac_to_hostname[mac] = hostname.strip()
    
    def get_hostname(self, ip):
        """Get hostname for IP address."""
        return self.hostnames.get(ip)
    
    def get_hostname_by_mac(self, mac):
        """Get hostname for MAC address."""
        return self.mac_to_hostname.get(mac)
    
    def extract_hostnames_from_packet(self, packet):
        """Extract device names from various protocols in packet."""
        hostnames = {'src': None, 'dst': None, 'src_mac': None, 'dst_mac': None}
        
        try:
            # Extract from NetBIOS
            netbios_name = self._extract_netbios(packet)
            if netbios_name:
                if packet[Ether].src:
                    self.add_mac_hostname(packet[Ether].src, netbios_name)
                    hostnames['src_mac'] = netbios_name
            
            # Extract from DHCP
            dhcp_hostname = self._extract_dhcp_hostname(packet)
            if dhcp_hostname:
                if IP in packet:
                    self.add_hostname(packet[IP].src, dhcp_hostname)
                    hostnames['src'] = dhcp_hostname
                if Ether in packet:
                    self.add_mac_hostname(packet[Ether].src, dhcp_hostname)
                    hostnames['src_mac'] = dhcp_hostname
            
            # Extract from mDNS
            mdns_hostname = self._extract_mdns_hostname(packet)
            if mdns_hostname:
                if IP in packet:
                    self.add_hostname(packet[IP].src, mdns_hostname)
                    hostnames['src'] = mdns_hostname
            
            # Extract from DNS responses (PTR records)
            dns_hostname = self._extract_dns_hostname(packet)
            if dns_hostname:
                if IP in packet:
                    # For DNS responses, the answer contains hostname
                    self.add_hostname(packet[IP].src, dns_hostname)
                    hostnames['src'] = dns_hostname
            
            # Try to get from ARP if it's an ARP packet
            if ARP in packet:
                # NetBIOS often travels with ARP
                arp_hostname = self._extract_arp_hostname(packet)
                if arp_hostname:
                    self.add_hostname(packet[ARP].psrc, arp_hostname)
                    self.add_mac_hostname(packet[ARP].hwsrc, arp_hostname)
                    hostnames['src'] = arp_hostname
                    hostnames['src_mac'] = arp_hostname
            
            # Extract from LLDP (Link Layer Discovery Protocol) - Switch/Router
            lldp_hostname = self._extract_lldp_hostname(packet)
            if lldp_hostname:
                if Ether in packet:
                    self.add_mac_hostname(packet[Ether].src, lldp_hostname)
                    hostnames['src_mac'] = lldp_hostname
                hostnames['src'] = lldp_hostname
            
            # Extract from CDP (Cisco Discovery Protocol) - Cisco devices
            cdp_hostname = self._extract_cdp_hostname(packet)
            if cdp_hostname:
                if Ether in packet:
                    self.add_mac_hostname(packet[Ether].src, cdp_hostname)
                    hostnames['src_mac'] = cdp_hostname
                hostnames['src'] = cdp_hostname
            
            # Extract from UPnP/SSDP - IoT devices, printer, router
            upnp_device = self._extract_upnp_device(packet)
            if upnp_device:
                if IP in packet:
                    self.add_hostname(packet[IP].src, upnp_device)
                    hostnames['src'] = upnp_device
                if Ether in packet:
                    self.add_mac_hostname(packet[Ether].src, upnp_device)
                    hostnames['src_mac'] = upnp_device
            
            # Extract from SNMP - Router/Switch management
            snmp_info = self._extract_snmp_sysname(packet)
            if snmp_info:
                if IP in packet:
                    self.add_hostname(packet[IP].src, snmp_info)
                    hostnames['src'] = snmp_info
                if Ether in packet:
                    self.add_mac_hostname(packet[Ether].src, snmp_info)
                    hostnames['src_mac'] = snmp_info
        
        except Exception as e:
            pass
        
        return hostnames
    
    def _extract_netbios(self, packet):
        """Extract NetBIOS computer name from packet."""
        try:
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            
            # NetBIOS query/response patterns
            # Look for common NetBIOS indicators
            if len(payload) > 20:
                # NetBIOS name query typically has pattern
                # Try to find printable ASCII sequences that might be hostname
                match = re.search(b'[A-Za-z0-9\-_]{1,15}', payload)
                if match:
                    name = match.group(0).decode('ascii', errors='ignore')
                    if name and not name.isdigit() and len(name) >= 2:
                        return name
            
            return None
        except:
            return None
    
    def _extract_dhcp_hostname(self, packet):
        """Extract hostname from DHCP protocol."""
        try:
            if not (UDP in packet):
                return None
            
            sport, dport = packet[UDP].sport, packet[UDP].dport
            
            # DHCP ports
            if not ((sport == 67 or sport == 68) or (dport == 67 or dport == 68)):
                return None
            
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            
            # DHCP hostname option (option 12)
            # Look for option 12 in DHCP options
            if len(payload) > 245:  # DHCP has fixed part before options
                options_start = 240
                pos = options_start
                
                while pos < len(payload) - 2:
                    option_type = payload[pos]
                    option_len = payload[pos + 1] if pos + 1 < len(payload) else 0
                    
                    if option_type == 12 and option_len > 0 and pos + 2 + option_len <= len(payload):
                        # Option 12 is hostname
                        hostname = payload[pos + 2:pos + 2 + option_len].decode('ascii', errors='ignore')
                        if hostname and hostname.isprintable():
                            return hostname.strip()
                    
                    if option_type == 255:  # End of options
                        break
                    
                    pos += 2 + option_len
            
            return None
        except:
            return None
    
    def _extract_mdns_hostname(self, packet):
        """Extract hostname from mDNS (Multicast DNS)."""
        try:
            if UDP not in packet:
                return None
            
            sport, dport = packet[UDP].sport, packet[UDP].dport
            
            # mDNS port
            if not (sport == 5353 or dport == 5353):
                return None
            
            if DNS in packet:
                dns = packet[DNS]
                
                # mDNS typically has .local domain
                if DNSQR in packet:
                    qname = packet[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('ascii', errors='ignore')
                    
                    if qname and '.local' in qname:
                        # Remove .local and trailing dot
                        hostname = qname.replace('.local.', '').replace('.local', '')
                        if hostname and hostname.isprintable() and len(hostname) >= 2:
                            return hostname
                
                if DNSRR in packet and hasattr(packet[DNS], 'an'):
                    for rr in packet[DNS].an:
                        if hasattr(rr, 'rrname'):
                            rrname = rr.rrname
                            if isinstance(rrname, bytes):
                                rrname = rrname.decode('ascii', errors='ignore')
                            
                            if rrname and '.local' in rrname:
                                hostname = rrname.replace('.local.', '').replace('.local', '')
                                if hostname and hostname.isprintable() and len(hostname) >= 2:
                                    return hostname
            
            return None
        except:
            return None
    
    def _extract_dns_hostname(self, packet):
        """Extract hostname from DNS responses."""
        try:
            if DNS not in packet:
                return None
            
            dns = packet[DNS]
            
            # Check if this is a DNS response
            if not dns.qr:  # qr=1 means response
                return None
            
            # Look for PTR records (reverse DNS)
            if hasattr(dns, 'an') and dns.an:
                for rr in dns.an:
                    if hasattr(rr, 'rdata') and isinstance(rr.rdata, str):
                        rdata = rr.rdata
                        if '.' in rdata and not rdata.startswith('['):
                            # Remove trailing dot
                            hostname = rdata.rstrip('.')
                            if hostname.isprintable() and len(hostname) >= 2:
                                return hostname
            
            return None
        except:
            return None
    
    def _extract_arp_hostname(self, packet):
        """Extract hostname from ARP packet (often combined with NetBIOS)."""
        try:
            if ARP not in packet:
                return None
            
            # ARP itself doesn't contain hostname, but might be part of NetBIOS query
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                # Try NetBIOS extraction on ARP payload
                return self._extract_netbios_from_raw(payload)
            
            return None
        except:
            return None
    
    def _extract_netbios_from_raw(self, payload):
        """Extract NetBIOS name from raw payload."""
        try:
            if len(payload) < 20:
                return None
            
            # NetBIOS uses specific encoding (half-ASCII)
            # Try to find standard NetBIOS name query patterns
            matches = re.findall(b'[A-Z][A-Za-z0-9\-_]{1,14}', payload)
            
            for match in matches:
                name = match.decode('ascii', errors='ignore')
                if len(name) >= 2 and len(name) <= 15 and not name.isdigit():
                    return name
            
            return None
        except:
            return None
    
    def _extract_lldp_hostname(self, packet):
        """Extract hostname from LLDP (Link Layer Discovery Protocol).
        
        LLDP is used by switches/routers to announce their presence.
        EtherType 0x88CC for LLDP.
        """
        try:
            if Ether not in packet:
                return None
            
            # LLDP uses special EtherType
            if packet[Ether].type != 0x88CC:
                return None
            
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            
            # LLDP TLV structure: Type (7 bits) + Length (9 bits) + Value
            # Type 5 = System Name
            pos = 0
            while pos + 2 <= len(payload):
                tlv_header = int.from_bytes(payload[pos:pos+2], 'big')
                tlv_type = (tlv_header >> 9) & 0x7F
                tlv_length = tlv_header & 0x1FF
                
                if tlv_type == 5 and tlv_length > 0:  # System Name TLV
                    if pos + 2 + tlv_length <= len(payload):
                        sysname = payload[pos+2:pos+2+tlv_length].decode('ascii', errors='ignore')
                        if sysname and sysname.isprintable() and len(sysname) >= 2:
                            return f"[LLDP Switch] {sysname}"
                
                if tlv_type == 0 and tlv_length == 0:  # End of LLDP
                    break
                
                pos += 2 + tlv_length
            
            return None
        except:
            return None
    
    def _extract_cdp_hostname(self, packet):
        """Extract hostname from CDP (Cisco Discovery Protocol).
        
        CDP is Cisco proprietary, uses port 1900 (SSDP-like).
        """
        try:
            if UDP not in packet:
                return None
            
            sport, dport = packet[UDP].sport, packet[UDP].dport
            
            # CDP often uses 1900 or 1985
            if not (sport in (1900, 1985) or dport in (1900, 1985)):
                return None
            
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            
            # Look for Cisco Device ID marker (type 0x0001)
            if b'Device ID' in payload or b'device id' in payload.lower():
                match = re.search(b'[A-Za-z0-9\.\-_]{3,30}', payload)
                if match:
                    device_id = match.group(0).decode('ascii', errors='ignore')
                    if device_id and device_id.isprintable():
                        return f"[Cisco CDP] {device_id}"
            
            return None
        except:
            return None
    
    def _extract_upnp_device(self, packet):
        """Extract device info from UPnP/SSDP.
        
        UPnP uses port 1900 (SSDP).
        Common for routers, printers, smart devices.
        """
        try:
            if UDP not in packet:
                return None
            
            sport, dport = packet[UDP].sport, packet[UDP].dport
            
            # SSDP/UPnP port
            if not (sport == 1900 or dport == 1900):
                return None
            
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            text = payload.decode('utf-8', errors='ignore').lower()
            
            # Look for common UPnP/SSDP headers
            device_type = ''
            if 'upnp' in text or 'ssdp' in text:
                # Try to extract SERVER or USER-AGENT header
                for header in ['server:', 'user-agent:']:
                    if header in text:
                        start = text.find(header) + len(header)
                        end = text.find('\r\n', start)
                        if end > start:
                            device_info = text[start:end].strip()
                            if device_info and len(device_info) > 3:
                                # Extract meaningful parts
                                if 'router' in device_info.lower():
                                    return f"[UPnP Router] {device_info[:40]}"
                                elif 'printer' in device_info.lower():
                                    return f"[UPnP Printer] {device_info[:40]}"
                                elif 'camera' in device_info.lower():
                                    return f"[UPnP Camera] {device_info[:40]}"
                                else:
                                    return f"[UPnP Device] {device_info[:40]}"
            
            return None
        except:
            return None
    
    def _extract_snmp_sysname(self, packet):
        """Extract device sysname from SNMP packets.
        
        SNMP port 161 - used by routers/switches for management.
        """
        try:
            if UDP not in packet:
                return None
            
            sport, dport = packet[UDP].sport, packet[UDP].dport
            
            # SNMP port
            if not (sport == 161 or dport == 161):
                return None
            
            if Raw not in packet:
                return None
            
            payload = bytes(packet[Raw].load)
            
            # SNMP sysName OID (.1.3.6.1.2.1.1.5.0)
            # Look for common printable ASCII that might be sysname
            matches = re.findall(b'[A-Za-z0-9\.\-_]{3,30}', payload)
            
            for match in matches:
                name = match.decode('ascii', errors='ignore')
                if (name and len(name) >= 3 and 
                    not name.isdigit() and 
                    name[0].isalpha() and
                    not name.startswith('.')):
                    return f"[SNMP Device] {name}"
            
            return None
        except:
            return None
    
    def get_all_hostnames(self):
        """Get all known hostnames."""
        return {
            'by_ip': self.hostnames.copy(),
            'by_mac': self.mac_to_hostname.copy()
        }
    
    def clear(self):
        """Clear all stored hostnames."""
        self.hostnames.clear()
        self.mac_to_hostname.clear()


def get_hostname_resolver():
    """Get singleton instance of hostname resolver."""
    return HostnameResolver()

