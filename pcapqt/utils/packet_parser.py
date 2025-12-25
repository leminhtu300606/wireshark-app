# -*- coding: utf-8 -*-
"""
Packet parser supporting OSI Layers 1-7.

Layer 1 (Physical): Frame information
Layer 2 (Data Link): Ethernet
Layer 3 (Network): IP, ARP
Layer 4 (Transport): TCP, UDP, ICMP
Layer 5 (Session): Connection management, session control
Layer 6 (Presentation): Data encoding, encryption, compression
Layer 7 (Application): Protocol-specific data
"""

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw, DNS
from datetime import datetime
import struct
import binascii

from .dns_resolver import get_dns_resolver
from .hostname_resolver import get_hostname_resolver

from .protocol_parsers import (
    WELL_KNOWN_PORTS,
    ETHER_TYPES,
    TLS_VERSIONS,
    TLS_CONTENT_TYPES,
    parse_dns_app,
    parse_http_app,
    parse_tls_app,
    parse_dhcp_app,
    parse_ftp_app,
    parse_smtp_app,
    parse_ssh_app,
    parse_pop3_app,
    parse_imap_app,
    parse_ntp_app,
    parse_snmp_app,
    parse_telnet_app,
    parse_raw_data,
)


class PacketParser:
    """Packet parser supporting OSI Layers 1-7."""
    
    @staticmethod
    def parse_packet(packet, packet_count, start_time):
        """Parse a packet and return basic info for table display."""
        info = {
            'no': packet_count,
            'time': (datetime.now() - start_time).total_seconds(),
            'src': 'Unknown', 'dst': 'Unknown',
            'protocol': 'Unknown', 'length': len(packet), 'info': '',
            'src_name': '', 'dst_name': '',  # Domain names from DNS
            'src_device': '', 'dst_device': '',  # Device names (hostname/NetBIOS)
            'src_mac': '', 'dst_mac': ''  # MAC addresses
        }
        if Ether in packet:
            info['src'] = packet[Ether].src
            info['dst'] = packet[Ether].dst
            info['src_mac'] = packet[Ether].src
            info['dst_mac'] = packet[Ether].dst

        # Extract device names from various protocols
        hostname_resolver = get_hostname_resolver()
        extracted_hostnames = hostname_resolver.extract_hostnames_from_packet(packet)

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            
            # Try to resolve hostnames from DNS cache
            resolver = get_dns_resolver()
            src_name = resolver.get_domain_for_ip(packet[IP].src)
            dst_name = resolver.get_domain_for_ip(packet[IP].dst)
            if src_name:
                info['src_name'] = src_name
            if dst_name:
                info['dst_name'] = dst_name
            
            # Get device names from extracted protocols
            if extracted_hostnames.get('src'):
                info['src_device'] = extracted_hostnames['src']
            if extracted_hostnames.get('src_mac'):
                info['src_device'] = extracted_hostnames['src_mac']

            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                
                # Get all detected Layer 7 protocols for better searchability
                all_protocols = PacketParser._detect_all_app_protocols(packet, sport, dport)
                if all_protocols:
                    info['protocol'] = ' | '.join(all_protocols)
                else:
                    info['protocol'] = app_proto if app_proto else 'TCP'
                
                # Enhanced Info for HTTP
                if app_proto == 'HTTP':
                     http_info = PacketParser._get_http_info(packet)
                     if http_info:
                         info['info'] = http_info
                     else:
                         info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
                elif app_proto == 'TLS' or info['protocol'].startswith('TLS'):
                    tls_info = PacketParser._get_tls_info(packet, sport, dport)
                    if tls_info:
                        info['info'] = tls_info
                    else:
                        info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
                else:
                    # Generic enhanced info for all other TCP protocols
                    extra_info = PacketParser._get_generic_protocol_info(packet, app_proto, sport, dport)
                    if extra_info:
                        info['info'] = f"{sport} → {dport} {extra_info}"
                    else:
                        info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                
                # Get all detected Layer 7 protocols for better searchability
                all_protocols = PacketParser._detect_all_app_protocols(packet, sport, dport)
                if all_protocols:
                    info['protocol'] = ' | '.join(all_protocols)
                else:
                    info['protocol'] = app_proto if app_proto else 'UDP'
                
                # Enhanced info for UDP protocols
                if app_proto == 'DNS':
                    dns_info = PacketParser._get_dns_info(packet)
                    if dns_info:
                        info['info'] = dns_info
                    else:
                        info['info'] = f"{sport} → {dport}"
                elif app_proto == 'QUIC':
                    info['info'] = f"{sport} → {dport} (QUIC Encrypted)"
                else:
                    # Generic enhanced info for all other UDP protocols
                    extra_info = PacketParser._get_generic_protocol_info(packet, app_proto, sport, dport)
                    if extra_info:
                        info['info'] = f"{sport} → {dport} {extra_info}"
                    else:
                        info['info'] = f"{sport} → {dport}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = f"Type: {packet[ICMP].type}"
            else:
                # Handle other IP protocols (IGMP, GRE, ESP, etc.)
                proto_num = packet[IP].proto
                proto_names = {
                    1: 'ICMP',
                    2: 'IGMP',
                    4: 'IP-in-IP',
                    6: 'TCP',
                    17: 'UDP',
                    41: 'IPv6-Encap',
                    47: 'GRE',
                    50: 'ESP',
                    51: 'AH',
                    58: 'ICMPv6',
                    89: 'OSPF',
                    103: 'PIM',
                    112: 'VRRP',
                    132: 'SCTP',
                }
                proto_name = proto_names.get(proto_num, f'IP-Proto-{proto_num}')
                info['protocol'] = proto_name
                
                # Add specific info based on protocol
                dst = packet[IP].dst
                if proto_num == 2:  # IGMP
                    # Check if multicast
                    if dst.startswith('224.') or dst.startswith('239.'):
                        info['info'] = f"Multicast Group: {dst}"
                    else:
                        info['info'] = f"IGMP → {dst}"
                elif proto_num == 89:  # OSPF
                    info['info'] = f"OSPF Router Communication"
                elif proto_num == 112:  # VRRP
                    info['info'] = f"Virtual Router Redundancy"
                else:
                    info['info'] = f"{packet[IP].src} → {dst}"
            
            # Append device name if available, else domain name
            if info['src_device']:
                info['info'] += f" [Device: {info['src_device']}]"
            elif info['dst_name']:
                info['info'] += f" (→ {info['dst_name']})"
            elif info['src_name'] and not info['info'].endswith(')'):
                info['info'] += f" (← {info['src_name']})"
        elif IPv6 in packet:
            info['src'] = packet[IPv6].src
            info['dst'] = packet[IPv6].dst
            
            # Try to resolve hostnames from DNS cache
            resolver = get_dns_resolver()
            src_name = resolver.get_domain_for_ip(packet[IPv6].src)
            dst_name = resolver.get_domain_for_ip(packet[IPv6].dst)
            if src_name:
                info['src_name'] = src_name
            if dst_name:
                info['dst_name'] = dst_name
            
            # Get device names from extracted protocols
            if extracted_hostnames.get('src'):
                info['src_device'] = extracted_hostnames['src']
            if extracted_hostnames.get('src_mac'):
                info['src_device'] = extracted_hostnames['src_mac']

            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                
                # Get all detected Layer 7 protocols for better searchability
                all_protocols = PacketParser._detect_all_app_protocols(packet, sport, dport)
                if all_protocols:
                    info['protocol'] = 'IPv6 | ' + ' | '.join(all_protocols)
                else:
                    info['protocol'] = 'IPv6 | ' + (app_proto if app_proto else 'TCP')
                
                # Enhanced Info for HTTP
                if app_proto == 'HTTP':
                     http_info = PacketParser._get_http_info(packet)
                     if http_info:
                         info['info'] = http_info
                     else:
                         info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
                elif app_proto == 'TLS' or (info['protocol'] and 'TLS' in info['protocol']):
                    tls_info = PacketParser._get_tls_info(packet, sport, dport)
                    if tls_info:
                        info['info'] = tls_info
                    else:
                        info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
                else:
                    # Generic enhanced info for all other TCP protocols
                    extra_info = PacketParser._get_generic_protocol_info(packet, app_proto, sport, dport)
                    if extra_info:
                        info['info'] = f"{sport} → {dport} {extra_info}"
                    else:
                        info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                
                # Get all detected Layer 7 protocols for better searchability
                all_protocols = PacketParser._detect_all_app_protocols(packet, sport, dport)
                if all_protocols:
                    info['protocol'] = 'IPv6 | ' + ' | '.join(all_protocols)
                else:
                    info['protocol'] = 'IPv6 | ' + (app_proto if app_proto else 'UDP')
                
                # Enhanced info for UDP protocols
                if app_proto == 'DNS':
                    dns_info = PacketParser._get_dns_info(packet)
                    if dns_info:
                        info['info'] = dns_info
                    else:
                        info['info'] = f"{sport} → {dport}"
                elif app_proto == 'QUIC':
                    info['info'] = f"{sport} → {dport} (QUIC Encrypted)"
                else:
                    # Generic enhanced info for all other UDP protocols
                    extra_info = PacketParser._get_generic_protocol_info(packet, app_proto, sport, dport)
                    if extra_info:
                        info['info'] = f"{sport} → {dport} {extra_info}"
                    else:
                        info['info'] = f"{sport} → {dport}"
            else:
                # Handle other IPv6 protocols (ICMPv6, etc.)
                nh = packet[IPv6].nh  # Next Header
                nh_names = {
                    0: 'IPv6-HopByHop',
                    6: 'IPv6 | TCP',
                    17: 'IPv6 | UDP',
                    43: 'IPv6-Routing',
                    44: 'IPv6-Fragment',
                    50: 'IPv6 | ESP',
                    51: 'IPv6 | AH',
                    58: 'IPv6 | ICMPv6',
                    59: 'IPv6-NoNext',
                    60: 'IPv6-DestOpts',
                    89: 'IPv6 | OSPF',
                    103: 'IPv6 | PIM',
                    132: 'IPv6 | SCTP',
                }
                proto_name = nh_names.get(nh, f'IPv6 | Proto-{nh}')
                info['protocol'] = proto_name
                info['info'] = f"{packet[IPv6].src} → {packet[IPv6].dst}"
            
            # Append device name if available, else domain name
            if info['src_device']:
                info['info'] += f" [Device: {info['src_device']}]"
            elif info['dst_name']:
                info['info'] += f" (→ {info['dst_name']})"
            elif info['src_name'] and not info['info'].endswith(')'):
                info['info'] += f" (← {info['src_name']})"
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            op = packet[ARP].op
            if op == 1:
                info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"
            else:
                info['info'] = f"{packet[ARP].psrc} is at {packet[ARP].hwsrc}"
        elif Ether in packet:
            # Non-IP Ethernet frame
            ether_type = packet[Ether].type
            proto_name = ETHER_TYPES.get(ether_type, f'Ethernet (0x{ether_type:04x})')
            info['protocol'] = proto_name
            info['info'] = f"EtherType: 0x{ether_type:04x}"

        return info

    @staticmethod
    def _detect_app_protocol(packet, sport, dport):
        """Detect application layer protocol based on ports and payload."""
        if sport == 53 or dport == 53:
            return 'DNS'
        if sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                return 'HTTP'
        if sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            # Check for QUIC (UDP 443 often used) - simplified check
            if UDP in packet:
                return 'QUIC'
            return 'TLS'
        if sport in (67, 68) or dport in (67, 68):
            return 'DHCP'
        if sport == 5353 or dport == 5353:
             return 'MDNS'
        if sport == 5355 or dport == 5355:
             return 'LLMNR'
        if sport == 1900 or dport == 1900:
             return 'SSDP'
        if sport in (137, 138, 139) or dport in (137, 138, 139):
             return 'NetBIOS'
        if sport == 445 or dport == 445:
             return 'SMB'
        if sport == 21 or dport == 21:
            return 'FTP'
        if sport == 20 or dport == 20:
            return 'FTP-Data'
        if sport == 25 or dport == 25 or sport == 587 or dport == 587 or sport == 465 or dport == 465:
            return 'SMTP'
        if sport == 22 or dport == 22:
            return 'SSH'
        if sport == 110 or dport == 110 or sport == 995 or dport == 995:
            return 'POP3'
        if sport == 143 or dport == 143 or sport == 993 or dport == 993:
            return 'IMAP'
        if sport == 123 or dport == 123:
            return 'NTP'
        if sport == 161 or dport == 161 or sport == 162 or dport == 162:
            return 'SNMP'
        if sport == 23 or dport == 23:
            return 'Telnet'
        # Additional protocols
        if sport == 389 or dport == 389 or sport == 636 or dport == 636:
            return 'LDAP'
        if sport == 3389 or dport == 3389:
            return 'RDP'
        if sport == 3306 or dport == 3306:
            return 'MySQL'
        if sport == 5432 or dport == 5432:
            return 'PostgreSQL'
        if sport == 6379 or dport == 6379:
            return 'Redis'
        if sport == 69 or dport == 69:
            return 'TFTP'
        if sport == 5060 or dport == 5060 or sport == 5061 or dport == 5061:
            return 'SIP'
        if sport == 88 or dport == 88:
            return 'Kerberos'
        if sport == 135 or dport == 135:
            return 'MS-RPC'
        if sport == 514 or dport == 514:
            return 'Syslog'
        if sport == 1433 or dport == 1433:
            return 'MSSQL'
        if sport == 1521 or dport == 1521:
            return 'Oracle'
        if sport == 27017 or dport == 27017:
            return 'MongoDB'
        if sport == 6667 or dport == 6667:
            return 'IRC'
        if sport == 179 or dport == 179:
            return 'BGP'
        if sport == 500 or dport == 500:
            return 'IKE'
        if sport == 1194 or dport == 1194:
            return 'OpenVPN'
        # More UDP protocols
        if sport == 3478 or dport == 3478 or sport == 3479 or dport == 3479:
            return 'STUN'
        if sport == 1812 or dport == 1812 or sport == 1813 or dport == 1813:
            return 'RADIUS'
        if sport == 554 or dport == 554:
            return 'RTSP'
        if (sport >= 16384 and sport <= 32767) or (dport >= 16384 and dport <= 32767):
            # Common RTP port range
            if UDP in packet:
                return 'RTP/RTCP'
        if sport == 1701 or dport == 1701:
            return 'L2TP'
        if sport == 1723 or dport == 1723:
            return 'PPTP'
        if sport == 4500 or dport == 4500:
            return 'IPSec-NAT'
        if sport == 1985 or dport == 1985:
            return 'HSRP'
        if sport == 520 or dport == 520:
            return 'RIP'
        if sport == 179 or dport == 179:
            return 'BGP'
        if sport == 5004 or dport == 5004 or sport == 5005 or dport == 5005:
            return 'RTP'
        if sport == 1645 or dport == 1645 or sport == 1646 or dport == 1646:
            return 'RADIUS'
        if sport == 49 or dport == 49:
            return 'TACACS'
        if sport == 1080 or dport == 1080:
            return 'SOCKS'
        if sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                return 'HTTP-Proxy'
        if sport == 8443 or dport == 8443:
            return 'HTTPS-Alt'
        if sport == 9000 or dport == 9000:
            return 'PHP-FPM'
        if sport == 9200 or dport == 9200:
            return 'Elasticsearch'
        if sport == 6443 or dport == 6443:
            return 'Kubernetes'
        if sport == 2049 or dport == 2049:
            return 'NFS'
        if sport == 111 or dport == 111:
            return 'Portmapper'
        if sport == 873 or dport == 873:
            return 'rsync'
        if sport == 3128 or dport == 3128:
            return 'Squid-Proxy'
        if sport == 1883 or dport == 1883 or sport == 8883 or dport == 8883:
            return 'MQTT'
        if sport == 5222 or dport == 5222 or sport == 5223 or dport == 5223:
            return 'XMPP'
        if sport == 6881 or dport == 6881:
            return 'BitTorrent'
        if sport == 27015 or dport == 27015:
            return 'Steam'
        if sport == 25565 or dport == 25565:
            return 'Minecraft'
        if sport == 3724 or dport == 3724:
            return 'WoW'
        if sport == 5938 or dport == 5938:
            return 'TeamViewer'
        if sport == 5900 or dport == 5900:
            return 'VNC'
        if sport == 1935 or dport == 1935:
            return 'RTMP'
        if sport == 27960 or dport == 27960:
            return 'Quake3'
        if sport == 3490 or dport == 3490:
            return 'Gocator'
        if sport == 54915 or dport == 54915:
            return 'Lmnart'
        return None

    @staticmethod
    def _detect_all_app_protocols(packet, sport, dport):
        """Detect ALL possible application layer protocols based on ports and payload.
        
        Returns a list of all detected Layer 7 protocols.
        """
        protocols = []
        
        # DNS
        if sport == 53 or dport == 53:
            protocols.append('DNS')
        
        # HTTP/HTTPS related
        if sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                protocols.append('HTTP')
        
        if sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            if UDP in packet:
                protocols.append('QUIC')
            else:
                protocols.append('TLS')
        
        # DHCP
        if sport in (67, 68) or dport in (67, 68):
            protocols.append('DHCP')
        
        # mDNS
        if sport == 5353 or dport == 5353:
            protocols.append('mDNS')
        
        # LLMNR
        if sport == 5355 or dport == 5355:
            protocols.append('LLMNR')
        
        # SSDP
        if sport == 1900 or dport == 1900:
            protocols.append('SSDP')
        
        # NetBIOS
        if sport in (137, 138, 139) or dport in (137, 138, 139):
            protocols.append('NetBIOS')
        
        # SMB
        if sport == 445 or dport == 445:
            protocols.append('SMB')
        
        # FTP
        if sport == 21 or dport == 21:
            protocols.append('FTP')
        
        if sport == 20 or dport == 20:
            protocols.append('FTP-Data')
        
        # SMTP/Email
        if sport == 25 or dport == 25 or sport == 587 or dport == 587 or sport == 465 or dport == 465:
            protocols.append('SMTP')
        
        # SSH
        if sport == 22 or dport == 22:
            protocols.append('SSH')
        
        # POP3
        if sport == 110 or dport == 110 or sport == 995 or dport == 995:
            protocols.append('POP3')
        
        # IMAP
        if sport == 143 or dport == 143 or sport == 993 or dport == 993:
            protocols.append('IMAP')
        
        # NTP
        if sport == 123 or dport == 123:
            protocols.append('NTP')
        
        # SNMP
        if sport == 161 or dport == 161 or sport == 162 or dport == 162:
            protocols.append('SNMP')
        
        # Telnet
        if sport == 23 or dport == 23:
            protocols.append('Telnet')
        
        # LDAP
        if sport == 389 or dport == 389 or sport == 636 or dport == 636:
            protocols.append('LDAP')
        
        # RDP
        if sport == 3389 or dport == 3389:
            protocols.append('RDP')
        
        # Databases
        if sport == 3306 or dport == 3306:
            protocols.append('MySQL')
        
        if sport == 5432 or dport == 5432:
            protocols.append('PostgreSQL')
        
        if sport == 1433 or dport == 1433:
            protocols.append('MSSQL')
        
        if sport == 1521 or dport == 1521:
            protocols.append('Oracle')
        
        if sport == 27017 or dport == 27017:
            protocols.append('MongoDB')
        
        if sport == 6379 or dport == 6379:
            protocols.append('Redis')
        
        # TFTP
        if sport == 69 or dport == 69:
            protocols.append('TFTP')
        
        # SIP
        if sport == 5060 or dport == 5060 or sport == 5061 or dport == 5061:
            protocols.append('SIP')
        
        # Kerberos
        if sport == 88 or dport == 88:
            protocols.append('Kerberos')
        
        # MS-RPC
        if sport == 135 or dport == 135:
            protocols.append('MS-RPC')
        
        # Syslog
        if sport == 514 or dport == 514:
            protocols.append('Syslog')
        
        # IRC
        if sport == 6667 or dport == 6667:
            protocols.append('IRC')
        
        # BGP
        if sport == 179 or dport == 179:
            protocols.append('BGP')
        
        # IKE
        if sport == 500 or dport == 500:
            protocols.append('IKE')
        
        # OpenVPN
        if sport == 1194 or dport == 1194:
            protocols.append('OpenVPN')
        
        # STUN
        if sport == 3478 or dport == 3478 or sport == 3479 or dport == 3479:
            protocols.append('STUN')
        
        # RADIUS
        if sport == 1812 or dport == 1812 or sport == 1813 or dport == 1813:
            protocols.append('RADIUS')
        
        # RTSP
        if sport == 554 or dport == 554:
            protocols.append('RTSP')
        
        # RTP/RTCP
        if (sport >= 16384 and sport <= 32767) or (dport >= 16384 and dport <= 32767):
            if UDP in packet:
                protocols.append('RTP/RTCP')
        
        # VPN/Tunneling
        if sport == 1701 or dport == 1701:
            protocols.append('L2TP')
        
        if sport == 1723 or dport == 1723:
            protocols.append('PPTP')
        
        if sport == 4500 or dport == 4500:
            protocols.append('IPSec-NAT')
        
        # HSRP
        if sport == 1985 or dport == 1985:
            protocols.append('HSRP')
        
        # RIP
        if sport == 520 or dport == 520:
            protocols.append('RIP')
        
        # RTP (generic)
        if sport == 5004 or dport == 5004 or sport == 5005 or dport == 5005:
            protocols.append('RTP')
        
        # RADIUS (alternate ports)
        if sport == 1645 or dport == 1645 or sport == 1646 or dport == 1646:
            protocols.append('RADIUS')
        
        # TACACS
        if sport == 49 or dport == 49:
            protocols.append('TACACS')
        
        # SOCKS
        if sport == 1080 or dport == 1080:
            protocols.append('SOCKS')
        
        # HTTP Proxy
        if sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                if 'HTTP' not in protocols:
                    protocols.append('HTTP-Proxy')
        
        # HTTPS Alt
        if sport == 8443 or dport == 8443:
            if 'TLS' not in protocols:
                protocols.append('HTTPS-Alt')
        
        # PHP-FPM
        if sport == 9000 or dport == 9000:
            protocols.append('PHP-FPM')
        
        # Elasticsearch
        if sport == 9200 or dport == 9200:
            protocols.append('Elasticsearch')
        
        # Kubernetes
        if sport == 6443 or dport == 6443:
            protocols.append('Kubernetes')
        
        # NFS
        if sport == 2049 or dport == 2049:
            protocols.append('NFS')
        
        # Portmapper
        if sport == 111 or dport == 111:
            protocols.append('Portmapper')
        
        # rsync
        if sport == 873 or dport == 873:
            protocols.append('rsync')
        
        # Squid Proxy
        if sport == 3128 or dport == 3128:
            protocols.append('Squid')
        
        # Telnet (SSH alternative)
        if sport == 2222 or dport == 2222:
            protocols.append('SSH-Alt')
        
        # RDP (alternate port)
        if sport == 3390 or dport == 3390:
            protocols.append('RDP-Alt')
        
        # MySQL (alternate)
        if sport == 3307 or dport == 3307:
            protocols.append('MySQL-Alt')
        
        # Postgres (alternate)
        if sport == 5433 or dport == 5433:
            protocols.append('PostgreSQL-Alt')
        
        # TeamViewer
        if sport == 5938 or dport == 5938:
            protocols.append('TeamViewer')
        
        # VNC
        if sport == 5900 or dport == 5900:
            protocols.append('VNC')
        
        # RTMP
        if sport == 1935 or dport == 1935:
            protocols.append('RTMP')
        
        # Game servers
        if sport == 27960 or dport == 27960:
            protocols.append('Quake3')
        
        # Gocator
        if sport == 3490 or dport == 3490:
            protocols.append('Gocator')
            
        # Lmnart
        if sport == 54915 or dport == 54915:
            protocols.append('Lmnart')
        
        return protocols

    @staticmethod
    def _is_http(payload):
        """Check if payload looks like HTTP."""
        if not payload:
            return False
        try:
            text = payload[:20].decode('utf-8', errors='ignore').upper()
            return any(text.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/'])
        except:
            return False

    @staticmethod
    def _get_http_info(packet):
        """Extract short HTTP info for main table (Method URI or Status)."""
        if Raw not in packet:
            return None
        try:
            payload = bytes(packet[Raw].load)
            # Try decoding
            try:
                text = payload[:1024].decode('utf-8')
            except:
                text = payload[:1024].decode('latin-1', errors='ignore')
                
            lines = text.split('\r\n')
            if not lines:
                return None
                
            first_line = lines[0]
            
            # Request: GET /index.html HTTP/1.1
            if not first_line.startswith('HTTP/'):
                parts = first_line.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    uri = parts[1]
                    # Extract Host header
                    host = ''
                    for line in lines[1:6]:
                        if line.lower().startswith('host:'):
                            host = f" (Host: {line.split(':', 1)[1].strip()})"
                            break
                    return f"{method} {uri}{host}"
            
            # Response: HTTP/1.1 200 OK
            else:
                parts = first_line.split(' ', 2)
                if len(parts) >= 2:
                    status = parts[1]
                    reason = parts[2] if len(parts) > 2 else ''
                    # Extract Server header
                    server = ''
                    for line in lines[1:6]:
                        if line.lower().startswith('server:'):
                             server = f" (Server: {line.split(':', 1)[1].strip()})"
                             break
                    return f"HTTP {status} {reason}{server}"
                    
            return None
        except:
            return None

    @staticmethod
    def _get_generic_protocol_info(packet, app_proto, sport, dport):
        """Extract generic info for any protocol from payload."""
        if Raw not in packet:
            # Return service name if known
            from .protocol_parsers import WELL_KNOWN_PORTS
            service = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
            if service:
                return f"[{service}]"
            return None
            
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 3:
                return None
            
            # Try to decode as text
            try:
                text = payload[:100].decode('utf-8', errors='ignore').strip()
            except:
                text = ''
            
            # SSH version
            if app_proto == 'SSH' or sport == 22 or dport == 22:
                if text.startswith('SSH-'):
                    return f"[{text.split()[0]}]"
                return "[SSH Encrypted]"
            
            # FTP/SMTP/POP3/IMAP commands or responses
            if app_proto in ('FTP', 'SMTP', 'POP3', 'IMAP'):
                if text[:3].isdigit():
                    # Response code
                    return f"[Response: {text[:3]}]"
                else:
                    # Command
                    cmd = text.split()[0][:10] if text else ''
                    if cmd:
                        return f"[{cmd}]"
            
            # MDNS/SSDP/LLMNR - discovery protocols
            if app_proto in ('MDNS', 'SSDP', 'LLMNR', 'NetBIOS'):
                return "[Discovery/Broadcast]"
            
            # SMB
            if app_proto == 'SMB':
                return "[SMB Session]"
            
            # Database protocols
            if app_proto in ('MySQL', 'PostgreSQL', 'MSSQL', 'Oracle', 'MongoDB', 'Redis'):
                return "[Database Query]"
            
            # RDP
            if app_proto == 'RDP':
                return "[Remote Desktop]"
            
            # VPN protocols
            if app_proto in ('OpenVPN', 'IKE'):
                return "[VPN Tunnel]"
            
            # NTP
            if app_proto == 'NTP':
                return "[Time Sync]"
            
            # SNMP
            if app_proto == 'SNMP':
                return "[SNMP Request]"
            
            # Kerberos
            if app_proto == 'Kerberos':
                return "[Authentication]"
            
            # LDAP
            if app_proto == 'LDAP':
                return "[Directory Query]"
            
            # SIP
            if app_proto == 'SIP':
                if text.startswith('SIP/') or text.startswith('INVITE') or text.startswith('REGISTER'):
                    method = text.split()[0]
                    return f"[{method}]"
                return "[VoIP Signaling]"
            
            # Syslog
            if app_proto == 'Syslog':
                return "[Log Message]"
            
            # Generic - show payload length
            if len(payload) > 0:
                return f"[{len(payload)} bytes]"
            
            return None
        except:
            return None

    @staticmethod
    def _get_dns_info(packet):
        """Extract DNS query/response info for main table."""
        if DNS not in packet:
            return None
        try:
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                if dns.qdcount > 0 and hasattr(dns, 'qd') and dns.qd:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='replace')
                    return f"Query: {qname}"
            else:  # Response
                if dns.qdcount > 0 and hasattr(dns, 'qd') and dns.qd:
                    qname = dns.qd.qname
                    if isinstance(qname, bytes):
                        qname = qname.decode('utf-8', errors='replace')
                    if dns.ancount > 0 and hasattr(dns, 'an') and dns.an:
                        try:
                            rdata = str(dns.an[0].rdata)
                            return f"Response: {qname} → {rdata}"
                        except:
                            pass
                    return f"Response: {qname}"
            return None
        except:
            return None

    @staticmethod
    def _get_tls_info(packet, sport, dport):
        """Extract TLS SNI or handshake info for main table."""
        if Raw not in packet:
            return None
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 6:
                return None
            
            # Get TLS version from record layer
            version_map = {
                (3, 0): 'SSLv3',
                (3, 1): 'TLSv1.0',
                (3, 2): 'TLSv1.1',
                (3, 3): 'TLSv1.2',
                (3, 4): 'TLSv1.3'
            }
            major, minor = payload[1], payload[2]
            tls_ver = version_map.get((major, minor), 'TLS')
            
            if payload[0] == 22:  # Handshake
                hs_type = payload[5]
                
                # For Client Hello, try to get version from handshake layer
                if hs_type == 1 and len(payload) > 10:
                    h_major, h_minor = payload[9], payload[10]
                    tls_ver = version_map.get((h_major, h_minor), tls_ver)
                    sni = PacketParser._extract_sni(payload)
                    if sni:
                        return f"[{tls_ver}] Client Hello → {sni}"
                    return f"[{tls_ver}] Client Hello"
                elif hs_type == 2:
                    return f"[{tls_ver}] Server Hello"
                elif hs_type == 11:
                    return f"[{tls_ver}] Certificate"
                else:
                    return f"[{tls_ver}] Handshake Type {hs_type}"
            elif payload[0] == 23:  # Application Data
                length = struct.unpack('!H', payload[3:5])[0] if len(payload) >= 5 else 0
                return f"[{tls_ver}] Application Data ({length} bytes)"
            elif payload[0] == 21:  # Alert
                return f"[{tls_ver}] Alert"
            return None
        except:
            return None

    @staticmethod
    def _extract_sni(payload):
        """Extract SNI from TLS Client Hello."""
        try:
            if len(payload) < 50:
                return None
            pos = 5 + 4 + 2 + 32  # Skip headers to session ID
            session_len = payload[pos]
            pos += 1 + session_len
            if pos + 2 > len(payload):
                return None
            cipher_len = struct.unpack('!H', payload[pos:pos+2])[0]
            pos += 2 + cipher_len
            if pos + 1 > len(payload):
                return None
            comp_len = payload[pos]
            pos += 1 + comp_len
            if pos + 2 > len(payload):
                return None
            ext_len = struct.unpack('!H', payload[pos:pos+2])[0]
            pos += 2
            ext_end = pos + ext_len
            while pos + 4 < ext_end and pos + 4 < len(payload):
                ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
                ext_data_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
                pos += 4
                if ext_type == 0:  # SNI
                    if pos + 5 < len(payload):
                        name_len = struct.unpack('!H', payload[pos+3:pos+5])[0]
                        if pos + 5 + name_len <= len(payload):
                            return payload[pos+5:pos+5+name_len].decode('utf-8', errors='replace')
                    break
                pos += ext_data_len
            return None
        except:
            return None

    @staticmethod
    def _get_tls_details(packet):
        """Extract TLS version from handshake."""
        if Raw not in packet:
            return None
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 6:
                return None
                
            # Content Type 22 = Handshake
            if payload[0] == 22:
                # TLS Record Version (payload[1:3]) - often 0x0301 (TLS 1.0) for compatibility
                # We need Client Hello version or Supported Versions extension
                
                # Simple check for Record Layer version first
                major, minor = payload[1], payload[2]
                version_map = {
                    (3, 0): 'SSLv3',
                    (3, 1): 'TLSv1.0',
                    (3, 2): 'TLSv1.1',
                    (3, 3): 'TLSv1.2',
                    (3, 4): 'TLSv1.3'
                }
                
                # Try to find Handshake Version (Client Hello)
                # Handshake Type (1 byte) + Length (3 bytes) + Version (2 bytes)
                if payload[5] == 1: # Client Hello
                     h_major, h_minor = payload[9], payload[10]
                     return version_map.get((h_major, h_minor), 'TLS')
                
                return version_map.get((major, minor), 'TLS')
            
            return None
        except:
            return None

    @staticmethod
    def _get_application_action(packet, sport, dport):
        """Detect the application-level action/request type."""
        if Raw not in packet:
            # Check for DNS without Raw
            if DNS in packet:
                dns = packet[DNS]
                return 'DNS Response' if dns.qr else 'DNS Query'
            return None
            
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 3:
                return None
                
            # HTTP Methods
            text_start = payload[:10].decode('utf-8', errors='ignore').upper()
            if text_start.startswith('GET '):
                return 'HTTP GET Request'
            elif text_start.startswith('POST '):
                return 'HTTP POST Request'
            elif text_start.startswith('PUT '):
                return 'HTTP PUT Request'
            elif text_start.startswith('DELETE '):
                return 'HTTP DELETE Request'
            elif text_start.startswith('HEAD '):
                return 'HTTP HEAD Request'
            elif text_start.startswith('OPTIONS '):
                return 'HTTP OPTIONS Request'
            elif text_start.startswith('PATCH '):
                return 'HTTP PATCH Request'
            elif text_start.startswith('HTTP/'):
                return 'HTTP Response'
            
            # DNS
            if sport == 53 or dport == 53:
                if DNS in packet:
                    dns = packet[DNS]
                    return 'DNS Response' if dns.qr else 'DNS Query'
            
            # FTP Commands
            if sport == 21 or dport == 21:
                ftp_cmds = ['USER', 'PASS', 'LIST', 'RETR', 'STOR', 'QUIT', 'CWD', 'PWD', 'PORT', 'PASV']
                for cmd in ftp_cmds:
                    if text_start.startswith(cmd):
                        return f'FTP {cmd} Command'
                if payload[:3].isdigit():
                    return 'FTP Response'
            
            # SMTP Commands
            if sport == 25 or dport == 25 or sport == 587 or dport == 587:
                smtp_cmds = ['HELO', 'EHLO', 'MAIL', 'RCPT', 'DATA', 'QUIT', 'AUTH']
                for cmd in smtp_cmds:
                    if text_start.startswith(cmd):
                        return f'SMTP {cmd} Command'
                if payload[:3].isdigit():
                    return 'SMTP Response'
            
            # TLS Handshake
            if len(payload) >= 6 and payload[0] == 22:  # Handshake
                hs_type = payload[5]
                hs_names = {1: 'Client Hello', 2: 'Server Hello', 11: 'Certificate', 12: 'Server Key Exchange', 16: 'Client Key Exchange'}
                return f'TLS Handshake ({hs_names.get(hs_type, "Type " + str(hs_type))})'
            
            # TLS Application Data
            if len(payload) >= 3 and payload[0] == 23:
                return 'TLS Application Data (Encrypted)'
            
            return None
        except:
            return None

    @staticmethod
    def get_protocol_name(proto_num):
        """Get protocol name from IP protocol number."""
        return {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP'}.get(proto_num, 'Unknown')

    @staticmethod
    def get_icmp_type(icmp_type):
        """Get ICMP type name."""
        return {0: 'Echo Reply', 3: 'Destination Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}.get(icmp_type, 'Unknown')

    @staticmethod
    def get_arp_op(op):
        """Get ARP operation name."""
        return {1: 'Request', 2: 'Reply'}.get(op, 'Unknown')

    @staticmethod
    def parse_tcp_flags(flags):
        """Parse TCP flags to human-readable format."""
        flag_list = []
        if flags & 0x01:
            flag_list.append('FIN')
        if flags & 0x02:
            flag_list.append('SYN')
        if flags & 0x04:
            flag_list.append('RST')
        if flags & 0x08:
            flag_list.append('PSH')
        if flags & 0x10:
            flag_list.append('ACK')
        if flags & 0x20:
            flag_list.append('URG')
        return ', '.join(flag_list) if flag_list else 'None'

    @staticmethod
    @staticmethod
    def get_packet_details(packet, packet_index):
        """Get detailed packet information for all OSI layers."""
        details = []
        
        # Extract device names first
        hostname_resolver = get_hostname_resolver()
        extracted_hostnames = hostname_resolver.extract_hostnames_from_packet(packet)
        
        # === Layer 1: Physical ===
        details.append(['=== Layer 1: Physical (Frame) ===', ''])
        details.append(['Frame Number', packet_index + 1])
        details.append(['Frame Length', f"{len(packet)} bytes"])
        details.append(['Capture Length', f"{len(packet)} bytes"])

        # === Layer 2: Data Link ===
        if Ether in packet:
            details.append(['=== Layer 2: Data Link (Ethernet II) ===', ''])
            details.append(['Destination MAC', packet[Ether].dst])
            details.append(['Source MAC', packet[Ether].src])
            
            # Show device names for MACs if available
            hostname_by_src_mac = hostname_resolver.get_hostname_by_mac(packet[Ether].src)
            hostname_by_dst_mac = hostname_resolver.get_hostname_by_mac(packet[Ether].dst)
            if hostname_by_src_mac:
                details.append(['Source Device Name', hostname_by_src_mac])
            if hostname_by_dst_mac:
                details.append(['Destination Device Name', hostname_by_dst_mac])
            
            ether_type = packet[Ether].type
            ETHER_TYPE_NAMES = {
                0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6',
                0x8100: 'VLAN (802.1Q)', 0x88CC: 'LLDP', 0x8892: 'PROFINET'
            }
            type_name = ETHER_TYPE_NAMES.get(ether_type, '')
            if type_name:
                details.append(['EtherType', f"0x{ether_type:04x} ({type_name})"])
            else:
                details.append(['EtherType', f"0x{ether_type:04x}"])
            
            # Calculate Frame Check Sequence (FCS) - CRC32
            raw_bytes = bytes(packet)
            if len(raw_bytes) >= 14:
                fcs = binascii.crc32(raw_bytes) & 0xffffffff
                details.append(['Frame Check Sequence (FCS)', f"0x{fcs:08x}"])

        # === Layer 3: Network ===
        if IP in packet:
            details.append(['=== Layer 3: Network (IPv4) ===', ''])
            details.append(['Version', packet[IP].version])
            details.append(['Header Length', f"{packet[IP].ihl * 4} bytes"])
            details.append(['TOS/DSCP', f"0x{packet[IP].tos:02x}"])
            details.append(['Total Length', f"{packet[IP].len} bytes"])
            details.append(['Identification', f"0x{packet[IP].id:04x}"])
            details.append(['Flags', str(packet[IP].flags)])
            details.append(['Fragment Offset', packet[IP].frag])
            details.append(['TTL', packet[IP].ttl])
            details.append(['Protocol', f"{packet[IP].proto} ({PacketParser.get_protocol_name(packet[IP].proto)})"])
            details.append(['Checksum', f"0x{packet[IP].chksum:04x}"])
            details.append(['Source IP', packet[IP].src])
            
            # Show device name for source IP if available
            src_device = hostname_resolver.get_hostname(packet[IP].src)
            if src_device:
                details.append(['Source Device', src_device])
            
            details.append(['Destination IP', packet[IP].dst])
            
            # Show device name for destination IP if available
            dst_device = hostname_resolver.get_hostname(packet[IP].dst)
            if dst_device:
                details.append(['Destination Device', dst_device])

        if IPv6 in packet:
            details.append(['=== Layer 3: Network (IPv6) ===', ''])
            details.append(['Version', packet[IPv6].version])
            details.append(['Traffic Class', f"0x{packet[IPv6].tc:02x}"])
            details.append(['Flow Label', f"0x{packet[IPv6].fl:05x}"])
            details.append(['Payload Length', f"{packet[IPv6].plen} bytes"])
            details.append(['Next Header', f"{packet[IPv6].nh}"])
            details.append(['Hop Limit', packet[IPv6].hlim])
            details.append(['Source IP', packet[IPv6].src])
            
            # Show device name for source IP if available
            src_device = hostname_resolver.get_hostname(packet[IPv6].src)
            if src_device:
                details.append(['Source Device', src_device])
            
            details.append(['Destination IP', packet[IPv6].dst])
            
            # Show device name for destination IP if available
            dst_device = hostname_resolver.get_hostname(packet[IPv6].dst)
            if dst_device:
                details.append(['Destination Device', dst_device])
            details.append(['Next Header', f"{packet[IPv6].nh}"])
            details.append(['Hop Limit', packet[IPv6].hlim])
            details.append(['Source IP', packet[IPv6].src])
            details.append(['Destination IP', packet[IPv6].dst])

        if ARP in packet:
            details.append(['=== Layer 3: Network (ARP) ===', ''])
            details.append(['Hardware Type', f"{packet[ARP].hwtype} (Ethernet)"])
            details.append(['Protocol Type', f"0x{packet[ARP].ptype:04x} (IPv4)"])
            details.append(['Operation', f"{packet[ARP].op} ({PacketParser.get_arp_op(packet[ARP].op)})"])
            details.append(['Sender MAC', packet[ARP].hwsrc])
            details.append(['Sender IP', packet[ARP].psrc])
            details.append(['Target MAC', packet[ARP].hwdst])
            details.append(['Target IP', packet[ARP].pdst])

        # === Layer 4: Transport ===
        sport = dport = 0
        if TCP in packet:
            sport, dport = packet[TCP].sport, packet[TCP].dport
            details.append(['=== Layer 4: Transport (TCP) ===', ''])
            details.append(['Source Port', sport])
            details.append(['Destination Port', dport])
            details.append(['Sequence Number', packet[TCP].seq])
            details.append(['Acknowledgment', packet[TCP].ack])
            details.append(['Header Length', f"{packet[TCP].dataofs * 4} bytes"])
            details.append(['Flags', PacketParser.parse_tcp_flags(packet[TCP].flags)])
            details.append(['Window Size', packet[TCP].window])
            details.append(['Checksum', f"0x{packet[TCP].chksum:04x}"])
            details.append(['Urgent Pointer', packet[TCP].urgptr])
            if packet[TCP].options:
                details.append(['Options', str(packet[TCP].options)])
        elif UDP in packet:
            sport, dport = packet[UDP].sport, packet[UDP].dport
            details.append(['=== Layer 4: Transport (UDP) ===', ''])
            details.append(['Source Port', sport])
            details.append(['Destination Port', dport])
            details.append(['Length', f"{packet[UDP].len} bytes"])
            details.append(['Checksum', f"0x{packet[UDP].chksum:04x}"])
        elif ICMP in packet:
            details.append(['=== Layer 4: Transport (ICMP) ===', ''])
            details.append(['Type', f"{packet[ICMP].type} ({PacketParser.get_icmp_type(packet[ICMP].type)})"])
            details.append(['Code', packet[ICMP].code])
            details.append(['Checksum', f"0x{packet[ICMP].chksum:04x}"])
            if hasattr(packet[ICMP], 'id'):
                details.append(['Identifier', packet[ICMP].id])
            if hasattr(packet[ICMP], 'seq'):
                details.append(['Sequence', packet[ICMP].seq])

        # === Layer 5: Session ===
        details.append(['=== Layer 5: Session ===', ''])
        if TCP in packet:
            flags = packet[TCP].flags
            details.append(['Session Type', 'TCP (Connection-Oriented)'])
            if flags & 0x02 and not (flags & 0x10):
                details.append(['Session State', 'SYN_SENT - Initiating connection'])
                details.append(['Dialog Control', 'Half-Open (Awaiting SYN-ACK)'])
            elif flags & 0x02 and flags & 0x10:
                details.append(['Session State', 'SYN_RECEIVED - Responding'])
                details.append(['Dialog Control', 'Half-Open (Sent SYN-ACK)'])
            elif flags & 0x01:
                details.append(['Session State', 'FIN_WAIT - Terminating'])
                details.append(['Dialog Control', 'Closing session'])
            elif flags & 0x04:
                details.append(['Session State', 'RESET - Connection aborted'])
                details.append(['Dialog Control', 'Session terminated abnormally'])
            else:
                details.append(['Session State', 'ESTABLISHED - Active'])
                details.append(['Dialog Control', 'Full-Duplex communication'])
            details.append(['Synchronization', f"SEQ={packet[TCP].seq}, ACK={packet[TCP].ack}"])
        elif UDP in packet:
            details.append(['Session Type', 'UDP (Connectionless)'])
            details.append(['Session State', 'Stateless - No session management'])
            details.append(['Dialog Control', 'Simplex/Datagram mode'])
            details.append(['Synchronization', 'N/A (Unreliable delivery)'])
        else:
            details.append(['Session Type', 'N/A'])
            details.append(['Session State', 'No transport layer detected'])
        
        # Application Action (Request Type)
        app_action = PacketParser._get_application_action(packet, sport, dport)
        if app_action:
            details.append(['Application Action', app_action])

        # === Layer 6: Presentation ===
        details.append(['=== Layer 6: Presentation ===', ''])
        
        is_encrypted = sport in (443, 8443, 22, 993, 995, 465) or dport in (443, 8443, 22, 993, 995, 465)
        
        if is_encrypted:
            if sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
                details.append(['Encryption', 'TLS/SSL'])
                if Raw in packet:
                    payload = bytes(packet[Raw].load)
                    if len(payload) >= 5:
                        version = struct.unpack('!H', payload[1:3])[0]
                        ver_name = TLS_VERSIONS.get(version, f'0x{version:04x}')
                        details.append(['TLS Version', ver_name])
                        content_type = payload[0]
                        ct_name = TLS_CONTENT_TYPES.get(content_type, f'{content_type}')
                        details.append(['Content Type', ct_name])
            elif sport == 22 or dport == 22:
                details.append(['Encryption', 'SSH Protocol'])
            else:
                details.append(['Encryption', 'TLS (Secure Port)'])
            details.append(['Data Format', 'Encrypted Binary'])
            details.append(['Compression', 'N/A (Encrypted)'])
        else:
            details.append(['Encryption', 'None (Plaintext)'])
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                # Detect format
                fmt = 'Binary'
                if payload[:5] == b'<?xml' or payload[:6] == b'<?XML ':
                    fmt = 'XML'
                elif payload[:1] in (b'{', b'['):
                    fmt = 'JSON'
                elif payload[:5] == b'<!DOC' or payload[:6].lower() == b'<html>':
                    fmt = 'HTML'
                elif payload[:4] == b'POST':
                    fmt = 'HTTP POST Data'
                elif payload[:3] in (b'GET', b'PUT', b'DEL', b'HEA', b'OPT', b'PAT'):
                    fmt = 'HTTP Request'
                elif payload[:4] == b'HTTP':
                    fmt = 'HTTP Response'
                elif all(32 <= b < 127 or b in (9, 10, 13) for b in payload[:50]):
                    fmt = 'ASCII Text'
                details.append(['Data Format', fmt])
                
                # Compression detection
                comp = 'None'
                if payload[:2] == b'\x1f\x8b':
                    comp = 'GZIP'
                elif payload[:4] == b'PK\x03\x04':
                    comp = 'ZIP'
                elif payload[:3] == b'BZh':
                    comp = 'BZIP2'
                details.append(['Compression', comp])
                
                # Encoding detection
                enc = 'ASCII'
                if payload[:3] == b'\xef\xbb\xbf':
                    enc = 'UTF-8 (BOM)'
                elif payload[:2] == b'\xff\xfe':
                    enc = 'UTF-16 LE'
                elif payload[:2] == b'\xfe\xff':
                    enc = 'UTF-16 BE'
                else:
                    try:
                        payload[:100].decode('utf-8')
                        enc = 'UTF-8'
                    except:
                        enc = 'Binary/Unknown'
                details.append(['Character Encoding', enc])
            else:
                details.append(['Data Format', 'No payload'])

        # === Layer 7: Application ===
        details.append(['=== Layer 7: Application ===', ''])
        app_proto = PacketParser._detect_app_protocol(packet, sport, dport) or 'Unknown'
        if app_proto != 'Unknown':
            details.append(['Protocol', app_proto])
        port_info = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport)
        if port_info:
            details.append(['Service', port_info])
        
        # Protocol-specific parsing using external parsers
        if DNS in packet or sport == 53 or dport == 53:
            parse_dns_app(packet, details)
        elif sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            parse_http_app(packet, details)
        elif sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            parse_tls_app(packet, details)
        elif sport in (67, 68) or dport in (67, 68):
            parse_dhcp_app(packet, details)
        elif sport == 21 or dport == 21:
            parse_ftp_app(packet, details)
        elif sport == 25 or dport == 25 or sport == 587 or dport == 587 or sport == 465 or dport == 465:
            parse_smtp_app(packet, details)
        elif sport == 22 or dport == 22:
            parse_ssh_app(packet, details)
        elif sport == 110 or dport == 110 or sport == 995 or dport == 995:
            parse_pop3_app(packet, details)
        elif sport == 143 or dport == 143 or sport == 993 or dport == 993:
            parse_imap_app(packet, details)
        elif sport == 123 or dport == 123:
            parse_ntp_app(packet, details)
        elif sport == 161 or dport == 161 or sport == 162 or dport == 162:
            parse_snmp_app(packet, details)
        elif sport == 23 or dport == 23:
            parse_telnet_app(packet, details)
        elif Raw in packet:
            parse_raw_data(packet, details)
        
        return details