from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw, DNS, DNSQR, DNSRR
from datetime import datetime
import struct


class PacketParser:
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
    
    # Common application layer ports
    WELL_KNOWN_PORTS = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP',
        80: 'HTTP', 110: 'POP3', 119: 'NNTP', 123: 'NTP', 143: 'IMAP',
        161: 'SNMP', 162: 'SNMP-Trap', 443: 'HTTPS', 465: 'SMTPS',
        587: 'SMTP-Submission', 993: 'IMAPS', 995: 'POP3S',
        3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
    }
    
    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
        16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 255: 'ANY'
    }
    
    DNS_RCODES = {
        0: 'No Error', 1: 'Format Error', 2: 'Server Failure',
        3: 'Name Error (NXDOMAIN)', 4: 'Not Implemented', 5: 'Refused'
    }
    
    DHCP_TYPES = {
        1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE',
        5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'
    }
    
    TLS_VERSIONS = {
        0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'
    }
    
    TLS_CONTENT_TYPES = {
        20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data'
    }
    
    TLS_HANDSHAKE_TYPES = {
        0: 'HelloRequest', 1: 'ClientHello', 2: 'ServerHello',
        4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange',
        13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify',
        16: 'ClientKeyExchange', 20: 'Finished'
    }
    
    @staticmethod
    def parse_packet(packet, packet_count, start_time):
        info = {
            'no': packet_count,
            'time': (datetime.now() - start_time).total_seconds(),
            'src': 'Unknown', 'dst': 'Unknown',
            'protocol': 'Unknown', 'length': len(packet), 'info': ''
        }

        if Ether in packet:
            info['src'] = packet[Ether].src
            info['dst'] = packet[Ether].dst

        if IP in packet:
            info['src'] = packet[IP].src
            info['dst'] = packet[IP].dst
            info['protocol'] = packet[IP].proto

            if TCP in packet:
                sport, dport = packet[TCP].sport, packet[TCP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                info['protocol'] = app_proto if app_proto else 'TCP'
                info['info'] = f"{sport} → {dport} [Flags: {packet[TCP].flags}]"
            elif UDP in packet:
                sport, dport = packet[UDP].sport, packet[UDP].dport
                app_proto = PacketParser._detect_app_protocol(packet, sport, dport)
                info['protocol'] = app_proto if app_proto else 'UDP'
                info['info'] = f"{sport} → {dport}"
            elif ICMP in packet:
                info['protocol'] = 'ICMP'
                info['info'] = f"Type: {packet[ICMP].type}"
        elif ARP in packet:
            info['protocol'] = 'ARP'
            info['src'] = packet[ARP].psrc
            info['dst'] = packet[ARP].pdst
            info['info'] = f"Who has {packet[ARP].pdst}? Tell {packet[ARP].psrc}"

        return info

    @staticmethod
    def _detect_app_protocol(packet, sport, dport):
        if sport == 53 or dport == 53: return 'DNS'
        if sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            if Raw in packet and PacketParser._is_http(bytes(packet[Raw].load)):
                return 'HTTP'
        if sport == 443 or dport == 443 or sport == 8443 or dport == 8443: return 'TLS'
        if sport in (67, 68) or dport in (67, 68): return 'DHCP'
        if sport == 21 or dport == 21: return 'FTP'
        if sport == 20 or dport == 20: return 'FTP-Data'
        if sport == 25 or dport == 25 or sport == 587 or dport == 587: return 'SMTP'
        if sport == 22 or dport == 22: return 'SSH'
        if sport == 110 or dport == 110 or sport == 995 or dport == 995: return 'POP3'
        if sport == 143 or dport == 143 or sport == 993 or dport == 993: return 'IMAP'
        if sport == 123 or dport == 123: return 'NTP'
        if sport == 161 or dport == 161 or sport == 162 or dport == 162: return 'SNMP'
        if sport == 23 or dport == 23: return 'Telnet'
        return None

    @staticmethod
    def _is_http(payload):
        if not payload: return False
        try:
            text = payload[:20].decode('utf-8', errors='ignore').upper()
            return any(text.startswith(m) for m in ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'HTTP/'])
        except: return False

    @staticmethod
    def get_protocol_name(proto_num):
        return {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto_num, 'Unknown')

    @staticmethod
    def get_icmp_type(icmp_type):
        return {0: 'Echo Reply', 3: 'Destination Unreachable', 8: 'Echo Request', 11: 'Time Exceeded'}.get(icmp_type, 'Unknown')

    @staticmethod
    def get_arp_op(op):
        return {1: 'Request', 2: 'Reply'}.get(op, 'Unknown')

    @staticmethod
    def parse_tcp_flags(flags):
        flag_list = []
        if flags & 0x01: flag_list.append('FIN')
        if flags & 0x02: flag_list.append('SYN')
        if flags & 0x04: flag_list.append('RST')
        if flags & 0x08: flag_list.append('PSH')
        if flags & 0x10: flag_list.append('ACK')
        if flags & 0x20: flag_list.append('URG')
        return ', '.join(flag_list) if flag_list else 'None'

    @staticmethod
    def get_packet_details(packet, packet_index):
        details = []
        
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
            details.append(['EtherType', f"{hex(packet[Ether].type)}"])

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
            details.append(['Destination IP', packet[IP].dst])

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
            if hasattr(packet[ICMP], 'id'): details.append(['Identifier', packet[ICMP].id])
            if hasattr(packet[ICMP], 'seq'): details.append(['Sequence', packet[ICMP].seq])

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
                        ver_name = PacketParser.TLS_VERSIONS.get(version, f'0x{version:04x}')
                        details.append(['TLS Version', ver_name])
                        content_type = payload[0]
                        ct_name = PacketParser.TLS_CONTENT_TYPES.get(content_type, f'{content_type}')
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
                elif payload[:4] == b'HTTP' or payload[:3] in (b'GET', b'POS', b'PUT', b'DEL'):
                    fmt = 'HTTP Text'
                elif all(32 <= b < 127 or b in (9, 10, 13) for b in payload[:50]):
                    fmt = 'ASCII Text'
                details.append(['Data Format', fmt])
                
                # Compression detection
                comp = 'None'
                if payload[:2] == b'\x1f\x8b': comp = 'GZIP'
                elif payload[:4] == b'PK\x03\x04': comp = 'ZIP'
                elif payload[:3] == b'BZh': comp = 'BZIP2'
                details.append(['Compression', comp])
                
                # Encoding detection
                enc = 'ASCII'
                if payload[:3] == b'\xef\xbb\xbf': enc = 'UTF-8 (BOM)'
                elif payload[:2] == b'\xff\xfe': enc = 'UTF-16 LE'
                elif payload[:2] == b'\xfe\xff': enc = 'UTF-16 BE'
                else:
                    try:
                        payload[:100].decode('utf-8')
                        enc = 'UTF-8'
                    except: enc = 'Binary/Unknown'
                details.append(['Character Encoding', enc])
            else:
                details.append(['Data Format', 'No payload'])

        # === Layer 7: Application ===
        details.append(['=== Layer 7: Application ===', ''])
        app_proto = PacketParser._detect_app_protocol(packet, sport, dport) or 'Unknown'
        details.append(['Protocol', app_proto])
        port_info = PacketParser.WELL_KNOWN_PORTS.get(dport) or PacketParser.WELL_KNOWN_PORTS.get(sport)
        if port_info:
            details.append(['Service', port_info])
        
        # Protocol-specific parsing
        if DNS in packet or sport == 53 or dport == 53:
            PacketParser._parse_dns_app(packet, details)
        elif sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
            PacketParser._parse_http_app(packet, details)
        elif sport == 443 or dport == 443 or sport == 8443 or dport == 8443:
            PacketParser._parse_tls_app(packet, details)
        elif sport in (67, 68) or dport in (67, 68):
            PacketParser._parse_dhcp_app(packet, details)
        elif sport == 21 or dport == 21:
            PacketParser._parse_ftp_app(packet, details)
        elif sport == 25 or dport == 25 or sport == 587 or dport == 587:
            PacketParser._parse_smtp_app(packet, details)
        elif sport == 22 or dport == 22:
            PacketParser._parse_ssh_app(packet, details)
        elif Raw in packet:
            PacketParser._parse_raw_data(packet, details)
        
        return details

    @staticmethod
    def _parse_dns_app(packet, details):
        if DNS in packet:
            dns = packet[DNS]
            qr = 'Response' if dns.qr else 'Query'
            details.append(['DNS Type', qr])
            details.append(['Transaction ID', f"0x{dns.id:04x}"])
            if dns.qdcount > 0 and DNSQR in packet:
                qname = packet[DNSQR].qname.decode() if isinstance(packet[DNSQR].qname, bytes) else str(packet[DNSQR].qname)
                qtype = PacketParser.DNS_TYPES.get(packet[DNSQR].qtype, str(packet[DNSQR].qtype))
                details.append(['Query', f"{qname} ({qtype})"])
            if dns.qr and dns.ancount > 0:
                details.append(['Answers', dns.ancount])
                if DNSRR in packet:
                    try:
                        rr = dns.an[0] if hasattr(dns, 'an') else None
                        if rr and hasattr(rr, 'rdata'):
                            details.append(['First Answer', str(rr.rdata)])
                    except: pass
            details.append(['Response Code', PacketParser.DNS_RCODES.get(dns.rcode, str(dns.rcode))])

    @staticmethod
    def _parse_http_app(packet, details):
        if Raw not in packet: return
        try:
            payload = bytes(packet[Raw].load)
            text = payload.decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            if not lines: return
            first = lines[0]
            if first.startswith('HTTP/'):
                parts = first.split(' ', 2)
                details.append(['HTTP Response', f"{parts[1]} {parts[2] if len(parts)>2 else ''}"])
            else:
                parts = first.split(' ')
                details.append(['HTTP Request', f"{parts[0]} {parts[1][:50] if len(parts)>1 else ''}"])
            # Show key headers
            for line in lines[1:6]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    if k.strip().lower() in ('host', 'content-type', 'content-length', 'user-agent'):
                        details.append([k.strip(), v.strip()[:60]])
        except: pass

    @staticmethod
    def _parse_tls_app(packet, details):
        if Raw not in packet:
            details.append(['TLS Status', 'Encrypted (no visible payload)'])
            return
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 6: return
            content_type = payload[0]
            if content_type == 22:  # Handshake
                hs_type = payload[5]
                hs_name = PacketParser.TLS_HANDSHAKE_TYPES.get(hs_type, f'Type {hs_type}')
                details.append(['TLS Handshake', hs_name])
            elif content_type == 23:
                length = struct.unpack('!H', payload[3:5])[0]
                details.append(['Encrypted Data', f'{length} bytes'])
            elif content_type == 21:
                details.append(['TLS Alert', 'Alert message'])
        except: pass

    @staticmethod
    def _parse_dhcp_app(packet, details):
        if Raw not in packet: return
        try:
            payload = bytes(packet[Raw].load)
            if len(payload) < 240: return
            op = 'Request' if payload[0] == 1 else 'Reply' if payload[0] == 2 else 'Unknown'
            details.append(['DHCP Message', op])
            xid = struct.unpack('!I', payload[4:8])[0]
            details.append(['Transaction ID', f'0x{xid:08x}'])
            yiaddr = '.'.join(str(b) for b in payload[16:20])
            if yiaddr != '0.0.0.0':
                details.append(['Offered IP', yiaddr])
            # Parse DHCP message type option
            if len(payload) > 240 and payload[236:240] == b'\x63\x82\x53\x63':
                i = 240
                while i < len(payload) and payload[i] != 255:
                    if payload[i] == 0: i += 1; continue
                    opt_code, opt_len = payload[i], payload[i+1]
                    if opt_code == 53 and opt_len >= 1:
                        msg_type = PacketParser.DHCP_TYPES.get(payload[i+2], f'Type {payload[i+2]}')
                        details.append(['DHCP Type', msg_type])
                        break
                    i += 2 + opt_len
        except: pass

    @staticmethod
    def _parse_ftp_app(packet, details):
        if Raw not in packet: return
        try:
            text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
            lines = text.split('\r\n')
            for line in lines[:3]:
                if line[:3].isdigit():
                    details.append(['FTP Response', line[:80]])
                else:
                    parts = line.split(' ', 1)
                    details.append(['FTP Command', f"{parts[0]} {parts[1][:50] if len(parts)>1 else ''}"])
        except: pass

    @staticmethod
    def _parse_smtp_app(packet, details):
        if Raw not in packet: return
        try:
            text = bytes(packet[Raw].load).decode('utf-8', errors='replace').strip()
            lines = text.split('\r\n')
            for line in lines[:3]:
                if line[:3].isdigit():
                    details.append(['SMTP Response', line[:80]])
                else:
                    parts = line.split(' ', 1)
                    cmd = parts[0].upper()
                    arg = parts[1][:50] if len(parts) > 1 else ''
                    details.append(['SMTP Command', f"{cmd} {arg}"])
        except: pass

    @staticmethod
    def _parse_ssh_app(packet, details):
        if Raw not in packet:
            details.append(['SSH Status', 'Encrypted session'])
            return
        try:
            payload = bytes(packet[Raw].load)
            if payload.startswith(b'SSH-'):
                text = payload.decode('utf-8', errors='replace')
                version_line = text.split('\n')[0].strip()
                details.append(['SSH Version', version_line])
            else:
                details.append(['SSH Status', 'Encrypted packet'])
        except: pass

    @staticmethod
    def _parse_raw_data(packet, details):
        if Raw not in packet: return
        raw_data = bytes(packet[Raw].load)
        details.append(['--- Raw Data ---', ''])
        details.append(['Payload Length', f"{len(raw_data)} bytes"])
        preview_len = min(64, len(raw_data))
        hex_preview = ' '.join(f"{b:02x}" for b in raw_data[:preview_len])
        if len(raw_data) > preview_len: hex_preview += '...'
        details.append(['Hex', hex_preview])
        ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw_data[:preview_len])
        if len(raw_data) > preview_len: ascii_preview += '...'
        details.append(['ASCII', ascii_preview])