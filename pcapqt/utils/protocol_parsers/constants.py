# -*- coding: utf-8 -*-
"""Protocol constants and mappings for packet parsing."""

# Common application layer ports
WELL_KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP',
    80: 'HTTP', 110: 'POP3', 119: 'NNTP', 123: 'NTP', 143: 'IMAP',
    161: 'SNMP', 162: 'SNMP-Trap', 443: 'HTTPS', 465: 'SMTPS',
    587: 'SMTP-Submission', 993: 'IMAPS', 995: 'POP3S',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB',
    3490: 'Gocator', 54915: 'Lmnart'
}

# Protocol to port mapping for filtering
PROTOCOL_PORTS = {
    'ssh': [22],
    'ftp': [20, 21],
    'http': [80, 8080],
    'https': [443, 8443],
    'tls': [443, 8443],
    'dns': [53],
    'smtp': [25, 465, 587],
    'pop3': [110, 995],
    'imap': [143, 993],
    'telnet': [23],
    'ntp': [123],
    'snmp': [161, 162],
    'dhcp': [67, 68],
    'mysql': [3306],
    'rdp': [3389],
}

# EtherType to protocol name mapping
ETHER_TYPES = {
    0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6',
    0x8100: 'VLAN', 0x88CC: 'LLDP', 0x8892: 'PROFINET',
    0x88A8: 'QinQ', 0x8863: 'PPPoE-Discovery', 0x8864: 'PPPoE-Session'
}

# DNS record types
DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 255: 'ANY'
}

# DNS response codes
DNS_RCODES = {
    0: 'No Error', 1: 'Format Error', 2: 'Server Failure',
    3: 'Name Error (NXDOMAIN)', 4: 'Not Implemented', 5: 'Refused'
}

# DHCP message types
DHCP_TYPES = {
    1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE',
    5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM'
}

# TLS version mappings
TLS_VERSIONS = {
    0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1',
    0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3'
}

# TLS content types
TLS_CONTENT_TYPES = {
    20: 'Change Cipher Spec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data'
}

# TLS handshake message types
TLS_HANDSHAKE_TYPES = {
    0: 'HelloRequest', 1: 'ClientHello', 2: 'ServerHello',
    4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange',
    13: 'CertificateRequest', 14: 'ServerHelloDone', 15: 'CertificateVerify',
    16: 'ClientKeyExchange', 20: 'Finished'
}
