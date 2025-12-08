# -*- coding: utf-8 -*-

from PyQt5.QtCore import Qt, QSortFilterProxyModel
import re


class PacketFilterModel(QSortFilterProxyModel):
    """
    Proxy model for filtering packet table.
    
    Optimized with:
        - Pre-compiled regex patterns for faster matching
        - Cached filter results to avoid recomputation
        - Direct data access instead of model.data() calls
    
    Supported filter syntax:
        - Protocol: tcp, udp, icmp, arp
        - Application protocols: ssh, dns, http, https, ftp, smtp, pop3, imap, telnet, ntp, snmp, dhcp, tls
        - IP filters: ip.src==192.168.1.1, ip.dst==10.0.0.1
        - Port filters: port==80, tcp.port==443, udp.port==53
        - Combined: tcp and port==80
        - Text search: any text to search in all columns
    """
    
    # Protocol to port mapping for filtering by protocol name
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
        'tftp': [69],
        'ldap': [389, 636],
        'redis': [6379],
        'mongodb': [27017],
        'postgresql': [5432],
    }
    
    # Pre-compiled regex patterns for common port lookups
    _port_regex_cache = {}
    
    # TCP-based protocols for quick lookup
    TCP_PROTOCOLS = frozenset(['ssh', 'http', 'https', 'ftp', 'smtp', 'pop3', 'imap', 'telnet', 'tls'])
    
    # UDP-based protocols for quick lookup
    UDP_PROTOCOLS = frozenset(['dns', 'dhcp', 'ntp', 'snmp', 'tftp'])
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.filter_expression = ""
        self.filter_tokens = []
        self._has_or_operator = False
        
        # Cache for filter results (row_index -> result)
        self._filter_cache = {}
        self._cache_valid = False
    
    def set_filter(self, expression):
        """Set the filter expression and invalidate the filter."""
        new_expression = expression.strip().lower()
        
        # Skip if expression hasn't changed
        if new_expression == self.filter_expression:
            return
        
        self.filter_expression = new_expression
        self.filter_tokens = self.parse_expression(self.filter_expression)
        self._has_or_operator = any(t[0] == 'operator' and t[1] == 'or' for t in self.filter_tokens)
        
        # Invalidate cache
        self._filter_cache.clear()
        self._cache_valid = False
        
        self.invalidateFilter()
    
    def invalidate_cache(self):
        """Invalidate the filter cache when source data changes."""
        self._filter_cache.clear()
        self._cache_valid = False
    
    @classmethod
    def _get_port_regex(cls, port):
        """Get or create compiled regex for port matching."""
        if port not in cls._port_regex_cache:
            cls._port_regex_cache[port] = re.compile(rf'\b{port}\b')
        return cls._port_regex_cache[port]
    
    def parse_expression(self, expression):
        """Parse filter expression into tokens."""
        if not expression:
            return []
        
        tokens = []
        
        # Split by 'and' / 'or' but keep them
        parts = re.split(r'\s+(and|or)\s+', expression)
        
        for part in parts:
            part = part.strip()
            if part in ('and', 'or'):
                tokens.append(('operator', part))
            elif part:
                tokens.append(self.parse_token(part))
        
        return tokens
    
    def parse_token(self, token):
        """Parse a single filter token."""
        token = token.strip()
        
        # Transport protocol filters
        if token in ('tcp', 'udp', 'icmp', 'arp'):
            return ('protocol', token.upper())
        
        # Application protocol filters (by port)
        if token in self.PROTOCOL_PORTS:
            return ('app_protocol', token)
        
        # IP source filter: ip.src==x.x.x.x
        match = re.match(r'ip\.src\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_src', match.group(1).strip())
        
        # IP destination filter: ip.dst==x.x.x.x
        match = re.match(r'ip\.dst\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_dst', match.group(1).strip())
        
        # IP filter (any): ip==x.x.x.x
        match = re.match(r'ip\s*[=:]+\s*(.+)', token)
        if match:
            return ('ip_any', match.group(1).strip())
        
        # TCP port filter: tcp.port==xxx
        match = re.match(r'tcp\.port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('tcp_port', int(match.group(1)))
        
        # UDP port filter: udp.port==xxx
        match = re.match(r'udp\.port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('udp_port', int(match.group(1)))
        
        # Generic port filter: port==xxx
        match = re.match(r'port\s*[=:]+\s*(\d+)', token)
        if match:
            return ('port', int(match.group(1)))
        
        # Text search (fallback)
        return ('text', token)
    
    def filterAcceptsRow(self, source_row, source_parent):
        """Determine if row should be shown based on filter."""
        if not self.filter_tokens:
            return True
        
        # Check cache first
        if source_row in self._filter_cache:
            return self._filter_cache[source_row]
        
        model = self.sourceModel()
        if not model:
            return True
        
        # Direct access to packet data (faster than model.data() calls)
        if source_row >= len(model.packets):
            return True
        
        packet_data = model.packets[source_row]
        
        # Build row_data with lowercase values
        # Columns: No., Time, Source, Destination, Protocol, Length, Info
        row_data = [str(packet_data[i]).lower() for i in range(len(packet_data))]
        
        # Evaluate filter
        result = self.evaluate_filter(row_data)
        
        # Cache result
        self._filter_cache[source_row] = result
        
        return result
    
    def evaluate_filter(self, row_data):
        """Evaluate filter expression against row data."""
        if not self.filter_tokens:
            return True
        
        # Simple evaluation without complex boolean logic
        # For now, treat all as AND
        results = []
        
        for token_type, token_value in self.filter_tokens:
            if token_type == 'operator':
                continue
            
            result = self.evaluate_token(token_type, token_value, row_data)
            
            # Early exit optimization
            if self._has_or_operator:
                if result:
                    return True  # OR: one True is enough
            else:
                if not result:
                    return False  # AND: one False is enough
            
            results.append(result)
        
        if self._has_or_operator:
            return any(results)
        else:
            return all(results)
    
    def evaluate_token(self, token_type, token_value, row_data):
        """Evaluate a single token against row data."""
        # Columns: 0=No., 1=Time, 2=Source, 3=Destination, 4=Protocol, 5=Length, 6=Info
        
        if token_type == 'protocol':
            # Match protocol column exactly or check if it's a sub-protocol
            protocol = row_data[4]
            token_lower = token_value.lower()
            return protocol == token_lower or protocol.startswith(token_lower)
        
        elif token_type == 'app_protocol':
            # Match by protocol name in protocol column OR by port in info column
            protocol = row_data[4]
            info = row_data[6]
            
            # Check if protocol column matches
            if token_value in protocol:
                return True
            
            # Check if any of the ports for this protocol appear in info
            ports = self.PROTOCOL_PORTS.get(token_value, [])
            for port in ports:
                regex = self._get_port_regex(port)
                if regex.search(info):
                    return True
            
            return False
        
        elif token_type == 'ip_src':
            return token_value in row_data[2]
        
        elif token_type == 'ip_dst':
            return token_value in row_data[3]
        
        elif token_type == 'ip_any':
            return token_value in row_data[2] or token_value in row_data[3]
        
        elif token_type == 'port':
            # Check in Info column for port numbers
            regex = self._get_port_regex(token_value)
            return regex.search(row_data[6]) is not None
        
        elif token_type == 'tcp_port':
            protocol = row_data[4]
            if 'tcp' not in protocol and protocol not in self.TCP_PROTOCOLS:
                return False
            regex = self._get_port_regex(token_value)
            return regex.search(row_data[6]) is not None
        
        elif token_type == 'udp_port':
            protocol = row_data[4]
            if 'udp' not in protocol and protocol not in self.UDP_PROTOCOLS:
                return False
            regex = self._get_port_regex(token_value)
            return regex.search(row_data[6]) is not None
        
        elif token_type == 'text':
            # Search in all columns
            return any(token_value in cell for cell in row_data)
        
        return True
