import re
import ipaddress
import sys
import argparse
import os
import copy

class Rule:
    def __init__(self, line_no, chain, action, params, original_line, address_lists):
        self.line_no = line_no
        self.chain = chain
        self.action = action
        self.params = params
        self.disabled = params.get('disabled') == 'yes'
        self.log = params.get('log') == 'yes'
        self.log_prefix = params.get('log-prefix', '')
        self.original_line = original_line
        self.address_lists = address_lists

    def matches(self, packet):
        if self.disabled:
            return False, "Rule is disabled"
        
        if 'src-address' in self.params:
            if not self.match_ip(packet['src_ip'], self.params['src-address']):
                return False, f"src-address {packet['src_ip']} mismatch with {self.params['src-address']}"
        
        if 'dst-address' in self.params:
            if not self.match_ip(packet['dst_ip'], self.params['dst-address']):
                return False, f"dst-address {packet['dst_ip']} mismatch with {self.params['dst-address']}"
        if 'src-address-list' in self.params:
            if not self.match_address_list(packet['src_ip'], self.params['src-address-list']):
                return False, f"src-address {packet['src_ip']} not in list {self.params['src-address-list']}"
        if 'dst-address-list' in self.params:
            if not self.match_address_list(packet['dst_ip'], self.params['dst-address-list']):
                return False, f"dst-address {packet['dst_ip']} not in list {self.params['dst-address-list']}"
        
        if 'protocol' in self.params:
            if packet['proto'] != self.params['protocol']:
                return False, f"protocol {packet['proto']} mismatch with {self.params['protocol']}"
        
        # Port matches only for tcp/udp
        if packet['proto'] not in ['tcp', 'udp']:
            if 'dst-port' in self.params or 'src-port' in self.params:
                return False, "Port match attempted on non-TCP/UDP protocol"
        
        if 'dst-port' in self.params:
            if not self.match_port(packet['dst_port'], self.params['dst-port']):
                return False, f"dst-port {packet['dst_port']} mismatch with {self.params['dst-port']}"
        if 'src-port' in self.params:
            if not self.match_port(packet['src_port'], self.params['src-port']):
                return False, f"src-port {packet['src_port']} mismatch with {self.params['src-port']}"
        
        # ICMP options
        if 'icmp-options' in self.params:
            if packet['proto'] != 'icmp':
                return False, "icmp-options on non-ICMP protocol"
            if not self.match_icmp(packet.get('icmp_type'), packet.get('icmp_code'), self.params['icmp-options']):
                return False, f"icmp-options mismatch with {self.params['icmp-options']}"
        
        if 'connection-state' in self.params:
            states = self.params['connection-state'].split(',')
            if packet['state'] not in states:
                return False, f"connection-state {packet['state']} mismatch with {self.params['connection-state']}"
        if 'connection-nat-state' in self.params:
            if packet.get('nat_state') != self.params['connection-nat-state']:
                return False, f"connection-nat-state {packet.get('nat_state')} mismatch with {self.params['connection-nat-state']}"
        
        if 'in-interface' in self.params:
            if packet['in_interface'] != self.params['in-interface']:
                return False, f"in-interface {packet['in_interface']} mismatch with {self.params['in-interface']}"
        if 'out-interface' in self.params:
            if packet['out_interface'] != self.params['out-interface']:
                return False, f"out-interface {packet['out_interface']} mismatch with {self.params['out-interface']}"
        return True, "Matched"
    
    def match_ip(self, ip, spec):
        negated = spec.startswith('!')
        if negated:
            spec = spec[1:]
        
        try:
            if '/' in spec:
                match = ipaddress.ip_address(ip) in ipaddress.ip_network(spec, strict=False)
            else:
                match = ipaddress.ip_address(ip) == ipaddress.ip_address(spec)
        except ValueError:
            match = False
            
        return not match if negated else match
    
    def match_address_list(self, ip, list_name):
        ips = self.address_lists.get(list_name, [])
        for spec in ips:
            if self.match_ip(ip, spec):
                return True
        return False
    
    def match_port(self, port, spec):
        if port is None: return False
        negated = spec.startswith('!')
        if negated:
            spec = spec[1:]
        
        match = False
        for p in spec.split(','):
            try:
                if '-' in p:
                    start, end = map(int, p.split('-'))
                    if start <= int(port) <= end:
                        match = True
                        break
                elif int(p) == int(port):
                    match = True
                    break
            except ValueError:
                continue
        
        return not match if negated else match
    
    def match_icmp(self, icmp_type, icmp_code, spec):
        if icmp_type is None or icmp_code is None:
            return False
        negated = spec.startswith('!')
        if negated:
            spec = spec[1:]
        
        match = False
        for o in spec.split(','):
            if ':' in o:
                t, c = o.split(':')
                t_start, t_end = (int(t), int(t)) if '-' not in t else map(int, t.split('-'))
                c_start, c_end = (int(c), int(c)) if '-' not in c else map(int, c.split('-'))
                if t_start <= icmp_type <= t_end and c_start <= icmp_code <= c_end:
                    match = True
                    break
            # Assuming no single type without code for simplicity
        return not match if negated else match
    
    def __str__(self):
        return self.original_line

def parse_params(line):
    params = {}
    pattern = r'(\S+)=(?:\"([^\"]*)\"|(\S+))|(\S+)'
    matches = re.finditer(pattern, line)
    for m in matches:
        if m.group(1):
            key = m.group(1)
            val = m.group(2) if m.group(2) is not None else m.group(3)
            params[key] = val
        elif m.group(4):
            params[m.group(4)] = 'yes'
    return params

class Conntrack:
    def __init__(self):
        self.table = {} # (src, sport, dst, dport, proto) -> (conn, direction)
    
    def lookup(self, packet):
        key = (str(packet['src_ip']), packet.get('src_port'), str(packet['dst_ip']), packet.get('dst_port'), packet['proto'])
        return self.table.get(key, (None, None))
    
    def establish(self, orig, nat):
        conn = {
            'orig_src_ip': str(orig['src_ip']), 'orig_src_port': orig.get('src_port'),
            'orig_dst_ip': str(orig['dst_ip']), 'orig_dst_port': orig.get('dst_port'),
            'nat_src_ip': str(nat['src_ip']) if str(nat['src_ip']) != str(orig['src_ip']) else None,
            'nat_src_port': nat.get('src_port') if nat.get('src_port') != orig.get('src_port') else None,
            'nat_dst_ip': str(nat['dst_ip']) if str(nat['dst_ip']) != str(orig['dst_ip']) else None,
            'nat_dst_port': nat.get('dst_port') if nat.get('dst_port') != orig.get('dst_port') else None,
            'proto': orig['proto']
        }
        
        fwd_key = (conn['orig_src_ip'], conn['orig_src_port'], conn['orig_dst_ip'], conn['orig_dst_port'], conn['proto'])
        self.table[fwd_key] = (conn, 'forward')
        
        reply_src_ip = conn['nat_dst_ip'] or conn['orig_dst_ip']
        reply_src_port = conn['nat_dst_port'] or conn['orig_dst_port']
        reply_dst_ip = conn['nat_src_ip'] or conn['orig_src_ip']
        reply_dst_port = conn['nat_src_port'] or conn['orig_src_port']
        reply_key = (reply_src_ip, reply_src_port, reply_dst_ip, reply_dst_port, conn['proto'])
        self.table[reply_key] = (conn, 'reply')
        
        return conn


class Config:
    def __init__(self, filename, extra_address_lists=None):
        self.rules = []  # filter rules (v4)
        self.ipv6_rules = [] # filter rules (v6)
        self.nat_rules = [] # nat rules (v4)
        self.address_lists = {} # v4 lists
        self.ipv6_address_lists = {} # v6 lists
        self.interfaces = [] # v4 networks
        self.ipv6_interfaces = [] # v6 networks
        self.interface_ips = {}
        self.local_ips = set()
        self.ipv6_local_ips = set()
        self.routes = [] # v4 routes
        self.ipv6_routes = [] # v6 routes
        self.parse_rsc(filename)
        if extra_address_lists:
            for extra_file in extra_address_lists:
                if os.path.exists(extra_file):
                    self.parse_extra_address_list(extra_file)
    
    def parse_rsc(self, filename):
        with open(filename, 'r') as f:
            content = f.read()
        
        content = content.replace('\\\n', '')
        content = content.replace('\\\r\n', '')
        
        lines = content.splitlines()
        context = ""
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            full_line = ""
            if line.startswith('/'):
                context = line
                if ' add ' in line:
                    full_line = line
            elif line.startswith('add'):
                full_line = context + " " + line
            
            if not full_line: continue

            if '/ip firewall address-list' in full_line:
                params = parse_params(full_line.split('add ')[1])
                name = params.get('list')
                addr = params.get('address')
                if name and addr:
                    self.address_lists.setdefault(name, []).append(addr)

            elif '/ipv6 firewall address-list' in full_line:
                params = parse_params(full_line.split('add ')[1])
                name = params.get('list')
                addr = params.get('address')
                if name and addr:
                    self.ipv6_address_lists.setdefault(name, []).append(addr)

            elif '/ip address' in full_line:
                params = parse_params(full_line.split('add ')[1])
                addr = params.get('address')
                if addr:
                    ip_only = addr.split('/')[0] if '/' in addr else addr
                    self.local_ips.add(ip_only)
                    iface = params.get('interface')
                    if iface:
                        self.interface_ips[iface] = ip_only
                        net = ipaddress.ip_network(addr, strict=False) if '/' in addr else ipaddress.ip_network(addr + "/32", strict=False)
                        self.interfaces.append((net, iface))

            elif '/ipv6 address' in full_line:
                params = parse_params(full_line.split('add ')[1])
                addr = params.get('address')
                if addr:
                    ip_only = addr.split('/')[0] if '/' in addr else addr
                    self.ipv6_local_ips.add(ip_only)
                    iface = params.get('interface')
                    if iface:
                        self.interface_ips[iface] = ip_only
                        net = ipaddress.ip_network(addr, strict=False) if '/' in addr else ipaddress.ip_network(addr + "/128", strict=False)
                        self.ipv6_interfaces.append((net, iface))

            elif '/ip route' in full_line:
                params = parse_params(full_line.split('add ')[1])
                dst = params.get('dst-address', '0.0.0.0/0')
                gw = params.get('gateway')
                if dst and gw:
                    self.routes.append((ipaddress.ip_network(dst, strict=False), gw))

            elif '/ipv6 route' in full_line:
                params = parse_params(full_line.split('add ')[1])
                dst = params.get('dst-address', '::/0')
                gw = params.get('gateway')
                if dst and gw:
                    self.ipv6_routes.append((ipaddress.ip_network(dst, strict=False), gw))

            elif '/ip firewall filter' in full_line:
                params = parse_params(full_line.split('add ')[1])
                chain = params.get('chain')
                action = params.get('action', 'accept')
                self.rules.append(Rule(i + 1, chain, action, params, full_line, self.address_lists))

            elif '/ipv6 firewall filter' in full_line:
                params = parse_params(full_line.split('add ')[1])
                chain = params.get('chain')
                action = params.get('action', 'accept')
                self.ipv6_rules.append(Rule(i + 1, chain, action, params, full_line, self.ipv6_address_lists))

            elif '/ip firewall nat' in full_line:
                params = parse_params(full_line.split('add ')[1])
                chain = params.get('chain')
                action = params.get('action', 'accept')
                self.nat_rules.append(Rule(i + 1, chain, action, params, full_line, self.address_lists))

    
    def parse_extra_address_list(self, filename):
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                list_match = re.search(r'list=(\S+)', line)
                addr_match = re.search(r'address=(\S+)', line)
                if list_match and addr_match:
                    name = list_match.group(1)
                    addr = addr_match.group(1)
                    if name not in self.address_lists:
                        self.address_lists[name] = []
                    if addr not in self.address_lists[name]:
                        self.address_lists[name].append(addr)
    
    def get_interface(self, ip_str):
        if not ip_str or ip_str == 'ROUTER_IP': return "unknown"
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return "unknown"
            
        is_v6 = ip.version == 6
        interfaces = self.ipv6_interfaces if is_v6 else self.interfaces
        routes = self.ipv6_routes if is_v6 else self.routes
        
        for net, iface in interfaces:
            if ip in net:
                return iface
        
        best_match = None
        best_len = -1
        for net, gw in routes:
            if ip in net:
                if net.prefixlen > best_len:
                    best_match = gw
                    best_len = net.prefixlen
        
        if best_match:
            if re.match(r'[0-9a-fA-F:]+', best_match) if is_v6 else re.match(r'\d+\.\d+\.\d+\.\d+', best_match):
                return self.get_interface(best_match)
            return best_match
            
        return "unknown"

def run_chain(ruleset, chain_name, packet, cfg_rules, verbose=False, depth=0, table_name="filter"):
    indent = " " * depth
    print(f"{indent}>>> Table: {table_name}, Chain: {chain_name}")
    
    chain_rules = [r for r in ruleset if r.chain == chain_name]
    if not chain_rules:
        print(f"{indent} (No rules in chain {chain_name})")
        return 'CONTINUE', None
    
    for i, rule in enumerate(chain_rules):
        matched, reason = rule.matches(packet)
        if matched:
            if rule.log:
                print(f"{indent} LOG: {rule.log_prefix} {packet}")
            
            print(f"{indent} [MATCH] L{rule.line_no}: {rule.action.upper()} {rule.original_line}")
            
            if rule.action == 'jump':
                target = rule.params.get('jump-target')
                print(f"{indent} Jumping to: {target}")
                res, info = run_chain(ruleset, target, packet, cfg_rules, verbose, depth + 1, table_name)
                if res in ['ACCEPT', 'DROP', 'REJECT', 'DST-NAT', 'SRC-NAT', 'MASQUERADE', 'FASTTRACK-CONNECTION']:
                    return res, info
                print(f"{indent} Returned from: {target}")
            
            elif rule.action == 'return':
                return 'CONTINUE', None
            
            elif rule.action in ['accept', 'drop', 'reject', 'fasttrack-connection']:
                return rule.action.upper(), None
            
            elif rule.action == 'passthrough':
                continue  # Continue to next rule, for counters
            
            elif rule.action == 'dst-nat':
                old_dst = packet['dst_ip']
                packet['dst_ip'] = rule.params.get('to-addresses', packet['dst_ip'])
                if 'to-ports' in rule.params:
                    packet['dst_port'] = int(rule.params['to-ports'])
                print(f"{indent} NAT (dst-nat): {old_dst} -> {packet['dst_ip']}")
                packet['nat_state'] = 'dstnat'
                return 'DST-NAT', True
            
            elif rule.action == 'src-nat':
                old_src = packet['src_ip']
                packet['src_ip'] = rule.params.get('to-addresses', packet['src_ip'])
                if 'to-ports' in rule.params:
                    packet['src_port'] = int(rule.params['to-ports'])
                print(f"{indent} NAT (src-nat): {old_src} -> {packet['src_ip']}")
                packet['nat_state'] = 'srcnat'
                return 'SRC-NAT', True
            
            elif rule.action == 'masquerade':
                old_src = packet['src_ip']
                packet['src_ip'] = cfg.interface_ips.get(packet['out_interface'], 'UNKNOWN')
                if packet['src_ip'] == 'UNKNOWN':
                    print(f"{indent} Warning: No IP for interface {packet['out_interface']}, using UNKNOWN")
                print(f"{indent} NAT (masquerade): {old_src} -> {packet['src_ip']}")
                packet['nat_state'] = 'srcnat'
                return 'MASQUERADE', True
            
            elif rule.action == 'redirect':
                if 'to-ports' in rule.params:
                    old_port = packet['dst_port']
                    packet['dst_port'] = int(rule.params['to-ports'])
                    print(f"{indent} NAT (redirect): port {old_port} -> {packet['dst_port']}")
                    packet['nat_state'] = 'dstnat'
                    return 'REDIRECT', True
                else:
                    return 'CONTINUE', None
        elif verbose:
            print(f"{indent} [SKIP] L{rule.line_no}: {reason}")
    
    print(f"{indent}>>> End of chain: {chain_name}")
    return 'CONTINUE', None

def simulate(cfg, conntrack, packet, verbose=False, label="PACKET"):
    print(f"\n[{label}]")
    orig_packet = copy.deepcopy(packet)
    
    is_v6 = ipaddress.ip_address(packet['src_ip']).version == 6
    local_ips = cfg.ipv6_local_ips if is_v6 else cfg.local_ips
    ruleset = cfg.ipv6_rules if is_v6 else cfg.rules
    
    # Determine Chain: INPUT, OUTPUT, or FORWARD
    filter_chain = 'forward'
    if packet['dst_ip'] in local_ips:
        filter_chain = 'input'
    elif packet['src_ip'] in local_ips or packet['src_ip'] == 'ROUTER_IP':
        filter_chain = 'output'
    
    print(f"Interfaces: in:{packet['in_interface']} out:{packet['out_interface']}")
    print(f"Chain detected: {filter_chain}")
    
    conn, direction = conntrack.lookup(packet)
    if conn:
        packet['state'] = 'established'
        print(f"Flow: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} ({packet['proto']}, {packet['state']})")
        print(f"Conntrack: Match found ({direction} direction)")
        
        if direction == 'forward':
            if conn['nat_src_ip']:
                print(f" Applying cached SRC-NAT: {packet['src_ip']} -> {conn['nat_src_ip']}")
                packet['src_ip'] = conn['nat_src_ip']
                if conn['nat_src_port']: packet['src_port'] = conn['nat_src_port']
            if conn['nat_dst_ip']:
                print(f" Applying cached DST-NAT: {packet['dst_ip']} -> {conn['nat_dst_ip']}")
                packet['dst_ip'] = conn['nat_dst_ip']
                if conn['nat_dst_port']: packet['dst_port'] = conn['nat_dst_port']
        else:
            if conn['nat_dst_ip']:
                print(f" Applying reverse DST-NAT: {packet['src_ip']} -> {conn['orig_dst_ip']}")
                packet['src_ip'] = conn['orig_dst_ip']
                packet['src_port'] = conn['orig_dst_port']
            if conn['nat_src_ip']:
                print(f" Applying reverse SRC-NAT: {packet['dst_ip']} -> {conn['orig_src_ip']}")
                packet['dst_ip'] = conn['orig_src_ip']
                packet['dst_port'] = conn['orig_src_port']
    else:
        packet['state'] = 'new'
        print(f"Flow: {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} ({packet['proto']}, {packet['state']})")
    
    # 1. PREROUTING (DSTNAT)
    if not is_v6 and packet['state'] == 'new' and filter_chain != 'output':
        res, _ = run_chain(cfg.nat_rules, 'dstnat', packet, cfg.rules, verbose, table_name="nat")
        if res == 'DST-NAT':
            # Re-check chain after DST-NAT
            if packet['dst_ip'] in local_ips:
                filter_chain = 'input'
            else:
                filter_chain = 'forward'
            packet['out_interface'] = cfg.get_interface(packet['dst_ip'])
            print(f"Rerouting after DST-NAT: new chain: {filter_chain}, new out-interface: {packet['out_interface']}")
    
    # 2. FILTERING
    res, _ = run_chain(ruleset, filter_chain, packet, ruleset, verbose, table_name="filter")
    
    if res == 'DROP' or res == 'REJECT':
        print(f"Result: {res}")
        return res, None
    
    # 3. POSTROUTING (SRCNAT)
    if not is_v6 and packet['state'] == 'new' and filter_chain != 'input':
        run_chain(cfg.nat_rules, 'srcnat', packet, cfg.rules, verbose, table_name="nat")
    
    if packet['state'] == 'new' and (res in ['ACCEPT', 'CONTINUE', 'ACCEPT (default)', 'FASTTRACK-CONNECTION']):
        conn = conntrack.establish(orig_packet, packet)
    
    final_res = res if res != 'CONTINUE' else 'ACCEPT (default)'
    print(f"Result: {final_res}")
    return final_res, conn

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MikroTik Firewall Simulator')
    parser.add_argument('--src', default='193.198.212.229', help='Source IP')
    parser.add_argument('--dst', default='172.16.16.153', help='Destination IP')
    parser.add_argument('--proto', default='udp', help='Protocol (tcp/udp/icmp)')
    parser.add_argument('--dport', type=int, default=161, help='Destination Port (for tcp/udp) or ICMP type (for icmp)')
    parser.add_argument('--sport', type=int, default=12345, help='Source Port (for tcp/udp) or ICMP code (for icmp)')
    parser.add_argument('--in-iface', help='In Interface (auto-detected if omitted)')
    parser.add_argument('--out-iface', help='Out Interface (auto-detected if omitted)')
    parser.add_argument('--no-response', action='store_true', help='Do not test return packet')
    parser.add_argument('--verbose', action='store_true', help='Show skipped rules')
    parser.add_argument('--rsc', default='backup.rsc', help='Backup RSC file')
    parser.add_argument('--extra-lists', nargs='*', default=['tilera.address-list.2'], help='Extra address list files')
    args = parser.parse_args()
    
    cfg = Config(args.rsc, extra_address_lists=args.extra_lists)
    
    print("\n[ADDRESS LISTS]")
    for name, addrs in sorted(cfg.address_lists.items()):
        print(f"  {name:20} (v4) {len(addrs):>5} entries")
    for name, addrs in sorted(cfg.ipv6_address_lists.items()):
        print(f"  {name:20} (v6) {len(addrs):>5} entries")
        
    conntrack = Conntrack()
    
    in_iface = args.in_iface or cfg.get_interface(args.src)
    out_iface = args.out_iface or cfg.get_interface(args.dst)
    packet = {
        'src_ip': args.src, 'dst_ip': args.dst,
        'proto': args.proto, 'in_interface': in_iface, 'out_interface': out_iface
    }
    if args.proto in ['tcp', 'udp']:
        packet['src_port'] = args.sport
        packet['dst_port'] = args.dport
    elif args.proto == 'icmp':
        packet['icmp_type'] = args.dport  # Use dport for type
        packet['icmp_code'] = args.sport  # Use sport for code
        packet['src_port'] = None
        packet['dst_port'] = None
    
    res, conn = simulate(cfg, conntrack, packet, verbose=args.verbose, label="INITIAL PACKET")
    if not args.no_response and conn:
        response_packet = {
            'src_ip': packet['dst_ip'], 'dst_ip': packet['src_ip'],
            'proto': packet['proto'],
            'in_interface': packet['out_interface'],
            'out_interface': packet['in_interface']
        }
        if args.proto in ['tcp', 'udp']:
            response_packet['src_port'] = packet['dst_port']
            response_packet['dst_port'] = packet['src_port']
        elif args.proto == 'icmp':
            response_packet['icmp_type'] = packet['icmp_code']  # Simple reverse for echo reply
            response_packet['icmp_code'] = 0
            response_packet['src_port'] = None
            response_packet['dst_port'] = None
        simulate(cfg, conntrack, response_packet, verbose=args.verbose, label="RESPONSE PACKET")
