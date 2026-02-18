import re
import sys
import subprocess
import argparse

# 2026-02-18T00:00:02.746264+01:00 sw-core firewall: DROP SNMP public_ext_to_in: in:bonding2-11 out:bridge1001, src-mac 04:01:a1:f2:d1:94, proto UDP, 176.65.134.118:44851->193.198.214.127:161, len 66
LOG_PATTERN = re.compile(
    r'.*firewall: (?P<action>\S+) (?P<label>.*?) (?P<chain>\S+): '
    r'in:(?P<in_iface>\S+) out:(?P<out_iface>\S+), .* '
    r'proto (?P<proto>\S+)(?: \(.*\))?, '
    r'(?P<src_ip>[\d\.]+):(?P<src_port>\d+)->(?P<dst_ip>[\d\.]+):(?P<dst_port>\d+)'
)

def run_simulation(src, dst, proto, sport, dport, in_iface, out_iface):
    cmd = [
        sys.executable, 'simulate_firewall.py',
        '--src', src,
        '--dst', dst,
        '--proto', proto.lower(),
        '--sport', sport,
        '--dport', dport,
        '--in-iface', in_iface,
        '--out-iface', out_iface
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = result.stdout
    
    # Final result is on the last line or close to it
    final_line = ""
    for line in reversed(output.splitlines()):
        if line.startswith("Result:"):
            final_line = line
            break
    
    if "DROP" in final_line:
        return "DROP"
    if "REJECT" in final_line:
        return "REJECT"
    if "ACCEPT" in final_line:
        return "ACCEPT"
    return "UNKNOWN"

def verify(log_file, limit=100):
    matches = 0
    mismatches = 0
    
    with open(log_file, 'r') as f:
        count = 0
        for line in f:
            if count >= limit:
                break
            
            m = LOG_PATTERN.match(line.strip())
            if not m:
                continue
            
            count += 1
            log_data = m.groupdict()
            expected = log_data['action'] # e.g., "DROP"
            
            # Simulator expects lowercase protocol
            sim_res = run_simulation(
                log_data['src_ip'], log_data['dst_ip'], 
                log_data['proto'], log_data['src_port'], log_data['dst_port'],
                log_data['in_iface'], log_data['out_iface']
            )
            
            if sim_res == expected:
                matches += 1
            else:
                mismatches += 1
                print(f"[FAIL] {log_data['src_ip']} -> {log_data['dst_ip']} ({log_data['proto']}) expected {expected}, got {sim_res}")
                print(f"  Log line: {line.strip()}")

    print(f"\nVerification Summary:")
    print(f"Total processed: {count}")
    print(f"Matches: {matches}")
    print(f"Mismatches: {mismatches}")
    if count > 0:
        accuracy = (matches / count) * 100
        print(f"Accuracy: {accuracy:.2f}%")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Verify Simulator against Logs')
    parser.add_argument('--log', default='drop.log', help='Path to drop.log')
    parser.add_argument('--limit', type=int, default=100, help='Max entries to test')
    args = parser.parse_args()
    
    verify(args.log, args.limit)
