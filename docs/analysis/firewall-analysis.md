# Firewall and Infrastructure Blocking Analysis

How to analyze tcpdump data to determine if infrastructure is blocking tunnel traffic.

## When to Use This Analysis

- Tunnel status shows "error" despite control plane being established
- IPsec traffic counters show inBytes=0, outBytes=0
- Gateway/RouteAgent logs show NO configuration errors
- Suspect infrastructure (firewall/network) is blocking tunnel traffic

## Data Sources

### tcpdump Analysis Files (TEXT - Always Read These First)

- `tcpdump/cluster1-gateway-<nodename>-analysis.txt`
- `tcpdump/cluster2-gateway-<nodename>-analysis.txt`

These files contain:

- Total packet count
- First 50 packets with details
- Source/destination IP pairs
- Packet direction (In/Out)
- Automatic interpretation

### tcpdump Binary Files (BINARY - Reference Only)

- `tcpdump/cluster1-gateway-<nodename>.pcap`
- `tcpdump/cluster2-gateway-<nodename>.pcap`

## Understanding Packet Capture

**IMPORTANT:** tcpdump captures BOTH incoming and outgoing packets on the gateway node interface.

### Capture Filter

The filter is set based on cable driver and configuration:

- **libreswan with ESP:** `proto 50`
- **libreswan with UDP encapsulation:** `udp port 4500` (or ceIPSecNATTPort)
- **vxlan:** `udp port 4500` (or ceIPSecNATTPort)

The analysis checks for packet direction (In/Out) regardless of underlying protocol.

## Analysis Patterns

### Pattern 1: No Egress Traffic

```text
Cluster1 analysis: "Total packets captured: 0"
Cluster2 analysis: "Total packets captured: 0"
```

**Diagnosis:**

- Gateway pods are NOT sending tunnel traffic
- Appears to be: IPsec tunnel not properly initialized at kernel level (verify with additional kernel-level and IPsec logs)

**Next steps:**

- Check ipsec-status.log for STATE_V2_ESTABLISHED_CHILD_SA
- Review gateway pod logs for cable driver initialization errors

### Pattern 2: Egress but No Ingress (Infrastructure Blocking)

**CRITICAL:** This is the most common infrastructure blocking pattern.

**Example A - Unidirectional blocking:**

```text
Cluster1 analysis: "Total packets captured: 150" (all "Out" direction)
Cluster2 analysis: "Total packets captured: 0"
```

**Diagnosis:**

- Packets leaving cluster1 but NOT arriving at cluster2
- Infrastructure blocking cluster1→cluster2 direction

**Example B - Bidirectional blocking:**

```text
Cluster1 analysis: "Total packets captured: 150" (all "Out", no "In")
Cluster2 analysis: "Total packets captured: 94" (all "Out", no "In")
```

**Diagnosis:**

- Both clusters sending packets, but NEITHER receiving
- Infrastructure blocking tunnel traffic in BOTH directions
- **This is the most common pattern**

**Appears to be:** INFRASTRUCTURE BLOCKING (firewall/network blocking tunnel traffic)

*(This should be verified with additional network/firewall logs and connectivity tests.)*

### Pattern 3: Both Sending but Tunnel Still Error

```text
Cluster1 analysis: "Total packets captured: 150" (bidirectional)
Cluster2 analysis: "Total packets captured: 150" (bidirectional)
```

**Diagnosis:**

- Packets flowing in both directions
- But tunnel status still shows "error"
- Most likely cause: Health check IP issue or packet corruption (verify with additional kernel-level and IPsec logs)

**Next steps:**

- Check: Are packets reaching the right destination IPs?
- Review: Source/destination pairs in analysis file
- Verify: Health check IPs exist on gateway nodes

## Recommended Solutions Based on Pattern

### If Pattern 2 Detected (Infrastructure Blocking)

#### Step 1: Determine Protocol Being Used

Check Gateway CR:

```yaml
status:
  gateways:
  - connections:
    - endpoint:
        backend: libreswan
        backend_config:
          udp-port: "4500"  # If present, UDP encapsulation is enabled
```

Also check Submariner CR:

```yaml
spec:
  ceIPSecForceUDPEncaps: true  # If true, UDP encapsulation forced
```

#### Step 2: Apply Appropriate Workaround

**If using ESP (proto 50):**

**Workaround:** Enable UDP encapsulation to bypass ESP filtering.

*This forces tunnel traffic to use UDP port 4500 instead of ESP (protocol 50), working around infrastructure that blocks ESP.
This does not fix the root cause (firewall policy) and has trade-offs: it changes the exposed protocol/port surface,
still depends on correct firewall configuration for UDP/4500, and may have security or operational implications.*

**For ACM-Managed Submariner:**

```bash
# On the ACM hub cluster
kubectl patch submarinerconfig -n <managed-cluster-namespace> <config-name> \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true, "ceIPSecNATTPort": 4500}}'
```

**For Standalone Submariner:**

```bash
# On each managed cluster
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true, "ceIPSecNATTPort": 4500}}'

# Restart gateway pods to apply changes
kubectl rollout restart daemonset -n submariner-operator submariner-gateway
```

**If already using UDP:**

→ Verify firewall allows the UDP port (default 4500)
→ Check ceIPSecNATTPort setting if custom port is used

## Important Notes

- tcpdump analysis files are pre-generated TEXT files - always read these first
- Binary pcap files are kept for reference but analysis is already done
- Compare analysis from BOTH clusters to identify the pattern
- "Out" packets with NO "In" packets = infrastructure blocking
- If no configuration errors exist in logs, issue is infrastructure-level

## Example Diagnosis Flow

```text
If tunnels are ESTABLISHED (ipsec-status shows STATE_V2_ESTABLISHED_CHILD_SA):
  AND traffic counters show inBytes=0, outBytes=0:
    → IPsec control plane is working, but datapath is broken

    If gateway/routeagent logs show NO configuration errors:
      → Appears to be INFRASTRUCTURE LEVEL (firewall/network blocking)

      Read tcpdump analysis files:
        If cluster1 analysis shows packets (Out) BUT cluster2 shows 0:
          → Packets leaving cluster1 but not reaching cluster2
          → Tunnel traffic being blocked between nodes
          → Check cable driver and protocol:
            - libreswan with ESP: Try UDP encapsulation
            - libreswan with UDP or vxlan: Verify firewall allows UDP port

        If both analysis files show 0 packets:
          → Gateway not sending packets
          → Check gateway pod logs for cable driver initialization errors
```
