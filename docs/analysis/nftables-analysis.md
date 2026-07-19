# nftables Analysis for Submariner Diagnostics

**Applies to**: Submariner 0.22+ deployments  
**File location**: `cluster*/gather/cluster*/<node>_nftables.log`

Starting with Submariner 0.22, Submariner migrated from iptables to nftables for packet filtering and NAT rules.

---

## When to Analyze nftables

**Prerequisites**: ALL must be true
1. Submariner version ≥ 0.22
2. Datapath is broken (tunnel error OR RouteAgent error OR connectivity failed)
3. nftables files exist in gather data

**Skip if**:
- Submariner < 0.22 (uses iptables instead)
- Datapath is healthy (no point checking rules if everything works)
- No nftables files collected

---

## nftables File Structure

Submariner creates these chains in the `inet submariner` table:

```nftables
table inet submariner {
    # GlobalNet SNAT (egress direction)
    chain SUBMARINER-GN-EGRESS { ... }
    chain SM-GN-EGRESS-PODS { ... }
    chain SM-GN-EGRESS-NS { ... }
    chain SM-GN-EGRESS-HDLS-PODS { ... }
    chain SM-GN-EGRESS-HDLS-EPS { ... }
    chain SM-GN-EGRESS-CLUSTER { ... }  # <-- Actual SNAT rules here
    
    # GlobalNet DNAT (ingress direction)
    chain SUBMARINER-GN-INGRESS { ... }  # <-- Health check DNAT here
    
    # MSS clamping (TCP optimization)
    chain SUBMARINER-FWD-MSSCLAMP { ... }
    
    # OVN-K SNAT exemptions (gateway nodes only)
    set mgmtport-no-snat-subnets-v4 { ... }
}
```

---

## Check 1: GlobalNet SNAT Rules (Gateway Nodes Only)

**When**: GlobalNet enabled AND analyzing gateway node

### What to Check

1. **Find SNAT chains**: `SM-GN-EGRESS-*` (not `SUBMARINER-POSTROUTING` which is iptables era)

```bash
grep -E "chain SM-GN-EGRESS-" <gateway-node>_nftables.log
```

2. **Look for SNAT rules** in `SM-GN-EGRESS-CLUSTER` chain:

```nftables
chain SM-GN-EGRESS-CLUSTER {
    ip saddr 172.21.0.0/16 meta mark & 0x000c0000 == 0x000c0000 counter packets 0 bytes 0 snat to 242.0.0.1-242.0.0.8
    ip saddr 172.17.128.0/17 meta mark & 0x000c0000 == 0x000c0000 counter packets 480571 bytes 28158124 snat to 242.0.0.1-242.0.0.8
}
```

**Key pattern**: `counter packets N bytes M snat to X.X.X.X`
- Note: `counter` comes BEFORE `snat` (not after)

### Failure Modes

❌ **No SM-GN-EGRESS-* chains found**
```
Possible causes:
- Submariner < 0.22 (using iptables)
- GlobalNet not enabled
- RouteAgent failed to configure nftables
```

❌ **SNAT to 0.0.0.0**
```nftables
snat to 0.0.0.0
```
```
Root cause: GlobalNet IP allocation failed
Impact: Outbound traffic will have invalid source IP
Remediation: Check submariner-globalnet pod logs for allocation errors
```

❌ **All SNAT counters = 0**
```
Root cause: Traffic not reaching nftables SNAT stage
Possible causes:
- IP rules misconfigured (traffic not routed to table 150)
- Routing table 150 missing routes
- Packets not matching meta mark 0x000c0000
```

### Success Pattern

✅ **SNAT rules with non-zero counters**
```nftables
counter packets 480571 bytes 28158124 snat to 242.0.0.1-242.0.0.8
```

**Important**: Sum counters across ALL SM-GN-EGRESS-* chains, not just one rule.

---

## Check 2: GlobalNet Health Check DNAT (Gateway Nodes Only)

**When**: GlobalNet enabled AND analyzing gateway node

### What to Check

Health check DNAT translates remote cluster's GlobalNet health check IP → local ovn-k8s-mp0 IP.

**Find in**: `SUBMARINER-GN-INGRESS` chain

```nftables
chain SUBMARINER-GN-INGRESS {
    type nat hook prerouting priority dstnat - 10; policy accept;
    ip protocol icmp ip daddr 242.0.255.253 counter packets 0 bytes 0 dnat to 172.17.130.2
}
```

**Key pattern**: `ip daddr 242.X.255.253 counter packets N bytes M dnat to <ovn-k8s-mp0-ip>`

### Interpretation

The DNAT counter shows **how many health check packets were received** from the remote cluster.

#### Asymmetric Health Check Pattern

**Scenario**: cluster1 counter = 0, cluster2 counter = 48,932

```
Evidence:
  (B) cluster1 DNAT counter = 0 packets
  (B) cluster2 DNAT counter = 48,932 packets
  (C) Tcpdump shows bidirectional tunnel traffic

Conclusion: 
  Tunnel is working (bidirectional traffic confirmed)
  But health check packets not reaching cluster1
  
Most likely cause: Local routing issue on cluster1 (Segment 1)
  - Check table 150 routes on cluster1 worker nodes
  - Check IP rules on cluster1 worker nodes
  - Verify OVN-K datapath configuration
```

#### Symmetric Failure Pattern

**Scenario**: Both counters = 0

```
Evidence:
  (B) cluster1 DNAT counter = 0
  (B) cluster2 DNAT counter = 0
  (C) Tcpdump may show limited or no traffic

Conclusion: Bidirectional issue
  - Tunnel not established, OR
  - Both clusters have local routing issues
```

### Important Notes

1. **DNAT is GlobalNet-specific**: Only check when `globalCIDR` is set in Submariner CR
2. **Gateway nodes only**: Health check DNAT only happens on gateway nodes
3. **Correlation required**: Don't conclude from DNAT counter alone - correlate with:
   - (A) Logs - check for errors
   - (C) Tcpdump - verify tunnel traffic exists

---

## Check 3: MSS Clamping

**When**: Always (applies to all deployments, not just GlobalNet)

### What to Check

MSS (Maximum Segment Size) clamping prevents TCP fragmentation issues in tunnels.

```nftables
chain SUBMARINER-FWD-MSSCLAMP {
    type filter hook forward priority filter - 10; policy accept;
    ip daddr 242.1.0.0/16 tcp flags syn / syn,rst counter packets 955400 bytes 57324000 tcp option maxseg size set 1398
    ip saddr 242.1.0.0/16 tcp flags syn / syn,rst counter packets 0 bytes 0 tcp option maxseg size set 1398
}
```

**Key pattern**: `tcp flags syn / syn,rst counter packets N ... tcp option maxseg size set XXXX`

### Interpretation

✅ **Active MSS clamping** (non-zero counter):
```
counter packets 955400 bytes 57324000
```
This is **normal and expected**. Shows TCP connections are being established.

⚠️ **Zero counter**:
```
counter packets 0 bytes 0
```
Could indicate:
- No TCP traffic yet (not necessarily a problem)
- TCP traffic not flowing through this path
- Check if connectivity tests used TCP

### Typical MSS Values

- **1398**: Common for GlobalNet + IPsec/VXLAN
- **1280**: Conservative value for very small MTU paths
- **1360-1400**: Typical range for tunneled traffic

---

## Check 4: OVN-K SNAT Exemptions (Gateway Nodes Only, OVN-K CNI)

**When**: CNI = OVN-Kubernetes AND analyzing gateway node

### What to Check

OVN-K has its own SNAT that conflicts with Submariner. Submariner must exempt remote cluster CIDRs from OVN's mgmtport SNAT.

**Find**: `mgmtport-no-snat-subnets-v4` set

```nftables
set mgmtport-no-snat-subnets-v4 {
    type ipv4_addr
    flags interval
    elements = { 10.244.0.0/16, 10.245.0.0/16,
                 172.21.0.0/16, 172.17.128.0/17,
                 242.0.0.0/16, 242.1.0.0/16 }
}
```

### Expected Elements

Should contain:
- Remote cluster pod CIDR (e.g., `10.245.0.0/16`)
- Remote cluster service CIDR (e.g., `172.21.0.0/16`)
- Remote cluster GlobalNet CIDR if enabled (e.g., `242.1.0.0/16`)

### Failure Mode

❌ **Remote CIDR missing from exemption set**

```
Impact: OVN will SNAT Submariner traffic from gateway node
  Source IP gets rewritten to gateway's pod IP
  Remote cluster rejects packets (source IP mismatch)
  
Symptoms:
  - Tunnel shows "connected" 
  - Gateway CR may show "error"
  - Packet captures show source IP = gateway pod IP (not expected IP)

Root cause: Submariner failed to configure OVN-K exemptions
```

### Important Notes

1. **Gateway nodes only**: Non-gateway nodes route through table 150, don't need exemptions
2. **OVN-K specific**: Other CNIs don't have this issue
3. **Pre-nftables versions**: Older OVN-K may not have this set (not an error)

---

## Cable Driver Awareness

**CRITICAL**: Only recommend cable-driver-specific checks.

### Check Cable Driver

Read from `manifest.txt`:
```
Cable driver: vxlan
```

Or parse from `subctl show all` output:
```
CABLE DRIVER
vxlan
```

### Recommendations by Cable Driver

| Cable Driver | Recommend |
|--------------|-----------|
| `libreswan` | Check IPsec counters in `ipsec-trafficstatus.log` |
| `vxlan` | Check VXLAN packet encapsulation, ARP resolution |
| `wireguard` | Check WireGuard tunnel status |

**Never** recommend IPsec checks for VXLAN or vice versa.

---

## nftables vs iptables

### How to Detect Which System is in Use

```bash
# nftables (Submariner 0.22+)
grep "table inet submariner" <node>_nftables.log

# iptables (Submariner < 0.22)
grep "Chain SUBMARINER" <node>_iptables.log
```

### Migration Notes

**Before 0.22**: Rules in iptables, SNAT in `SUBMARINER-POSTROUTING` chain  
**After 0.22**: Rules in nftables, SNAT in `SM-GN-EGRESS-CLUSTER` chain

**Don't mix**: If analyzing 0.22+ deployment, read nftables files. If < 0.22, read iptables files.

---

## Analysis Workflow

### 1. Determine Scope

```
IF Submariner < 0.22 THEN
  SKIP nftables analysis (use iptables instead)
  
IF datapath healthy THEN
  SKIP nftables analysis (no point if everything works)
  
IF no nftables files THEN
  SKIP nftables analysis
```

### 2. Check GlobalNet-Specific Rules (if enabled)

```
FOR each gateway node:
  - Check SNAT rules in SM-GN-EGRESS-* chains
  - Check SNAT packet counters (sum across all chains)
  - Check health check DNAT counter
  - Collect DNAT counter for correlation analysis
```

### 3. Check MSS Clamping (always)

```
FOR each gateway node:
  - Check SUBMARINER-FWD-MSSCLAMP chain
  - Verify MSS value is reasonable (1280-1400)
  - Non-zero counter = TCP traffic flowing (good)
```

### 4. Check OVN-K Exemptions (if OVN-K CNI)

```
FOR gateway node only:
  - Check mgmtport-no-snat-subnets-v4 set
  - Verify remote CIDRs are in exemption list
```

### 5. Correlate with Other Evidence

**Don't conclude from nftables alone**. Use A+B+C correlation:

- **(A) Logs**: Check for nftables configuration errors
- **(B) nftables**: SNAT/DNAT counters, rule existence
- **(C) Tcpdump**: Actual packet flow

**Example**:
```
Evidence:
  (A) No errors in RouteAgent logs
  (B) SNAT counter = 480k packets (healthy)
  (B) DNAT counter = 0 packets (cluster1)
  (B) DNAT counter = 48k packets (cluster2)
  (C) Tcpdump shows bidirectional tunnel traffic

Conclusion: Asymmetric local routing issue on cluster1
```

---

## Common Patterns

### Pattern 1: Healthy GlobalNet Datapath

```
✓ SNAT rules found (2+ rules)
✓ SNAT counter: 480,571 packets
✓ Health check DNAT counter: 48,932 packets
✓ MSS clamping active
✓ OVN exemptions configured
```

### Pattern 2: SNAT Not Working

```
✓ SNAT rules found
✗ SNAT counter: 0 packets
```

**Diagnose**:
1. Check IP rules (is traffic routed to table 150?)
2. Check table 150 routes (is default route present?)
3. Check packet mark (is meta mark 0x000c0000 being set?)

### Pattern 3: Asymmetric Health Check

```
cluster1:
  ✓ SNAT counter: 480k
  ✗ DNAT counter: 0
  
cluster2:
  ✓ SNAT counter: 505k
  ✓ DNAT counter: 48k
```

**Diagnose**: cluster1 local routing issue (Segment 1)

---

## References

- **Submariner nftables migration**: https://github.com/submariner-io/submariner/pull/2850
- **GlobalNet architecture**: See `datapath-architecture.md`
- **OVN-K SNAT exemptions**: See `ovn-offline-verification.md`

---

## Packet Capture Analysis (tcpdump)

When available, analyze pcap files to understand tunnel traffic patterns.

### VXLAN Cable Driver

For VXLAN deployments, analyze UDP port 4500 traffic:

**ICMP Packet Types to Check**:
- **Echo Request (Egress)**: Health checks being sent to remote cluster
- **Echo Request (Ingress)**: Health checks received from remote cluster  
- **Echo Reply (Egress)**: Responses to remote health checks
- **Echo Reply (Ingress)**: Responses received from remote
- **Unreachable (Egress/Ingress)**: Routing failures (⚠ indicates problem)

**Direction Indicators**:
- **Egress**: Outbound traffic leaving the gateway
- **Ingress**: Inbound traffic arriving at the gateway

**Example Analysis**:
```
cluster1:
  ICMP Packets:
    ✓ Echo Request (Egress): 13 packets    ← Sending health checks
    ✓ Echo Request (Ingress): 1 packets   ← Receiving health checks
    ✓ Echo Reply (Egress): 1 packets      ← Sending replies
    
cluster2:
  ICMP Packets:
    ⚠ Unreachable (Egress): 20 packets - routing issue
```

**CRITICAL: Analyze ICMP TYPES, not just packet counts**

**Diagnosis from ICMP Patterns**:
- **Both clusters: Egress Echo Request**: Healthy - both sending health checks ✓
- **One cluster: Egress Unreachable instead of Echo Request**: Local routing issue ✗
  - Cluster cannot route to remote GlobalNet health check IP
  - This is NOT a tunnel failure - it's a routing configuration problem
  - Root cause: Missing routes or routing table misconfiguration
  - **VXLAN-specific**: Check ARP resolution (see below)
- **Egress Request + No Ingress Reply**: Remote not responding (check remote cluster)
- **No Egress Request**: Local not sending (check local datapath)

**VXLAN-Specific: ARP Resolution Check**

VXLAN is an L2 overlay - the gateway needs to ARP for the remote gateway's MAC before sending packets.

If you see **ICMP Unreachable + No ARP packets**:
```
cluster2:
  ICMP Packets:
    ⚠ Unreachable (Egress): 20 packets - routing issue
  ✗ ARP packets: 0
```

**Diagnosis**: Gateway cannot resolve remote gateway MAC address
- Check VXLAN tunnel interface is UP
- Verify remote gateway reachability at L2
- Check VXLAN network connectivity (UDP port 4500)

If you see **ARP packets present**:
```
cluster1:
  ICMP Packets:
    ✓ Echo Request (Egress): 13 packets
  ✓ ARP packets: 5
```

**Diagnosis**: L2 connectivity working, ARP resolution successful

**DON'T conclude "tunnel working" from packet counts alone**:
```
WRONG Analysis:
  Tcpdump: 900 packets bidirectional → Tunnel working ✓

CORRECT Analysis:  
  Tcpdump cluster1: Echo Request (Egress) ✓
  Tcpdump cluster2: Unreachable (Egress) ✗
  → cluster2 has local routing issue preventing health checks
  → NOT a tunnel problem
```

### IPsec Cable Driver (libreswan) - Most Common Deployment

For IPsec deployments, tcpdump on `any` interface captures BOTH layers:

**Pre-Encapsulation Layer** (before IPsec encryption):
- Original ICMP packets (same detail as VXLAN above)
- **ICMP packet types**: Echo Request, Echo Reply, Unreachable
- **Direction**: Egress vs Ingress

**Post-Encapsulation Layer** (after IPsec encryption):
- ESP protocol packets (encrypted tunnel traffic)
- **Direction**: Egress vs Ingress
- Cannot decode payload (encrypted)

**Example Analysis**:
```
cluster1:
  ICMP Packets (pre-encapsulation):
    ✓ Echo Request (Egress): 13 packets
    ✓ Echo Request (Ingress): 1 packets
    ✓ Echo Reply (Egress): 1 packets
  ESP Packets (post-encapsulation):
    ✓ Egress: 15 packets (encrypted tunnel traffic)
    ✓ Ingress: 12 packets (encrypted tunnel traffic)

cluster2:
  ICMP Packets (pre-encapsulation):
    ⚠ Unreachable (Egress): 20 packets - routing issue
  ESP Packets (post-encapsulation):
    ✓ Egress: 18 packets
    ✓ Ingress: 14 packets
```

**Diagnosis from IPsec Patterns**:

**Pre-Encapsulation (ICMP)**:
- Use same diagnosis as VXLAN section above
- Shows health check behavior before encryption

**Post-Encapsulation (ESP)**:
- **Both Egress and Ingress > 0**: Tunnel established and working
- **Only Egress, no Ingress**: Tunnel one-way (infrastructure blocking?)
- **No Egress**: IPsec not encrypting (check IPsec SA status)

**Cross-Layer Validation**:
- **ICMP Egress but no ESP Egress**: IPsec encryption failing
- **ESP matches ICMP counts**: Healthy encryption pipeline
- **ESP higher than ICMP**: May include other traffic besides health checks

### Correlation with nftables Counters

**Don't conclude from pcap alone** - correlate with nftables:

**Pattern**: Egress ICMP but DNAT counter = 0
```
Evidence:
  (C) Tcpdump: 15 Echo Requests egress from cluster1
  (C) Tcpdump: 0 Echo Requests ingress at cluster2
  (B) cluster2 DNAT counter: 0
  
Conclusion: Packets leaving cluster1 but not reaching cluster2
  → Tunnel failure OR infrastructure blocking
```

**Pattern**: Egress + Ingress ICMP but DNAT counter = 0
```
Evidence:
  (C) Tcpdump: Bidirectional traffic confirmed
  (B) cluster1 DNAT counter: 0
  
Conclusion: Tunnel working but post-decapsulation routing broken
  → Packets reach gateway but not routed to ovn-k8s-mp0
```

## Important Reminders

1. **Cable driver awareness**: Only recommend checks relevant to the actual cable driver
2. **GlobalNet-specific**: SNAT/DNAT checks only apply when GlobalNet enabled
3. **Correlation required**: Don't conclude from nftables counters alone - use tcpdump
4. **Gateway nodes only**: Most checks only apply to active gateway node
5. **Version aware**: nftables only in 0.22+, use iptables for older versions
6. **Packet analysis**: Analyze pcap files for ICMP type and direction details
7. **IPsec pre/post-encapsulation**: Tcpdump on 'any' shows BOTH unencrypted ICMP AND encrypted ESP
8. **Tcpdump limitations**: Point-in-time sample - use nftables SNAT/DNAT for cumulative counts
