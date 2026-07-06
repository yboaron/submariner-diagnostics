# RouteAgent Health Analysis

How to analyze RouteAgent status and understand datapath segmentation.

> **Purpose:** Determine which datapath segment is failing to focus investigation correctly.

## CRITICAL: Understanding Datapath Segments

**RouteAgent health checks test the FULL datapath, not just the tunnel!**

### Datapath Segments

```text
Cross-cluster pod connectivity requires TWO segments:

Segment 1: Non-GW Node → Local-GW (intra-cluster routing)
Segment 2: Local-GW → Remote-GW (inter-cluster tunnel)

Complete path: Non-GW Node → Local-GW → Remote-GW
```

### Health Check Coverage

**Gateway CR health check:**
- **Tests:** Local-GW → Remote-GW (Segment 2 only)
- **Method:** Health check IP ping between gateways
- **Limitation:** Does NOT test local routing from worker nodes

**RouteAgent CR health check:**
- **Tests:** Non-GW → Local-GW → Remote-GW (Segments 1+2)
- **Method:** Health check IP ping from worker nodes through gateway to remote
- **Advantage:** Tests complete path

## Decision Matrix: Which Segment is Broken?

| Gateway CR Status | RouteAgent CR Status | Faulty Segment | Investigation Focus |
| ----------------- | -------------------- | -------------- | ------------------- |
| connected | connected | ✅ None | Datapath healthy - no OVN investigation needed |
| connected | error | 🔴 Segment 1 | Non-GW → Local-GW routing (IP rules, table 150, OVN policies) |
| error | connected | ⚠️ Unusual | Gateway health check fails but full path works - investigate GW check |
| error | error | 🔴 Segment 2 | Local-GW → Remote-GW tunnel (IPsec, firewall, cable driver) |

### Early Exit Optimization

**If Gateway=connected AND RouteAgent=connected:**
- ✅ **STOP** - Datapath is fully healthy
- No need to check OVN configuration
- No need to analyze tcpdump
- Report: "Submariner L3 connectivity appears healthy"

**If Gateway=connected AND RouteAgent=error:**
- 🔍 Focus ONLY on Segment 1 (local routing)
- Tunnel is working (Gateway CR proves it)
- Don't waste time on tunnel/firewall investigation
- Check: IP rules, table 150 routes, OVN policies

**If Gateway=error:**
- 🔍 Focus on Segment 2 FIRST (tunnel)
- Fix tunnel before investigating local routing
- See: [tunnel-analysis.md](tunnel-analysis.md)

## RouteAgent Status Analysis

### Data Source

**File:** `cluster*/routeagents.yaml`

**Format:**
```yaml
apiVersion: v1
items:
- metadata:
    name: worker-0
  spec:
    debug: false
  status:
    remoteEndpoints:
    - status: connected  # or error, connecting
      spec:
        cluster_id: cluster2
        health_check_ip: 10.130.1.2
- metadata:
    name: worker-1
  # ...
```

### Status Values

**connected:**
- Health check ping to remote gateway succeeded
- Full datapath (Segments 1+2) is working
- This node can reach remote cluster

**error:**
- Health check ping to remote gateway failed
- Either Segment 1 or Segment 2 is broken
- Need to correlate with Gateway CR to determine which

**connecting:**
- Submariner still establishing connection
- May indicate tunnel not ready yet

**(empty/no status):**
- Gateway nodes don't run health checks
- Gateway CR is the authoritative source for gateway health

### Correlation with Gateway CR

**Pattern 1: Gateway=connected, RouteAgent=error**

```yaml
# Gateway CR shows tunnel working
status:
  connections:
  - status: connected
    endpoint:
      cluster_id: cluster2

# But RouteAgent on worker shows error
# routeagents.yaml
- metadata:
    name: worker-0
  status:
    remoteEndpoints:
    - status: error
```

**Diagnosis:** Segment 1 failure (worker → gateway routing)

**What Submariner configures for Segment 1:**

**For Non-OVN CNIs (kindnet, Calico, etc.):**
- VXLAN interface `vx-submariner` on worker
- Route: `10.130.0.0/16 via 240.18.0.5 dev vx-submariner`
- VTEP endpoint: Gateway node IP

**For OVN-Kubernetes:**
- IP rules: `150: from all to 10.130.0.0/16 lookup 150`
- Table 150: `default via <nexthop> dev ovn-k8s-mp0`
- OVN router policies (multi-zone) or static routes (single-zone)

**Verification:**
- Non-OVN: Check `vx-submariner` interface exists, routes present
- OVN-K: Check IP rules, table 150, ovn-k8s-mp0 interface (see [ovn-offline-verification.md](ovn-offline-verification.md))

**Pattern 2: Gateway=error, RouteAgent=error**

```yaml
# Gateway CR shows tunnel broken
status:
  connections:
  - status: error
    statusMessage: "connecting to 172.18.0.5..."

# RouteAgent also shows error
- metadata:
    name: worker-0
  status:
    remoteEndpoints:
    - status: error
```

**Diagnosis:** Segment 2 failure (gateway → remote gateway tunnel)

**Investigation focus:**
- IPsec tunnel status (see [tunnel-analysis.md](tunnel-analysis.md))
- Firewall blocking (see [firewall-analysis.md](firewall-analysis.md))
- Cable driver issues (libreswan, wireguard, vxlan)

**Do NOT investigate local routing** until tunnel is fixed.

**Pattern 3: Gateway=connected, RouteAgent=connected**

```yaml
# Both show connected
status:
  connections:
  - status: connected

# routeagents.yaml
- metadata:
    name: worker-0
  status:
    remoteEndpoints:
    - status: connected
```

**Diagnosis:** Datapath fully healthy

**Action:** STOP - no further investigation needed

## CNI-Specific Datapath Components

### Non-OVN CNI (kindnet, Calico, Cilium, etc.)

**What RouteAgent configures:**

**On all nodes:**
1. VXLAN interface
   ```bash
   # ip link show vx-submariner
   vx-submariner: mtu 1400 qdisc noqueue state UNKNOWN
       link/ether ... brd ff:ff:ff:ff:ff:ff
   ```

2. Routes for remote clusters
   ```bash
   # ip route show
   10.130.0.0/16 via 240.18.0.5 dev vx-submariner onlink
   172.30.0.0/16 via 240.18.0.5 dev vx-submariner onlink
   ```

3. VTEP entries (remote node IPs)
   ```bash
   # bridge fdb show dev vx-submariner
   00:00:00:00:00:00 dst 172.18.0.5 self permanent  # Gateway node
   00:00:00:00:00:00 dst 172.18.0.6 self permanent  # Worker nodes
   ```

**Verification:**
- Interface exists: `ip link show vx-submariner`
- Routes present: `ip route show | grep vx-submariner`
- VTEP entries: `bridge fdb show dev vx-submariner`

### OVN-Kubernetes CNI

**What RouteAgent configures:**

**On all nodes (gateway and non-gateway):**

1. **IP Rules** - Direct traffic to routing tables

   ```bash
   # ip rule show | grep 150
   150: from all to 10.130.0.0/16 lookup 150  # Remote pod CIDR
   150: from all to 172.31.0.0/16 lookup 150  # Remote service CIDR
   150: from all to 242.254.0.0/16 lookup 150 # Remote globalnet (if enabled)
   
   # ip rule show | grep 149
   149: from all to 10.131.0.0/16 lookup 149  # Local pod CIDR (ingress)
   ```

2. **Routing Tables**

   ```bash
   # ip route show table 150
   default via 10.129.2.1 dev ovn-k8s-mp0
   
   # ip route show table 149
   default via 10.129.2.1 dev ovn-k8s-mp0
   ```

3. **ovn-k8s-mp0 Interface**

   ```bash
   # ip addr show ovn-k8s-mp0
   ovn-k8s-mp0: <BROADCAST,MULTICAST,UP> mtu 1400
       inet 10.129.2.2/23 scope global ovn-k8s-mp0
   ```

**On gateway node only:**

1. **OVN Logical Router Policies**

   ```bash
   # ovn-nbctl lr-policy-list ovn_cluster_router
   20000  ip4.dst==10.130.0.0/16  reroute  10.1.1.2
   ```

2. **OVN Static Routes**

   ```bash
   # ovn-nbctl lr-route-list ovn_cluster_router
   10.130.0.0/16  10.1.1.2
   ```

**Multi-zone topology differences:**
- Non-gateway nexthop: Transit switch IP (169.254.0.1 or 100.88.0.x)
- Gateway nexthop: ovn-k8s-mp0 IP (10.1.1.2)

**Verification:**
- See: [ovn-offline-verification.md](ovn-offline-verification.md) for complete checklist

## Common Issues and Patterns

### Issue 1: VXLAN Interface Missing (Non-OVN)

**Symptoms:**
- Gateway=connected, RouteAgent=error
- `ip link show vx-submariner` returns nothing

**What should be there:**
- RouteAgent creates `vx-submariner` interface on all nodes
- VXLAN ID: 100, UDP port: 4800

**Investigation:**
- Check RouteAgent logs for interface creation errors
- Verify node has VXLAN kernel module loaded

**Escalate if:**
- RouteAgent logs show no errors but interface still missing

### Issue 2: Table 150 Route Missing (OVN-K)

**Symptoms:**
- Gateway=connected, RouteAgent=error
- `ip route show table 150` is empty or missing ovn-k8s-mp0 route

**What should be there:**
```bash
default via <nexthop> dev ovn-k8s-mp0 table 150
```

**Investigation:**
- Check if ovn-k8s-mp0 interface exists
- Check RouteAgent logs for: `"error monitoring routing table for interface"`

**Escalate if:**
- ovn-k8s-mp0 exists and is UP
- IP rules are present
- But table 150 route still missing (likely OVN-K platform issue)

### Issue 3: OVN Policies Missing (OVN-K)

**Symptoms:**
- Gateway=connected, RouteAgent=error
- `ovn-nbctl lr-policy-list` shows no reroute policies for remote CIDRs

**What should be there:**
- Router policies with priority 20000
- Action: reroute to ovn-k8s-mp0 IP or transit switch IP

**Investigation:**
- Check if GatewayRoute/NonGatewayRoute CRs exist
- Check gateway RouteAgent logs for OVN configuration errors

**Escalate if:**
- CRs exist but OVN policies missing
- RouteAgent logs show no errors

## Analysis Workflow

### Step 1: Get Gateway and RouteAgent Status

```bash
# Gateway CR status
grep -A5 "status:" cluster1/gather/cluster1/gateway.yaml

# RouteAgent status for each node
grep -B2 -A5 "status:" cluster1/routeagents.yaml
```

### Step 2: Determine Faulty Segment

Use decision matrix above.

### Step 3: Focus Investigation

**If Segment 1 (local routing):**

- Non-OVN: Check VXLAN interface and routes
- OVN-K: Check IP rules, table 150, OVN policies (see [ovn-offline-verification.md](ovn-offline-verification.md))

**If Segment 2 (tunnel):**

- See: [tunnel-analysis.md](tunnel-analysis.md)
- See: [firewall-analysis.md](firewall-analysis.md)

### Step 4: Verify Configuration

**For Non-OVN:**
1. VXLAN interface exists
2. Routes present
3. VTEP entries present

**For OVN-K:**
1. IP rules present (all nodes)
2. Table 150/149 routes present (all nodes)
3. ovn-k8s-mp0 interface UP (all nodes)
4. OVN policies present (gateway only)

### Step 5: Escalate if Needed

**If all configuration is correct but connectivity fails:**

- Provide evidence (file contents, status outputs)
- Contact Submariner community:
  - [Slack](https://kubernetes.slack.com/archives/C010RJV694M)
  - [GitHub Issues](https://github.com/submariner-io/submariner/issues)

**Do NOT:**
- Deep-dive into CNI platform internals
- Manually modify VXLAN, OVN, or routing configuration
- Troubleshoot underlying CNI issues

## Summary

**RouteAgent CR tells you:**
- Whether full datapath works (Segments 1+2)
- Which nodes can reach remote clusters

**Gateway CR tells you:**
- Whether tunnel works (Segment 2 only)

**Together they tell you:**
- Which segment is broken
- Where to focus investigation

**Early exit:**
- Both connected → STOP, datapath healthy
- Gateway connected + RouteAgent error → Focus on local routing ONLY
- Gateway error → Fix tunnel first
