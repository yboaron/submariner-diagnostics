# OVN-Kubernetes Configuration Verification

How to verify Submariner configured OVN-Kubernetes correctly from offline diagnostic logs.

> **Purpose:** Verify Submariner's configuration is present. If all config is correct but connectivity
> still fails, escalate to Submariner community - do NOT deep-dive into OVN platform internals.

## CRITICAL: Check Datapath Segmentation FIRST

**Before investigating configuration, determine which segment is failing:**

```
Full datapath: Non-GW → Local-GW → Remote-GW

Segment 1 (Local routing): Non-GW → Local-GW
Segment 2 (Inter-cluster): Local-GW → Remote-GW
```

**Decision Tree:**

| Gateway CR | RouteAgent CR | Investigation Focus                      |
| ---------- | ------------- | ---------------------------------------- |
| connected  | connected     | Datapath healthy - STOP HERE             |
| connected  | error         | Segment 1: Local routing (this guide)    |
| error      | connected     | Investigate GW health check issue        |
| error      | error         | Segment 2: Tunnel (tunnel-analysis.md)   |

**Early Exit:**
- If Gateway=connected AND RouteAgent=connected → Skip OVN verification entirely
- If Gateway=error AND RouteAgent=error → Fix tunnel first (Segment 2), then come back to this
- If Gateway=error AND RouteAgent=connected → Unusual case, investigate why GW health check fails despite full path working

## What Submariner Configures for OVN-K

Submariner configures different components based on node role and OVN topology.

### Use Case 1: Gateway Node (All Topologies)

**RouteAgent creates:**

1. **IP Rules** - Direct traffic to routing tables
   ```bash
   # Egress: Remote cluster CIDRs → table 150
   150: from all to 10.130.0.0/16 lookup 150
   150: from all to 172.31.0.0/16 lookup 150
   150: from all to 242.254.0.0/16 lookup 150  # If globalnet enabled
   
   # Ingress: Local cluster CIDRs → table 149
   149: from all to 10.131.0.0/16 lookup 149
   149: from all to 172.31.0.0/16 lookup 149
   149: from all to 242.254.0.0/16 lookup 149  # If globalnet enabled
   ```

2. **Table 150 Route** - Send to OVN datapath
   ```bash
   default via <nexthop> dev ovn-k8s-mp0 table 150
   # Nexthop discovered from ovn-k8s-mp0's default route
   ```

3. **Table 149 Route** - Receive from tunnel
   ```bash
   default via <nexthop> dev ovn-k8s-mp0 table 149
   ```

4. **OVN Logical Router Policies** - Reroute to ovn-k8s-mp0
   ```bash
   action: reroute
   match: "ip4.dst==10.130.0.0/16"
   nexthops: ["10.1.1.2"]  # ovn-k8s-mp0 IP
   priority: 20000
   ```

5. **OVN Static Routes** - Routing in OVN datapath
   ```bash
   ip_prefix: "10.130.0.0/16"
   nexthop: "10.1.1.2"  # ovn-k8s-mp0 IP
   ```

6. **GatewayRoute CR** - Declarative representation
   ```yaml
   kind: GatewayRoute
   spec:
     routePolicySpec:
       remoteCIDRs:
       - 10.130.0.0/16
       - 172.31.0.0/16
       nextHops:
       - 10.1.1.2  # ovn-k8s-mp0 IP or transit switch IP
   ```

### Use Case 2: Non-Gateway Node (Single-Zone)

**Same as Gateway node** - RouteAgent configures identical host networking components.

**Key difference:** NextHop in OVN policy points to gateway's ovn-k8s-mp0 IP (not transit switch).

### Use Case 3: Non-Gateway Node (OVN Interconnect / Multi-Zone)

**RouteAgent creates:**

1. **IP Rules** - Same as gateway
2. **Table 150/149 Routes** - Same as gateway
3. **OVN Logical Router Policies** - Different nexthop
   ```bash
   action: reroute
   match: "ip4.dst==10.130.0.0/16"
   nexthops: ["169.254.0.1"]  # Transit switch IP to gateway zone
   priority: 20000
   ```

4. **NonGatewayRoute CR**
   ```yaml
   kind: NonGatewayRoute
   spec:
     routePolicySpec:
       remoteCIDRs:
       - 10.130.0.0/16
       nextHops:
       - 169.254.0.1  # Transit switch IP
   ```

**Traffic flow:** Worker zone → Transit switch → Gateway zone → IPsec tunnel

### Use Case 4: Control-Plane Node

**Same as non-gateway worker nodes** - All nodes need host networking for submariner-route-agent pod.

## How to Verify Configuration

### Step 1: Identify Node Roles

**Files:**
- `cluster*/gather/cluster*/gateway.yaml` - Gateway CR
- `cluster*/routeagents.yaml` - RouteAgent CRs (all nodes)

**Find active gateway:**
```yaml
# In gateway.yaml
status:
  gateways:
  - haStatus: active
    localEndpoint:
      hostname: worker-0  # ← Active gateway node
```

### Step 2: Detect OVN Topology

**Files:**
- `cluster*/gather/cluster*/nongatewayroutes_*.yaml`

**Check nexthop:**
```yaml
spec:
  routePolicySpec:
    nextHops:
    - 169.254.0.1    # → Multi-zone (transit switch)
    - 100.88.0.2     # → Multi-zone (transit switch)
    - 10.129.0.2     # → Single-zone (gateway mgmt IP)
```

### Step 3: Verify Host Networking (All Nodes)

**Files needed per node:**
- `<node>_ip-rules.log`
- `<node>_ip-routes-table150.log`
- `<node>_ip-a.log`

**Check 1: IP Rules Present**
```bash
# Verify rules exist for remote CIDRs
grep "lookup 150" <node>_ip-rules.log
grep "lookup 149" <node>_ip-rules.log
```

**Check 2: Table 150 Route**
```bash
# Verify default route via ovn-k8s-mp0
grep "default via.*ovn-k8s-mp0" <node>_ip-routes-table150.log
```

**Check 3: ovn-k8s-mp0 Interface**
```bash
# Verify interface exists, is UP, and has IP
grep "ovn-k8s-mp0.*UP" <node>_ip-a.log
```

### Step 4: Verify OVN Policies (Gateway Node Only)

**Files:**
- `<gateway-node>_ovn-nbctl-lr-policy-list.log`
- `<gateway-node>_ovn-nbctl-lr-route-list.log`

**Check router policies:**
```bash
# Should see reroute policies for remote CIDRs
# Priority 20000, action=reroute, nexthops=[ovn-k8s-mp0 IP or transit IP]
grep "reroute" <gateway-node>_ovn-nbctl-lr-policy-list.log
```

**Check static routes:**
```bash
# Should see routes for remote CIDRs
grep "10.130.0.0/16" <gateway-node>_ovn-nbctl-lr-route-list.log
```

### Step 5: Verify CRs Present (v0.16.0+)

**Files:**
- `cluster*/gather/cluster*/gatewayroutes_*.yaml`
- `cluster*/gather/cluster*/nongatewayroutes_*.yaml`

**Check GatewayRoute:**
```yaml
# One per remote cluster on gateway node
kind: GatewayRoute
metadata:
  name: <gateway-node>-<remote-cluster-id>
spec:
  routePolicySpec:
    remoteCIDRs: [...]
    nextHops: [...]
```

**Check NonGatewayRoute:**
```yaml
# One per remote cluster on each non-gateway node
kind: NonGatewayRoute
metadata:
  name: <node>-<remote-cluster-id>
spec:
  routePolicySpec:
    remoteCIDRs: [...]
    nextHops: [...]
```

## Verification Results

### If ALL Checks Pass

**Configuration appears correct** - Submariner appears to have configured OVN-K as expected.

**Next steps:**
1. Check OVN-K pinger tcpdump to identify failed segment
2. If Segment 1 fails (traffic not reaching ovn-k8s-mp0) → Likely OVN-K platform issue
3. Contact Submariner community:
   - [Slack](https://kubernetes.slack.com/archives/C010RJV694M)
   - [GitHub Issues](https://github.com/submariner-io/submariner/issues)

**Do NOT:**
- Deep-dive into OVN platform internals
- Manually modify OVN policies or routes
- Troubleshoot OVN-K CNI issues

### If Configuration Missing

**IP rules missing:**
- Check RouteAgent logs for: `"error installing IPHook chain"`
- Check RouteAgent pod permissions (CNI plugin compatibility)

**Table 150 route missing:**
- Check RouteAgent logs for: `"error monitoring routing table for interface"`
- Verify ovn-k8s-mp0 interface exists

**OVN policies missing:**
- Check if GatewayRoute/NonGatewayRoute CRs exist
- Check gateway RouteAgent logs for OVN configuration errors

**If logs show errors:**
- Report to Submariner community with error messages
- Include Submariner version and OVN-K version

## OVN-K Pinger Tcpdump Analysis

**Purpose:** Identify which datapath segment failed when RouteAgent reports errors.

**Files:** `ovnk-pinger/*.pcap`

**Checkpoints:**
1. `ovn-k8s-mp0` - Entry to OVN datapath
2. `any` - All interfaces

**Analysis:**

**Worker node with RouteAgent error:**

| ovn-k8s-mp0 | Diagnosis |
| ----------- | --------- |
| Empty (0 bytes) | **Segment 1 FAILED** - Traffic not reaching OVN (table 150 missing or IP rules misconfigured) |
| Has packets | Segment 1 OK - Check if packets continue on 'any' interface |

**If Segment 1 fails:**
1. Verify table 150 route exists on the node
2. Verify IP rules exist
3. If both present → OVN-K platform issue, contact Submariner community

**If Segment 1 passes but RouteAgent still fails:**
- Check 'any' interface for tunnel traffic
- May be OVN routing issue or tunnel issue
- Contact Submariner community with tcpdump results

## Summary: What This Guide Does NOT Cover

**Out of scope (escalate to Submariner community):**
- OVN-K CNI platform issues
- OVN logical switch/router troubleshooting
- OVN database consistency issues
- GENEVE tunnel between OVN zones
- OVN-K upgrade/version compatibility
- Low-level iptables/nftables rules

**In scope:**
- Verify Submariner's configuration is present
- Identify which datapath segment failed
- Provide evidence for Submariner community escalation
