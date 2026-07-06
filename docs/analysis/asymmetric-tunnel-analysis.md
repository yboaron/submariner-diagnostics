# Asymmetric Tunnel Status Analysis

When one cluster shows "connected" but the other shows "error" or "connecting".

> **See also:** [datapath-architecture.md](datapath-architecture.md) - Submariner's datapath is asymmetric by design.
> This guide addresses asymmetric *tunnel status*, which is different from the normal asymmetric datapath.

## What is Asymmetric Status?

```text
Cluster1 → Cluster2: status=connected
Cluster2 → Cluster1: status=error
```

This indicates tunnel traffic can pass in at least one direction, but return path may have issues.

## Possible Causes

1. **Routing configuration issues** (gateway node showing "error")
2. **SNAT issues** (especially with OVN-Kubernetes local gateway mode)
3. **Asymmetric ACL/NAT/firewall filtering** (allows one direction, blocks return)
4. **Return-path filtering issues**

## Analysis Steps

### Step 1: Check CNI Type

Read Gateway CR from both clusters:

```bash
cluster*/gather/cluster*/submariners_submariner-operator_submariner.yaml
```

Look for `status.networkPlugin` field:

```yaml
status:
  networkPlugin: OVNKubernetes  # or Calico, etc.
```

### Step 2: Check RouteAgent Status Pattern (CRITICAL)

**Before investigating CNI-specific issues**, check if the error cluster shows a **mixed RouteAgent pattern**.

This is a key diagnostic clue that rules out infrastructure/firewall blocking.

#### Read RouteAgent Status on Error Cluster

```bash
# If cluster2 shows "error" status
grep -A10 "status:" cluster2/routeagents.yaml
```

**Look for the pattern:**
- SOME workers show `status: connected` (can ping remote healthCheckIP)
- SOME workers show `status: error` (cannot ping remote healthCheckIP)
- Gateway node shows `status: none` (expected - gateways don't ping themselves)

**Example mixed pattern:**
```yaml
# Worker 1
status: error
statusMessage: "Failed to successfully ping the remote endpoint IP 172.32.4.2"

# Worker 2
status: connected
latencyRTT: 4.45ms

# Worker 3
status: connected
latencyRTT: 4.40ms

# Gateway node
status: none
statusMessage: "Health check is not performed on gateway nodes"
```

#### Interpretation

**If mixed pattern detected:**
- ✅ This **rules OUT** infrastructure/firewall blocking
  - If firewall was blocking, ALL workers would fail
  - SOME workers succeeding proves tunnel datapath is reachable
  
- ✅ This **confirms** node-specific routing/SNAT issue
  - Gateway node or specific workers have routing misconfiguration
  - NOT a cross-cluster infrastructure problem
  
**Diagnosis:** Node-specific routing/SNAT issue (NOT infrastructure blocking)

**Next steps:**
- Compare routing tables on working vs failing worker nodes
- Check for SNAT configuration differences
- Verify OVN-K routing policies (if applicable)

**Skip infrastructure firewall investigation** - the mixed pattern proves connectivity is possible.

---

### Step 3: If CNI is OVN-Kubernetes

This configuration **might be affected by** a known issue with OVN-Kubernetes in local gateway mode.

#### Detect OVN-Kubernetes Gateway Mode

**Local gateway mode:** ALL nodes act as gateways  
**Shared gateway mode:** Only designated nodes

Detection methods:

**Method 1: Check for breth0 interface**

```bash
# In local mode: ALL nodes have breth0
# In shared mode: Only gateway nodes have breth0
grep -h "^[0-9]*: breth0:" cluster*/gather/cluster*/*_ip-a.log | wc -l
```

**Method 2: Check for per-node gateway routers**

```bash
# In local mode: ALL nodes have GR_<nodename> router
# In shared mode: Only gateway nodes have GR_ routers
grep -h "^name.*: GR_" cluster*/gather/cluster*/*_ovn_logical_routers.log | wc -l
```

**Detection Logic:**

- If `breth0_count == total_nodes` → Local gateway mode
- If `breth0_count < total_nodes` → Shared gateway mode

#### Check for Gateway vs RouteAgent Status Discrepancy

If local gateway mode is detected:

```bash
# Check Gateway CR status
grep -A5 "status:" cluster*/gather/cluster*/gateways_submariner-operator_*.yaml | grep "status:"

# Check RouteAgent CR status
grep -A30 "status:" cluster*/gather/cluster*/routeagents_*.yaml | grep "status:"
```

**Pattern indicating known issue:**

- Gateway CR: `status: error` with "Failed to successfully ping" message
- RouteAgent CR: `status: connected`
- Both clusters in local gateway mode

### Known Issue (OVN-K Local Gateway Mode)

This configuration **appears similar to** submariner-io/submariner#3857 where OVN's pod-subnet masquerade
may interfere with Submariner health check traffic.

**Use cautious language:**

- "This configuration appears similar to"
- "Might be related to"
- "Could potentially be addressed by"

#### References

- Issue: <https://github.com/submariner-io/submariner/issues/3857>
- Community workaround: <https://github.com/yboaron/submariner-workarounds/tree/main/ovn-local-gateway-health-check>

**Important:**

- This is a workaround, not an official fix
- **Only applicable to non-globalnet deployments** (does NOT work with Globalnet enabled)
- Review and test thoroughly before applying
- Consider potential side effects
- Alternative: Switch to shared gateway mode (requires cluster reconfiguration)

### Step 4: If CNI is NOT OVN-Kubernetes

This could be a routing configuration issue on the gateway node showing "error" status.

#### Check routing table

File: `cluster*/gather/cluster*/<gateway-node>_ip-routes-table150.log`

Verify routes exist for remote cluster CIDRs.

#### Check health check IP configuration

File: `cluster*/gather/cluster*/<gateway-node>_ip-a.log`

Search for the health check IP (from Gateway CR).

## Important Notes

- Asymmetric status suggests tunnel traffic can pass in at least one direction
- The cluster showing "connected" appears able to reach the other cluster
- Issue could be return-path routing, source IP modification, or asymmetric ACL/NAT/firewall filtering
- Use cautious language: "could be", "worth checking", "might be related to"
- One-way infrastructure filtering remains possible despite asymmetric status
