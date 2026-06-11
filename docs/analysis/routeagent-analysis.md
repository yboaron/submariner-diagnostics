# RouteAgent Health Analysis

How to analyze RouteAgent status and OVN-specific routing configuration.

> **See also:** [datapath-architecture.md](datapath-architecture.md) for detailed explanation of Submariner's asymmetric datapath
> (egress vs ingress paths differ).

## CRITICAL: Understanding Datapath Segments

**RouteAgent health checks test the FULL datapath, not just the tunnel!**

### Datapath Segments

```text
Cross-cluster pod connectivity requires TWO segments:

Segment 1: WorkerNode → LocalGW (intra-cluster routing)
Segment 2: LocalGW → RemoteGW (inter-cluster tunnel)

Complete path: WorkerNode → LocalGW → RemoteGW → RemotePod
```

### Health Check Coverage

**Gateway health check (Gateway CR status):**

- Tests: LocalGW → RemoteGW (tunnel segment only)
- Uses: Health check IP ping between gateways
- **Limitation:** Does NOT test local routing from worker nodes

**RouteAgent health check (RouteAgent CR status):**

- Tests: WorkerNode → LocalGW → RemoteGW (full datapath)
- Uses: Health check IP ping from worker nodes through local gateway to remote gateway
- **Advantage:** Tests both segments together

## Basic RouteAgent Health

### Data Source

File: `cluster*/routeagents.yaml`

### Check RouteAgent Status

```yaml
status:
  remoteEndpoints:
  - status: connected  # or error, connecting
    spec:
      cluster_id: remote-cluster
```

### Rules for Interpretation

- **Gateway nodes:** `status: none` = OK (expected - gateway doesn't check itself)
- **Non-gateway nodes:** `status: connected` = OK (can route through gateway to remote)
- **Non-gateway nodes:** `status != connected` = Problem (could be segment 1 or 2)

## CRITICAL: Datapath Segmentation Logic

**Use Gateway + RouteAgent status together to determine which segment is failing:**

### Pattern 1: Gateway "error" + RouteAgent "error"

```text
Gateway health check: error (LocalGW → RemoteGW fails)
RouteAgent health check: error (WorkerNode → LocalGW → RemoteGW fails)
```

**Analysis:**
→ **Segment 2 (tunnel) is broken**  
→ Focus on gateway-to-gateway issue FIRST  
→ RouteAgent errors are downstream effect of tunnel failure  
→ Don't investigate local routing until tunnel is fixed

**Next steps:**

- Focus on tunnel analysis (see [tunnel-analysis.md](tunnel-analysis.md))
- Check tcpdump data for infrastructure blocking
- Verify firewall inter-cluster test results

### Pattern 2: Gateway "error" + RouteAgent "connected"

```text
Gateway health check: error (LocalGW → RemoteGW reports failure)
RouteAgent health check: connected (WorkerNode → LocalGW → RemoteGW succeeds!)
```

**Analysis:**
→ **Tunnel datapath is actually working** (RouteAgent proves it)  
→ Gateway health check failure is misleading  
→ Most likely: Gateway health check IP configuration issue  
→ Could also be: Gateway-specific routing problem (host network vs pod network)

**Next steps:**

- Verify health check IPs are correctly configured
- Check if health check IP exists on gateway node (ip-a.log)
- Investigate why gateway pod health check fails despite datapath working
- Check gateway pod logs for health check errors

**Important:** This pattern indicates the tunnel IS functional! Don't waste time on infrastructure blocking investigation.

### Pattern 3: Gateway "connected" + RouteAgent "error"

```text
Gateway health check: connected (LocalGW → RemoteGW works)
RouteAgent health check: error (WorkerNode → LocalGW → RemoteGW fails)
```

**Analysis:**
→ **Segment 1 (local routing) is broken**  
→ Tunnel works, but worker nodes can't route to local gateway  
→ This appears to be a local routing issue (pending further validation with logs)

**Next steps:**

- Check routing table on worker nodes (ip-routes-table150.log)
- Verify routes to remote cluster CIDRs exist on worker nodes
- Check RouteAgent pod logs on failing nodes
- If OVN-K: Check OVN routing configuration

### Pattern 4: Both "connected"

```text
Gateway health check: connected
RouteAgent health check: connected
```

**Analysis:**
→ **Datapath is healthy**  
→ If connectivity issues exist, they're NOT in the Submariner datapath  
→ Look elsewhere (application-level, service discovery, etc.)

## OVN-Kubernetes Specific Checks

**Only applicable if CNI = OVNKubernetes**

### When to Check OVN Configuration

- Any tunnel connectivity failure with "Failed to successfully ping" errors
- Gateway pod showing "write ip 0.0.0.0" in logs
- OVN-Kubernetes CNI environments
- Non-gateway nodes succeed but gateway node fails

### API Server Health Check

File: `cluster*/gather/cluster*/<gateway-pod>-submariner-gateway.log`

Look for rate limiter errors:

```text
rate limiter Wait returned an error: rate: Wait(n=1) would exceed context deadline
```

**Analysis:**

- Count occurrences across the entire log file
- Example: 124 errors over 3 weeks could indicate API server instability
- **Possible Impact:** May contribute to resource sync issues, OVN controller stuck, routes not syncing
- **Note:** Unlikely to be direct root cause of "write ip 0.0.0.0" errors, but could contribute to instability

**Recommendation if found:**

```text
Consider checking API server health:
- oc adm top nodes (check control plane CPU/memory)
- Review API server logs for throttling/performance issues
- Verify etcd health is normal
- Check control plane resource utilization
```

### IP Rule Consistency Check

**CRITICAL:** Check for IP rule differences, especially `fwmark 0x3f0`

File: `cluster*/gather/cluster*/<nodename>_ip-rules.log`

Look for this rule:

```text
5999: from all fwmark 0x3f0 lookup main
```

#### Analysis Patterns

**Pattern 1: Cluster Asymmetry (LIKELY ISSUE)**

```text
cluster1: All nodes have "5999: from all fwmark 0x3f0 lookup main"
cluster2: NO nodes have this rule
```

→ This **appears to be** a likely root cause of connectivity failure

**Possible interaction with Gateway pod:**

This asymmetry suggests a possible routing interaction. To verify:

- Check if Gateway pod traffic carries `pkt_mark=1008` (0x3f0 in hex) in OVN logs
- Verify IP rule 5999 exists: `ip rule show`
- Confirm main routing table lacks routes to remote cluster CIDRs: `ip route show table main`
- Review gateway pod logs for sendmsg() permission errors

**If the interaction is confirmed:**

This likely requires investigation at the OVN-Kubernetes or infrastructure level. Consider:

- Reviewing OVN packet marking policies
- Checking if IP rule configuration is expected for the OVN-K version in use
- Consulting with networking team about IP rule asymmetry
- Checking OVN-Kubernetes documentation for known issues

**Why non-GW nodes might not be affected:**

Non-GW RouteAgent traffic may remain in OVN overlay routing and not match the packet marking criteria,
allowing table 150 routes to work normally.

**Pattern 2: Both Clusters Have It (OK)**

```text
cluster1: Has fwmark 0x3f0 rule
cluster2: Has fwmark 0x3f0 rule
```

→ Consistent configuration (issue is elsewhere)

**Pattern 3: Neither Has It (OK)**

```text
cluster1: No fwmark 0x3f0 rule
cluster2: No fwmark 0x3f0 rule
```

→ Consistent configuration (issue is elsewhere)

#### Verification Steps

1. Check ALL nodes in both clusters (rule should be present on all or none)
2. Look for OVN packet marking in `<nodename>_ovn_lr_ovn_cluster_router_policies.log`:

   ```text
   pkt_mark=1008
   ```

3. Verify main routing table has NO routes to remote clusters:

   ```bash
   grep -E "<remote-cidr-1>|<remote-cidr-2>" <nodename>_ip-routes.log
   ```

#### Possible Root Cause

- Rule appears to be added by OVN-Kubernetes (possibly version-specific)
- Could be related to AdminNetworkPolicy or NetworkPolicy features
- Consider checking OVN-K version differences between clusters

### OVN Logical Router Configuration

#### Step 1: Check OVN Logical_Router_Static_Route

File: `cluster*/gather/cluster*/<nodename>_ovn_lr_ovn_cluster_router_routes.log`

Expected:

```text
IPv4 Routes
Route Table <main>:
            172.32.0.0/16                172.28.4.2 dst-ip
            172.34.0.0/16                172.28.4.2 dst-ip
```

- Routes to remote cluster CIDRs should exist
- Nexthop should be local health check IP (e.g., 172.28.4.2 on ovn-k8s-mp0)
- Get remote CIDRs from Gateway CR `status.gateways[].connections[].endpoint.subnets[]`

#### Step 2: Check OVN Logical_Router_Policy

File: `cluster*/gather/cluster*/<nodename>_ovn_lr_ovn_cluster_router_policies.log`

Expected:

```text
Routing Policies
     20000                           ip4.dst == 172.32.0.0/16         reroute
     20000                           ip4.dst == 172.34.0.0/16         reroute
       102 ... && ip4.dst == ...     allow               pkt_mark=1008
```

- Priority 20000 policies for remote cluster CIDRs (reroute action)
- Priority 102 policies may mark certain traffic with pkt_mark=1008

**IMPORTANT:** If `pkt_mark=1008` is found AND `fwmark 0x3f0` IP rule exists:
→ This combination **appears to be** the likely cause of Gateway pod ping failure!

#### Step 3: Verify Main Routing Table

File: `cluster*/gather/cluster*/<gateway-node>_ip-routes.log`

Check that main table does NOT have remote cluster routes:

```bash
grep "<remote-cidr>" <gateway-node>_ip-routes.log
```

Expected:

- Main table should NOT have routes to remote clusters
- Submariner uses table 150 for remote cluster routing
- If main table HAS these routes → unusual configuration

#### Step 4: Check Table 150 (OVN Local Gateway Mode)

File: `cluster*/gather/cluster*/<gateway-node>_ip-routes-table150.log`

Expected for OVN local gateway mode:

```text
default via 172.28.4.1 dev ovn-k8s-mp0
```

NOT expected (but would work):

```text
172.32.0.0/16 via 172.28.4.2 dev ovn-k8s-mp0
172.34.0.0/16 via 172.28.4.2 dev ovn-k8s-mp0
```

**Analysis:**

- OVN local gateway mode uses OVN Logical_Router_Static_Route, NOT Linux table 150 routes
- Both gateway nodes (working and broken) have identical table 150: just default route
- Actual routing happens at OVN level, not Linux routing table level

## Important Notes

- RouteAgent logs should be checked for configuration errors
- If no errors exist, trust Submariner components
- Don't recommend manual iptables/nftables investigation unless logs indicate problems
- For OVN-K environments, check both Linux-level and OVN-level configuration
