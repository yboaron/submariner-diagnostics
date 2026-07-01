# Tunnel Health Analysis

This guide covers analyzing Submariner tunnel connectivity from collected diagnostic data.

> **See also:** [datapath-architecture.md](datapath-architecture.md) - Understanding Submariner's asymmetric datapath
> (egress via VXLAN/OVN, ingress via CNI routing) is essential for correct diagnosis.

## Data Sources

### Primary: Gateway CR Status

File: `cluster*/gather/cluster*/submariners_submariner-operator_submariner.yaml`

The Gateway CR is the authoritative source for tunnel status:

```yaml
status:
  gateways:
  - connections:
    - endpoint:
        backend: libreswan           # Cable driver type
        private_ip: 172.18.0.4
        public_ip: 1.2.3.4
      usingIP: 172.18.0.4            # IP actually being used
      status: error                   # Connection status
      statusMessage: "Failed to successfully ping the remote endpoint IP..."
      healthCheckIP: 242.0.255.254   # Remote cluster's health check IP target
```

### Important Fields

- `backend`: Cable driver (libreswan, wireguard, vxlan)
- `usingIP`: IP address being used for tunnel (private or public)
- `status`: Tunnel status (connected, error, connecting)
- `statusMessage`: Error details if status != connected
- `healthCheckIP`: Remote cluster's health check IP target

### Hosted Cluster Configuration

Check Submariner CR spec:

- `spec.hostedCluster`: If true, this is a hosted control plane deployment
- `spec.loadBalancerEnabled`: If true, load balancer services are used

## Analysis Steps

### Step 1: Read Gateway CR Status

Read the Gateway CR from both clusters and compare:

- Connection status (connected/error/connecting)
- Cable driver being used
- Which IP is being used (private vs public)

### Step 2: Check for Asymmetric Tunnel Status

**CRITICAL:** Check this before concluding infrastructure/firewall blocking.

Pattern:

```text
Cluster1 tunnel status: "connected"
Cluster2 tunnel status: "error" (or vice versa)
```

This asymmetric pattern could indicate:

- Routing/SNAT issue (worth checking if CNI is OVN-Kubernetes)
- Return-path filtering problem
- Asymmetric ACL/NAT/firewall filtering
- One-way infrastructure blocking (still possible)

**Important:** Use cautious language like "could be", "worth checking", "might be related to"

### Step 3: Verify IPsec Control Plane (if backend=libreswan)

File: `cluster*/gather/cluster*/<gateway-node>_ipsec-status.log`

Look for tunnel state:

```text
#222: "submariner-cable-..." STATE_V2_ESTABLISHED_IKE_SA
#224: "submariner-cable-..." STATE_V2_ESTABLISHED_CHILD_SA
```

**Expected:** All tunnels should show STATE_V2_ESTABLISHED_CHILD_SA

### Step 4: Check IPsec Datapath Traffic

File: `cluster*/gather/cluster*/<gateway-node>_ipsec-trafficstatus.log`

```text
#224: "submariner-cable-...", inBytes=0, outBytes=0
```

**Expected:** If tunnel is "connected", inBytes and outBytes should be > 0  
**Problem:** inBytes=0 and outBytes=0 indicates datapath failure despite control plane being up

### Step 5: Verify XFRM Policies

File: `cluster*/gather/cluster*/<gateway-node>_ip-xfrm-policy.log`

Check for bidirectional policies:

```text
src 10.130.0.0/16 dst 10.131.0.0/16
    dir out priority 1761505 ptype main
    tmpl src 172.18.0.5 dst 172.18.0.4
        proto esp reqid 16401 mode tunnel
```

**Expected:** Policies should exist for both directions (in/out) for pod and service CIDRs

### Step 6: Verify Routing

File: `cluster*/gather/cluster*/<gateway-node>_ip-routes-table150.log`

Check for routes to remote cluster CIDRs:

```text
10.131.0.0/16 dev eth0 proto static scope link src 10.130.1.1
```

**Expected:** Routes should exist for remote cluster's pod and service CIDRs

### Step 7: Verify Health Check IPs

File: `cluster*/gather/cluster*/<gateway-node>_ip-a.log`

Search for the health check IP (from Gateway CR):

```bash
grep "<healthCheckIP>" cluster*/gather/cluster*/<gateway-node>_ip-a.log
```

Look for health check IP on veth interfaces:

```text
inet 10.130.1.1/32 scope global veth...
```

**Analysis:**

- **If health check IP exists:** Issue is most likely NOT health check IP configuration - focus on datapath/infrastructure
- **If health check IP is missing:** Could indicate configuration issue

## Load Balancer Analysis (Hosted Clusters and Managed Cloud)

**CRITICAL:** LoadBalancer service fundamentally changes traffic flow and tcpdump analysis.

### Detection

Check Submariner CR:

```yaml
spec:
  loadBalancerEnabled: true  # LoadBalancer service is in use
```

If true, read the LoadBalancer service configuration.

File: `cluster*/gather/cluster*/services_submariner-operator_submariner-gateway.yaml`

### How LoadBalancer Changes Traffic Flow

**Without LoadBalancer:**

```
Incoming: RemoteIP:4500 → GatewayNode:4500 → GatewayPod:4500
Outgoing: GatewayPod:4500 → GatewayNode:4500 → RemoteIP:4500
```

**With LoadBalancer:**

```
Incoming: RemoteIP:4500 → LoadBalancer:4500 → GatewayNode:NodePort → GatewayPod:4500
Outgoing: GatewayPod:4500 → LoadBalancer:4500 → RemoteIP:4500
```

**Key difference:** Incoming traffic arrives on **NodePort**, not the service port!

### LoadBalancer Service Configuration

```yaml
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local  # or Cluster
  ports:
  - name: cable-encaps
    nodePort: 31410          # ← Incoming traffic arrives HERE
    port: 4500               # ← Service port (what remote sends to)
    protocol: UDP
    targetPort: 4500
  - name: natt-discovery
    nodePort: 30197
    port: 4490
    protocol: UDP
    targetPort: 4490
status:
  loadBalancer:
    ingress:
    - ip: 159.23.101.235     # LoadBalancer external IP
```

### Critical Checks for LoadBalancer

1. ✓ `spec.type: LoadBalancer`
2. ✓ `spec.externalTrafficPolicy`:
   - **`Local`** - Recommended for most deployments (preserves source IP)
   - **`Cluster`** - REQUIRED for hosted control plane clusters
   - Reference: <https://github.com/submariner-io/submariner-operator/commit/f14c74e0c8180a64e7f38a7a82afeedd45940147>
3. ✓ UDP ports exposed: 4490 (natt-discovery), 4500 (cable-encaps)
4. ✓ `status.loadBalancer.ingress[].ip` - Load balancer IP assigned
5. ✓ **NodePort allocation** - Check `spec.ports[].nodePort` values

### tcpdump Analysis with LoadBalancer

**CRITICAL:** tcpdump interpretation is DIFFERENT when LoadBalancer is enabled!

#### Old tcpdump collection (before ICMP capture)

If diagnostic was collected with older version (check capture filter):

```text
Capture Filter: udp port 4500
```

**Problem:** This filter will MISS incoming traffic because:

- Outgoing: Captured correctly (gateway pod → port 4500)
- Incoming: **NOT captured** (arrives on NodePort, e.g., 31410)

**Expected tcpdump pattern:**

```text
✓ Outgoing UDP port 4500 packets: YES (to remote LB IP)
✗ Incoming UDP port 4500 packets: NO (normal - arrives on NodePort instead!)
```

**DO NOT conclude "infrastructure blocking" based on this pattern alone!**

#### New tcpdump collection (with ICMP capture)

If diagnostic was collected with current version:

```text
Capture Filter: udp port 4500 or icmp
```

**Analysis approach:**

1. **Check outgoing UDP 4500:** Should see packets to remote LB IP
2. **Check incoming ICMP:** Should see health check pings arriving
3. **If ICMP arrives but tunnel still error:** Configuration issue, not infrastructure blocking
4. **If NO ICMP arrives:** Investigate further (could be infrastructure or health check IP issue)

#### Enhanced tcpdump collection (with NodePort capture)

**NEW:** If diagnostic was collected with LoadBalancer-enhanced version:

```text
Capture Filter: udp port 4500 or icmp or udp port 30443 or udp port 32567
LoadBalancer Service: Yes (IP: 169.63.205.145)
  NodePort mappings: 30443 -> 4500, 32567 -> 4490
```

**Enhanced statistics available:**

```text
CAPTURE STATISTICS:
  Tunnel packets (udp port 4500): 0
  ICMP packets: 12
  NodePort packets (udp port 30443 or udp port 32567): 523

NODEPORT TRAFFIC ANALYSIS:
  ✓ Traffic IS arriving on NodePorts (before OVN forwarding)
  ⚠ WARNING: NodePort traffic seen, but NO tunnel traffic on ports 4500/4490
     This suggests OVN is NOT forwarding NodePort -> gateway pod ports
```

**Analysis approach with NodePort capture:**

| NodePort Packets | Tunnel Packets | Failure Segment Identified              |
| ---------------- | -------------- | --------------------------------------- |
| 0                | 0              | LoadBalancer → NodePort                 |
| > 0              | 0              | NodePort → Gateway Pod (OVN/CNI)        |
| > 0              | > 0            | Normal operation (traffic flowing)      |
| 0                | > 0            | Unexpected (investigate pod network)    |

**Important:** Both failure segments are **outside Submariner's scope**:

1. **LoadBalancer → NodePort segment** - Involves cloud provider LoadBalancer, security groups, firewall rules, network policies
2. **NodePort → Gateway Pod segment** - Involves CNI (OVN-Kubernetes) or platform networking layer

The tcpdump analysis **identifies which segment is failing** to focus the investigation, but resolving these issues
requires troubleshooting the infrastructure/platform components, not Submariner itself.

### Common LoadBalancer Issues

#### 1. Wrong externalTrafficPolicy for Hosted Clusters

**Symptom:** IKE negotiation stuck at STATE_V2_PARENT_I1

**Cause:** `externalTrafficPolicy: Local` in hosted cluster deployment

**Fix:** Must use `externalTrafficPolicy: Cluster` for hosted clusters

```bash
# On the affected managed cluster
kubectl patch service -n submariner-operator submariner-gateway \
  --type merge \
  -p '{"spec": {"externalTrafficPolicy": "Cluster"}}'
```

#### 2. Load Balancer Not Forwarding UDP

**Symptom:** Firewall test passes, but tunnel still error

**Cause:** LoadBalancer configuration doesn't forward UDP correctly

**Check:**

- Cloud provider LoadBalancer supports UDP (some have limitations)
- Health check configuration (must allow UDP forwarding even when health check fails)

#### 3. NodePort Conflicts

**Symptom:** Intermittent connectivity issues

**Cause:** NodePort already in use by another service

**Check:** Verify NodePort values are unique across cluster

### Analysis Decision Tree for LoadBalancer

```text
If loadBalancerEnabled: true
  ↓
  Check LB service status.loadBalancer.ingress[].ip
    ↓
    If NO IP assigned:
      → LoadBalancer provisioning failed
      → Check cloud provider quota, permissions, subnet availability
    ↓
    If IP assigned:
      ↓
      Check externalTrafficPolicy
        ↓
        If hostedCluster: true AND externalTrafficPolicy: Local
          → CRITICAL: Must use "Cluster" for hosted clusters
          → This causes IKE failure
        ↓
        Check tcpdump capture filter
          ↓
          If "udp port 4500" only (old version):
            → DO NOT rely on tcpdump for incoming traffic analysis
            → Use firewall inter-cluster test results instead
            → Check for ICMP health check logs in gateway pod
          ↓
          If "udp port 4500 or icmp" (new version):
            → Check if ICMP health checks are arriving
            → If ICMP arrives: Configuration issue, not infrastructure
            → If ICMP doesn't arrive: Infrastructure or health check IP issue
```

### Verification Steps with LoadBalancer

**1. Verify LoadBalancer IP is reachable:**

```bash
# From external location or another cluster
nc -vzu <LB-IP> 4500
nc -vzu <LB-IP> 4490
```

**2. Check if LoadBalancer is forwarding to correct NodePort:**

```bash
# Check service configuration
kubectl get svc -n submariner-operator submariner-gateway -o yaml | grep -A 10 "nodePort:"
```

**3. Verify gateway pod is selected correctly:**

```bash
# LoadBalancer forwards to pods matching this selector
kubectl get svc -n submariner-operator submariner-gateway -o yaml | grep -A 5 "selector:"

# Should match: gateway.submariner.io/status: active
```

### Important Notes

- **LoadBalancer obscures tcpdump analysis** - incoming traffic arrives on NodePort, not service port
- **Old diagnostic collection** (without ICMP capture) cannot reliably detect infrastructure blocking when LoadBalancer is used
- **Firewall inter-cluster test** is more reliable indicator when LoadBalancer is enabled
- **Health check ping arrivals** (if captured) are the best indicator of connectivity when using LoadBalancer

## Diagnosis Patterns

### Pattern: Control Plane OK, Datapath Failed

```text
IPsec status: STATE_V2_ESTABLISHED_CHILD_SA ✓
Traffic counters: inBytes=0, outBytes=0 ✗
Gateway logs: No configuration errors ✓
```

→ Root cause is likely **infrastructure-level blocking** (firewall/network)  
→ Check tcpdump data to determine where packets are dropped

### Pattern: Asymmetric Status

```text
Cluster1: status=connected
Cluster2: status=error
```

→ Tunnel traffic appears able to reach cluster1  
→ Check for return-path routing issues, SNAT problems (OVN-K local gateway mode), or asymmetric filtering  
→ See asymmetric-tunnel-analysis.md for detailed investigation

## Important Notes

- Health check ping failures are SYMPTOMS of datapath issues, not root causes
- Look for configuration errors in logs - if none are found, the issue most likely appears to be infrastructure-level
  (based on available logs; offline or missing data could change this conclusion)
- ICMP health checks are INSIDE the IPsec tunnel - infrastructure only sees ESP/UDP packets
- Don't conclude "ICMP blocked by firewall" - it's incorrect
