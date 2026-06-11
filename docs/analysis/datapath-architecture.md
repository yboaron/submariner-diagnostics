# Submariner Datapath Architecture

**CRITICAL:** Understanding Submariner's datapath is essential for diagnosing connectivity issues correctly.

> **Purpose of this document:**
> - For AI/human analyzers to **understand** how Submariner datapath works
> - Helps identify **which segment is broken** (egress vs ingress, segment 1 vs segment 2)
> - **NOT for end-user reports** - reports should identify the broken segment and point to Submariner experts
> - **DO NOT recommend** manual OVN rule changes, nftables modifications, or low-level kernel tweaks in reports

## Overview

Submariner uses **different datapath architectures** depending on the CNI plugin:

1. **Non-OVN CNIs** (kindnet, Calico, Cilium, etc.) - Asymmetric VXLAN + CNI routing
2. **OVN-Kubernetes** - OVN logical router policies + host networking

The datapath is **asymmetric** - egress and ingress traffic follow different paths.

---

## Non-OVN CNI Datapath (kindnet, Calico, Cilium, etc.)

### Egress Path (Local Pod → Remote Cluster)

Traffic from non-gateway nodes to remote clusters uses **VXLAN tunnel** to reach the gateway:

```
Non-Gateway Node (worker2)
  └─ Pod (10.131.1.16)
       ↓ [Route: 10.130.0.0/16 via 240.18.0.5 dev vx-submariner]
  └─ vx-submariner interface (240.18.0.6)
       ↓ [VXLAN tunnel - UDP port 4800]
       ↓ [Destination: Gateway node 172.18.0.5]
Gateway Node (worker)
  └─ vx-submariner interface (240.18.0.5)
       ↓ [VXLAN decapsulation]
  └─ Routing stack
       ↓ [IPsec encapsulation - ESP or UDP 4500]
       ↓ [Cable driver: libreswan/wireguard/vxlan]
  └─ Physical interface
       ↓
Remote Gateway Node
```

**Key configuration:**
- VXLAN interface: `vx-submariner` (created by RouteAgent)
- VXLAN ID: 100
- UDP port: 4800
- Remote endpoint: Gateway node IP (e.g., 172.18.0.5)
- Routes: `10.130.0.0/16 via 240.18.0.5 dev vx-submariner`

### Ingress Path (Remote Cluster → Local Pod)

Traffic from remote clusters to local pods **DOES NOT use VXLAN**:

```
Remote Gateway Node
       ↓ [IPsec tunnel - ESP or UDP 4500]
Gateway Node (worker)
  └─ Physical interface
       ↓ [IPsec decryption by cable driver]
  └─ Decrypted packet
       |  src: 10.130.0.15 (remote cluster pod)
       |  dst: 10.131.1.16 (local worker2 pod)
       ↓
  └─ CNI routing (NOT VXLAN!)
       ↓ [CNI must route to worker node]
       ↓ [Example: route via 172.18.0.6 dev eth0]
       ↓
Non-Gateway Node (worker2)
  └─ CNI bridge/interface
       ↓
  └─ Destination Pod (10.131.1.16)
```

**Key points:**
- **VXLAN is NOT used for ingress**
- After IPsec decryption, **CNI is responsible for routing**
- Gateway must have CNI routes to reach pods on worker nodes
- For kindnet: Routes like `10.131.1.0/24 via 172.18.0.6 dev eth0`
- For Calico: BGP-distributed routes
- For Cilium: Overlay or native routing

### Why rp_filter=1 is Intentional

Reverse path filtering (`rp_filter=1` - strict mode) is **deliberately enabled**:

```
Egress:  Pod → vx-submariner (240.18.0.x) → Gateway
Ingress: Gateway → eth0/CNI bridge → Pod
```

- Different interfaces for egress vs ingress
- Traffic is **asymmetric by design**
- `rp_filter=1` allows this asymmetric flow
- Return packets use different interface than outgoing packets

### RouteAgent's Role (Non-OVN)

**On all nodes:**
- Creates `vx-submariner` VXLAN interface
- Populates remote VTEP IPs (all cluster nodes)
- Adds routes for remote cluster CIDRs via vx-submariner
- Configures nftables/iptables rules for traffic forwarding

**Health check:**
- Tests full egress+ingress path: `WorkerNode → VXLAN → Gateway → IPsec → Remote → IPsec → Gateway → CNI → WorkerNode`
- If health check fails, check **both** VXLAN egress AND CNI ingress routing

---

## OVN-Kubernetes Datapath

OVN-K uses a **completely different architecture** - all datapath logic runs in the **RouteAgent pod**.

### Architecture Overview

**Key components:**
- `ovn-k8s-mp0` interface: OVN management interface for host networking
- OVN logical router: `ovn_cluster_router`
- Routing tables: 149 (ingress) and 150 (egress)
- IP rules: Direct traffic to routing tables
- Two CRDs: `GatewayRoute` and `NonGatewayRoute`

**Reference:**
- Code: `pkg/routeagent_driver/handlers/ovn/`
- Design: [SEP-0027 OVN Interconnect](https://github.com/submariner-io/enhancements/blob/devel/seps/SEP-0027-ovn-interconnect.md)

### Egress Path (Local Pod → Remote Cluster)

#### On Gateway Node:

```
Gateway Node
  └─ Pod (10.131.2.10)
       ↓ [OVN logical switch]
  └─ ovn_cluster_router
       ↓ [Logical router policy - priority 20000]
       ↓ [Match: ip4.dst==10.130.0.0/16]
       ↓ [Action: reroute to ovn-k8s-mp0 IP]
  └─ ovn-k8s-mp0 interface (e.g., 10.1.1.2)
       ↓ [Routing table 150]
       ↓ [Default route via ovn-k8s-mp0 nexthop]
  └─ Physical interface
       ↓ [IPsec encapsulation]
       ↓
Remote Gateway
```

**Configuration (programmed by GatewayRouteController):**

```bash
# OVN Logical Router Policy
_uuid               : xxx
action              : reroute
match               : "ip4.dst==10.130.0.0/16"
nexthops            : ["10.1.1.2"]  # ovn-k8s-mp0 IP
priority            : 20000

# OVN Logical Router Static Route
_uuid               : xxx
ip_prefix           : "10.130.0.0/16"
nexthop             : "10.1.1.2"   # ovn-k8s-mp0 IP

# IP Rule (added by RouteAgent)
from all to 10.130.0.0/16 lookup 150

# Route in table 150
default via <ovn-k8s-mp0-nexthop> dev ovn-k8s-mp0 table 150
```

#### On Non-Gateway Node (OVN Interconnect):

```
Non-Gateway Node (in zone AZ2)
  └─ Pod (10.131.1.16)
       ↓ [OVN logical switch - zone AZ2]
  └─ ovn_cluster_router (zone AZ2)
       ↓ [Logical router policy - priority 20000]
       ↓ [Match: ip4.dst==10.130.0.0/16]
       ↓ [Action: reroute to transit switch IP]
       ↓ [Nexthop: 169.254.0.1 - gateway zone transit switch]
  └─ OVN transit switch
       ↓ [OVN GENEVE tunnel between zones]
       ↓
Gateway Node (in zone GLOBAL)
  └─ (continues as gateway egress above)
```

**Configuration (programmed by NonGatewayRouteController):**

```bash
# OVN Logical Router Policy (non-gateway zone)
_uuid               : xxx
action              : reroute
match               : "ip4.dst==10.130.0.0/16"
nexthops            : ["169.254.0.1"]  # Transit switch IP to gateway zone
priority            : 20000
```

### Ingress Path (Remote Cluster → Local Pod)

```
Remote Gateway
       ↓ [IPsec tunnel]
Gateway Node
  └─ Physical interface
       ↓ [IPsec decryption]
  └─ Decrypted packet (src=10.130.0.15, dst=10.131.1.16)
       ↓ [IP rule: to 10.131.0.0/16 lookup 149]
  └─ Routing table 149
       ↓ [Default route via ovn-k8s-mp0]
  └─ ovn-k8s-mp0 interface
       ↓ [Enters OVN dataplane]
  └─ ovn_cluster_router
       ↓ [OVN routing to destination zone/node]
  └─ Destination Pod (10.131.1.16)
```

**Configuration:**

```bash
# IP Rule (added by RouteAgent)
from all to 10.131.0.0/16 lookup 149

# Route in table 149
default via <ovn-k8s-mp0-nexthop> dev ovn-k8s-mp0 table 149

# iptables/nftables FORWARD rules
# Allow traffic between cable interface and ovn-k8s-mp0
-A SUBMARINER-FORWARD -i <cable-intf> -o ovn-k8s-mp0 -d 10.131.0.0/16 -j ACCEPT
-A SUBMARINER-FORWARD -o <cable-intf> -i ovn-k8s-mp0 -s 10.131.0.0/16 -j ACCEPT
```

### RouteAgent's Role (OVN)

**On Gateway Node:**
- Creates `GatewayRoute` CRs (one per remote cluster)
- `GatewayRouteController` programs OVN logical router:
  - Logical router policies (priority 20000) to reroute remote traffic
  - Static routes for remote CIDRs
- Programs IP rules and routing tables (149, 150)
- Configures iptables FORWARD rules for traffic between cable interface and ovn-k8s-mp0
- Handles MSS clamping (MSS = 1398 for 1500 MTU)

**On Non-Gateway Nodes:**
- Creates `NonGatewayRoute` CRs (if OVN Interconnect enabled)
- `NonGatewayRouteController` programs OVN logical router:
  - Logical router policies to send traffic via transit switch to gateway zone
- Programs IP rules for host networking use cases

**Health check:**
- Same as non-OVN: Tests full egress+ingress path
- Egress: Pod → OVN → ovn-k8s-mp0 → IPsec
- Ingress: IPsec → ovn-k8s-mp0 → OVN → Pod

### OVN Interconnect vs Single Zone

**Single Zone (Global):**
- All nodes in one OVN zone: "global"
- Transit switch exists but not used for forwarding
- All nodes have transit switch IP: `169.254.0.1/16`

**Multi-Zone:**
- Multiple OVN databases, one per zone
- Transit switches connect zones via GENEVE tunnels
- Each zone has unique transit switch IP range
- Non-gateway nodes route remote traffic via transit switch to gateway zone

**Detection (from node annotations):**
```yaml
# Single zone
k8s.ovn.org/ovn-zone: global
k8s.ovn.org/ovn-node-transit-switch-port-ips: ["169.254.0.1/16"]

# Multi-zone
k8s.ovn.org/zone-name: az2
k8s.ovn.org/node-transit-switch-port-ifaddr: ["169.254.0.5/16"]
```

---

## Diagnostic Implications

### Common Misunderstandings

❌ **Wrong:** "VXLAN tunnel is bidirectional (non-OVN)"  
✓ **Correct:** VXLAN is egress-only; ingress uses CNI routing

❌ **Wrong:** "rp_filter=1 is blocking traffic"  
✓ **Correct:** rp_filter=1 is intentional for asymmetric datapath

❌ **Wrong:** "Check VXLAN FDB for ingress issues"  
✓ **Correct:** For ingress, check CNI routes on gateway node

❌ **Wrong:** "OVN uses VXLAN like other CNIs"  
✓ **Correct:** OVN uses logical router policies and ovn-k8s-mp0 interface

### Diagnosing Ingress Failures (Non-OVN)

If RouteAgent health check fails or pods can't reach remote clusters:

**Check CNI routing on gateway node:**

```bash
# 1. Does gateway have route to worker node pod subnets?
ip route show | grep <worker-pod-subnet>

# Example for kindnet:
# 10.131.1.0/24 via 172.18.0.6 dev eth0

# 2. Check routing table
ip route show table main

# 3. Verify pod subnet assignments per node
kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.podCIDR}{"\n"}'
```

**If CNI routes are missing:**
- Issue is with CNI, not Submariner
- kindnet: Check kube-proxy/CNI config
- Calico: Check BGP peering
- Cilium: Check overlay/native routing config

### Diagnosing Egress Failures (Non-OVN)

If traffic from worker nodes can't reach remote clusters:

**Check VXLAN configuration:**

```bash
# 1. Check vx-submariner interface exists
ip link show vx-submariner

# 2. Check VXLAN configuration
ip -d link show vx-submariner
# Look for: vxlan id 100 remote <gateway-ip> dstport 4800

# 3. Check routes
ip route show | grep vx-submariner
# Should see: 10.130.0.0/16 via 240.18.0.5 dev vx-submariner

# 4. Check nftables/iptables rules
nft list chain ip submariner SUBMARINER-FORWARD
```

### Diagnosing OVN Issues

**Check OVN logical router configuration:**

```bash
# 1. Check logical router policies (priority 20000)
ovn-nbctl lr-policy-list ovn_cluster_router

# Should see policies for remote CIDRs with reroute action

# 2. Check static routes
ovn-nbctl lr-route-list ovn_cluster_router

# 3. Check IP rules
ip rule show | grep -E "149|150"

# 4. Check routing tables
ip route show table 149
ip route show table 150

# 5. Check ovn-k8s-mp0 interface
ip addr show ovn-k8s-mp0
```

**For OVN Interconnect:**

```bash
# Check transit switch IP (from node annotations)
kubectl get node <node-name> -o yaml | grep -E "transit-switch|zone"

# Check if NonGatewayRoute CRs exist
kubectl get nongateways -n submariner-operator
```

### Packet Flow Verification

**Non-OVN egress trace:**
```bash
# From worker2, trace packet to remote cluster
traceroute -i vx-submariner 10.130.0.15
```

**Non-OVN ingress trace (on gateway):**
```bash
# Check if packets arrive after IPsec decryption
tcpdump -i eth0 'dst 10.131.1.16'

# Check if CNI forwards to worker node
tcpdump -i eth0 'dst 172.18.0.6'
```

**OVN trace:**
```bash
# Check IP rules are hit
ip -s rule show

# Check table 149/150 usage
ip route get 10.130.0.15 from 10.131.1.16 iif ovn-k8s-mp0
ip route get 10.130.0.15 from 10.131.1.16 oif ovn-k8s-mp0
```

---

## References

- Non-OVN code: `pkg/routeagent_driver/handlers/kubeproxy/`
- OVN code: `pkg/routeagent_driver/handlers/ovn/`
- OVN design: [SEP-0027 OVN Interconnect](https://github.com/submariner-io/enhancements/blob/devel/seps/SEP-0027-ovn-interconnect.md)
- VXLAN interface: `pkg/routeagent_driver/handlers/kubeproxy/vxlan/`
