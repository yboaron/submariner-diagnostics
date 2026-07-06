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
- `ovn-k8s-mp0` interface: OVN management port (OVS internal port) - bridge between host stack and OVN logical network
- OVN logical router: `ovn_cluster_router`
- Routing tables: 149 (ingress) and 150 (egress)
- IP rules: Direct traffic to routing tables
- Two CRDs: `GatewayRoute` and `NonGatewayRoute`

**Critical Understanding:**
- `ovn-k8s-mp0` is NOT just a simple interface - it's an **OVS internal port**
- Routing TO ovn-k8s-mp0 = packet **enters** OVN logical network
- Routing FROM ovn-k8s-mp0 = packet **exits** OVN to host network stack
- **ALL nodes** (gateway and worker) send traffic into OVN first
- OVN configuration (policies + static routes) determines where packet exits

**Reference:**
- Code: `pkg/routeagent_driver/handlers/ovn/`
- Design: [Submariner OVN-K Support](https://github.com/submariner-io/enhancements/pull/163)

### Egress Path (Local Pod → Remote Cluster)

#### On Gateway Node:

```
Gateway Node
  └─ Pod (10.131.2.10)
       ↓ [OVN logical switch]
  └─ ovn_cluster_router
       ↓ [Standard OVN routing to destination]
  
  OR (for host networking pods like RouteAgent pinger):
  
  └─ Host networking pod
       ↓ [IP rule 150: to remote Globalnet CIDR lookup 150]
  └─ Routing table 150
       ↓ [Default route via ovn-k8s-mp0 nexthop]
  └─ ovn-k8s-mp0 interface (ENTERS OVN)
       ↓
  └─ ovn_cluster_router
       ↓ [Logical router policy - priority 20000]
       ↓ [Match: ip4.dst==10.130.0.0/16]
       ↓ [Nexthop: gateway's own ovn-k8s-mp0 IP (e.g., 10.131.0.2)]
       ↓ [OVN Static Route: ip_prefix=10.130.0.0/16, nexthop=10.131.0.2]
       ↓ [HAIRPIN: Route back to same node's ovn-k8s-mp0]
  └─ ovn-k8s-mp0 interface (EXITS OVN to host stack)
       ↓
  └─ Host network stack
       ↓ [XFRM policy matches]
  └─ IPsec tunnel (cable driver)
       ↓
Remote Gateway
```

**Key Insight - Gateway Hairpin:**
- Host networking traffic enters OVN via ovn-k8s-mp0
- OVN routes it back to the SAME node's ovn-k8s-mp0 (hairpin)
- Packet exits OVN into host stack where IPsec tunnel is

**Configuration (programmed by GatewayRouteController):**

```bash
# OVN Logical Router Policy (GATEWAY NODE ONLY)
_uuid               : xxx
action              : reroute
match               : "ip4.dst==10.130.0.0/16"
nexthops            : ["10.131.0.2"]  # Gateway's own ovn-k8s-mp0 IP
priority            : 20000

# OVN Logical Router Static Route (GATEWAY NODE ONLY)
_uuid               : xxx
ip_prefix           : "10.130.0.0/16"
nexthop             : "10.131.0.2"   # Gateway's own ovn-k8s-mp0 IP (hairpin!)

# IP Rule (ALL NODES - added by host_networking.go)
from all to 10.130.0.0/16 lookup 150

# Route in table 150 (ALL NODES - added by host_networking.go)
default via 10.131.0.1 dev ovn-k8s-mp0 table 150
# Nexthop discovered from cluster CIDR route on ovn-k8s-mp0
```

**Important:**

- OVN policies/routes only on gateway (GatewayRouteController checks nexthop == own mgmtIP)
- Host networking (IP rules + table 150) configured on ALL nodes by same code
- Nexthop is NOT the destination - just the gateway IP for ovn-k8s-mp0's subnet

#### On Non-Gateway Node:

```
Non-Gateway Node (worker)
  └─ Pod (10.131.1.16)
       ↓ [OVN logical switch]
  └─ ovn_cluster_router
       ↓ [Standard OVN routing to destination]

  OR (for host networking pods like RouteAgent pinger):
  
  └─ Host networking pod
       ↓ [IP rule 150: to remote Globalnet CIDR lookup 150]
  └─ Routing table 150
       ↓ [Default route via ovn-k8s-mp0 nexthop (e.g., 10.128.0.1)]
  └─ ovn-k8s-mp0 interface (ENTERS OVN)
       ↓
  └─ ovn_cluster_router
       ↓ [Logical router policy - priority 20000]
       ↓ [Match: ip4.dst==10.130.0.0/16]
       ↓ [Nexthop: gateway node's transit switch IP OR direct IP]
       ↓ [Action: Route to gateway node via OVN]
  └─ OVN transit network
       ↓ [OVN GENEVE tunnel to gateway node]
       ↓
Gateway Node
  └─ OVN receives packet
       ↓ [OVN Static Route: nexthop=gateway's ovn-k8s-mp0 IP]
  └─ ovn-k8s-mp0 interface (EXITS OVN to host stack)
       ↓
  └─ Host network stack
       ↓ [XFRM policy matches]
  └─ IPsec tunnel
       ↓
Remote Gateway
```

**Key Insight - Worker Path:**
- Host networking traffic enters OVN via worker's ovn-k8s-mp0
- OVN routes to gateway node via transit network
- Packet exits OVN at gateway's ovn-k8s-mp0 into host stack
- Gateway host stack forwards to IPsec tunnel

**Configuration (programmed by NonGatewayRouteController):**

```bash
# OVN Logical Router Policy (ALL NODES including gateway)
_uuid               : xxx
action              : reroute
match               : "ip4.dst==10.130.0.0/16"
nexthops            : ["<gateway-transit-ip>"]  # Gateway node's transit IP
priority            : 20000

# IP Rule (ALL NODES - added by host_networking.go)
from all to 10.130.0.0/16 lookup 150

# Route in table 150 (ALL NODES - added by host_networking.go)
default via 10.128.0.1 dev ovn-k8s-mp0 table 150
# Each node has different nexthop based on its own ovn-k8s-mp0 subnet
```

**Important:**
- NonGatewayRouteController runs on ALL nodes (including gateway)
- Skips processing if nexthop == local transit switch IP (avoid routing loop)
- Same host networking config (IP rules + table 150) on all nodes

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

**CR Creation (Active Gateway ONLY):**
- Creates `GatewayRoute` CRs (one per remote cluster)
  - Contains: Remote CIDRs + gateway's mgmtIP as nexthop
  - Source: `gateway_route_handler.go` (only when `IsOnGateway() == true`)
- Creates `NonGatewayRoute` CRs (one per remote cluster)
  - Contains: Remote CIDRs + gateway's transit IP as nexthop
  - Source: `non_gateway_route_handler.go`

**OVN Configuration (Controllers run on ALL nodes):**

**GatewayRouteController (ALL nodes, but only active on gateway):**
- Watches `GatewayRoute` CRs
- Only processes when CR's nexthop == this node's mgmtIP
- Programs on gateway node ONLY:
  - OVN Logical Router Policy (priority 20000, nexthop = own ovn-k8s-mp0 IP)
  - OVN Static Route (nexthop = own ovn-k8s-mp0 IP - enables hairpin)

**NonGatewayRouteController (ALL nodes including gateway):**
- Watches `NonGatewayRoute` CRs
- Skips if CR's nexthop == local transit switch IP (avoid loop)
- Programs on all nodes:
  - OVN Logical Router Policy (priority 20000, nexthop = gateway transit IP)

**Host Networking (ALL nodes - `host_networking.go`):**
- Programs IP rules for remote Globalnet CIDRs → table 150
- Programs table 150 default route via ovn-k8s-mp0
- Discovers nexthop from existing cluster CIDR route on ovn-k8s-mp0
- Same code runs on gateway and worker nodes

**Gateway-Specific:**
- Configures iptables FORWARD rules for cable ↔ ovn-k8s-mp0
- Handles MSS clamping (MSS = 1398 for 1500 MTU)

**Health check:**
- Same as non-OVN: Tests full egress+ingress path
- Egress: Pod → table 150 → ovn-k8s-mp0 (enter OVN) → OVN routing → ovn-k8s-mp0 (exit OVN) → IPsec
- Ingress: IPsec → table 149 → ovn-k8s-mp0 (enter OVN) → OVN → Pod

### Source IP Selection in Host Networking

**Critical Understanding:**

When table 150 routes via ovn-k8s-mp0:
```bash
default via 10.131.0.1 dev ovn-k8s-mp0 table 150
```

**Kernel selects source IP = ovn-k8s-mp0's own IP (NOT the nexthop!):**
- Nexthop: `10.131.0.1` (used for L2 forwarding within OVN)
- Source IP: `10.131.0.2` (the interface's assigned IP)

**Example:**
- Gateway node: ovn-k8s-mp0 IP = `10.131.0.2` → Source becomes `10.131.0.2`
- Worker node: ovn-k8s-mp0 IP = `10.128.0.2` → Source becomes `10.128.0.2`

**This source IP:**
- Is preserved through OVN routing
- Appears in IPsec tunnel packets
- Is used for health check responses

**Error Pattern - `0.0.0.0` source:**
If gateway logs show:
```
FATAL: sending packet: write ip 0.0.0.0->242.0.255.254: sendmsg: object is remote
```

This means **routing failed to select a source IP** - indicates table 150 route is missing or ovn-k8s-mp0 has no IP assigned.

### Common Misconceptions

**❌ WRONG:** "Gateway bypasses OVN, only workers use OVN"
**✓ CORRECT:** Both gateway and workers enter OVN via ovn-k8s-mp0. Gateway hairpins back to same node, workers exit at gateway node.

**❌ WRONG:** "Table 150 nexthop is the destination IP"
**✓ CORRECT:** Nexthop is the gateway IP for ovn-k8s-mp0's subnet. Kernel uses it for L2 forwarding, not as destination.

**❌ WRONG:** "ovn-k8s-mp0 is just a regular interface"
**✓ CORRECT:** It's an OVS internal port. Routing to it = enter OVN. Routing from it = exit OVN.

**❌ WRONG:** "Source IP becomes the nexthop (e.g., 10.131.0.1)"
**✓ CORRECT:** Source IP becomes ovn-k8s-mp0's own IP (e.g., 10.131.0.2).

### Pod Networking Datapath (Non-hostNetwork Pods)

**How regular pods communicate with remote clusters:**

Regular pods (without `hostNetwork: true`) don't use IP rules or routing tables.
Instead, OVN handles their routing entirely within the OVN datapath.

#### Pod Egress Flow (Gateway Node):

```
Pod (10.131.2.10)
  └─ veth pair → OVN logical switch (e.g., node_local_switch)
       ↓
  └─ OVN distributed router (ovn_cluster_router)
       ↓ [Check destination]
       |
       ├─ Local cluster traffic → Normal OVN routing to destination pod
       |
       └─ Remote cluster traffic (10.130.0.0/16):
            ↓ [Submariner Logical Router Policy - priority 20000]
            ↓ [Match: ip4.dst == 10.130.0.0/16]
            ↓ [Action: reroute, Nexthop: ovn-k8s-mp0 IP (10.131.0.2)]
            ↓
         ovn-k8s-mp0 (EXITS OVN to host stack)
            ↓
         Host network stack
            ↓ [XFRM policy matches destination]
         IPsec tunnel → Remote Gateway
```

**Key Difference from Host Networking:**
- **No IP rules** - Pod traffic enters OVN via veth pair, not via table 150
- **No table 150** - Routing decision happens entirely in OVN cluster router
- **Same OVN policies** - Submariner's priority 20000 policies apply to all traffic

#### Pod Egress Flow (Worker Node):

```
Pod (10.128.1.5)
  └─ veth pair → OVN logical switch (node_local_switch)
       ↓
  └─ OVN distributed router (ovn_cluster_router)
       ↓ [Check destination]
       |
       ├─ Local cluster traffic → Normal OVN routing
       |
       └─ Remote cluster traffic (10.130.0.0/16):
            ↓ [Submariner Logical Router Policy - priority 20000]
            ↓ [Match: ip4.dst == 10.130.0.0/16]
            ↓ [Nexthop: Gateway transit IP OR gateway node IP]
            ↓
         OVN transit network (GENEVE tunnel)
            ↓
         Gateway Node OVN
            ↓ [OVN Static Route: nexthop = gateway's ovn-k8s-mp0]
            ↓
         ovn-k8s-mp0 (EXITS OVN to host stack)
            ↓
         Host network stack → IPsec tunnel
```

**Same as host networking, but entry point differs:**
- Host networking: Enters via table 150 → ovn-k8s-mp0
- Pod networking: Enters via veth pair → OVN logical switch

#### OVN Logical Switch Topology:

```
Per-Node Setup:
  node_local_switch (e.g., compute-0)
    ├─ Pod veth pairs (10.131.2.0/24 subnet)
    └─ Router port → ovn_cluster_router

ovn_cluster_router (cluster-wide distributed router)
  ├─ Ports to each node_local_switch
  ├─ Default routes (programmed by OVN-K)
  └─ Submariner policies (priority 20000 - OVERRIDE defaults)
```

**How Submariner Overrides OVN-K:**
- OVN-K default policies: Lower priority (e.g., 1000-2000)
- Submariner policies: Priority 20000 (HIGHER)
- Result: Remote cluster traffic matches Submariner policy first

#### Pod Ingress Flow (Remote → Local Pod):

```
Remote Gateway
  └─ IPsec tunnel
       ↓
Gateway Node
  └─ IPsec decryption
       ↓ [Decrypted packet: src=10.130.0.5, dst=10.131.2.10]
       ↓ [IP rule 149: to 10.131.0.0/16 lookup 149]
  └─ Routing table 149
       ↓ [Default via ovn-k8s-mp0]
  └─ ovn-k8s-mp0 (ENTERS OVN)
       ↓
  └─ OVN cluster router
       ↓ [Check destination: 10.131.2.10]
       ↓ [Normal OVN routing - finds pod on compute-0]
       |
       ├─ Same node: Direct to local switch
       └─ Different node: GENEVE tunnel to destination node
            ↓
  └─ OVN logical switch (node_local_switch on compute-0)
       ↓
  └─ veth pair → Destination Pod (10.131.2.10)
```

**Key Point:**

- Ingress uses table 149 to enter OVN (via ovn-k8s-mp0)
- Once in OVN, standard OVN routing delivers to destination pod
- No special Submariner policies needed for ingress

### Ingress Path Deep Dive (Table 149)

**Purpose:** Route decrypted IPsec traffic back into OVN datapath.

**Configuration (Gateway Node Only):**

```bash
# IP Rule (programmed by host_networking.go)
# Matches LOCAL cluster CIDRs (not remote!)
from all to 10.131.0.0/16 lookup 149

# Table 149 Route
default via 10.131.0.1 dev ovn-k8s-mp0 table 149

# iptables/nftables FORWARD Rules (programmed by cable driver setup)
# Allow traffic between IPsec interface and OVN
-A SUBMARINER-FORWARD -i vx-submariner -o ovn-k8s-mp0 -d 10.131.0.0/16 -j ACCEPT
-A SUBMARINER-FORWARD -o vx-submariner -i ovn-k8s-mp0 -s 10.131.0.0/16 -j ACCEPT
```

**Why Table 149 is Needed:**

When IPsec decrypts a packet:
1. Packet emerges in host network stack with remote source IP
2. Destination is local cluster pod (e.g., 10.131.2.10)
3. Without table 149: Kernel would use main routing table (wrong path!)
4. With table 149: IP rule matches local CIDR → table 149 → ovn-k8s-mp0 → OVN

**Asymmetry:**
- **Egress:** Table 150 matches REMOTE cluster CIDRs
- **Ingress:** Table 149 matches LOCAL cluster CIDRs

**iptables FORWARD Rules:**

These are needed because:
- Packet arrives on cable interface (e.g., vx-submariner for VXLAN cable driver)
- Packet must forward through kernel to ovn-k8s-mp0
- Default FORWARD policy might be DROP
- Submariner explicitly allows cable ↔ ovn-k8s-mp0 forwarding

### Globalnet vs Non-Globalnet Behavior

**Non-Globalnet:**

Uses actual pod CIDRs directly:

```bash
# IP Rules
from all to 10.130.0.0/16 lookup 150  # Remote cluster pod CIDR
from all to 10.131.0.0/16 lookup 149  # Local cluster pod CIDR

# OVN Policies
match: "ip4.dst == 10.130.0.0/16"
```

**Advantages:**
- Simpler configuration
- No SNAT/DNAT overhead

**Requirements:**
- Pod CIDRs MUST NOT overlap between clusters
- Network must allow pod-to-pod routing

**Globalnet Enabled:**

Uses virtual Globalnet CIDRs:

```bash
# IP Rules
from all to 242.1.0.0/16 lookup 150  # Remote cluster Globalnet CIDR
from all to 10.131.0.0/16 lookup 149  # Local cluster pod CIDR (unchanged)

# OVN Policies
match: "ip4.dst == 242.1.0.0/16"  # Remote Globalnet CIDR
```

**SNAT/DNAT Handling:**
- **Egress:** Submariner SNATs source to local Globalnet IP (e.g., 242.0.5.10)
- **Ingress:** Submariner DNATs destination from Globalnet to actual pod IP
- Performed by Globalnet controller (separate from OVN routing)

**Advantages:**
- Allows overlapping pod CIDRs
- Works with private/non-routable pod networks

**Configuration Difference:**
- IP rule 150 points to remote Globalnet CIDR (not pod CIDR)
- OVN policies match Globalnet CIDRs
- Everything else identical

**Health Check IPs:**
- Non-Globalnet: Gateway endpoint IP (actual pod IP)
- Globalnet: Gateway Globalnet IP (virtual IP from 242.x.255.254 range)

### Complete Traffic Flow Example (Real IPs from Diagnostics)

**Scenario:** Worker node pinger → Remote cluster health check

**Environment:**
- Local cluster: Pod CIDR 10.128.0.0/14, Globalnet 242.0.0.0/16
- Remote cluster: Pod CIDR 10.96.0.0/14, Globalnet 242.1.0.0/16
- Gateway node: compute-2 (ovn-k8s-mp0: 10.131.0.2)
- Worker node: control-plane-0 (ovn-k8s-mp0: 10.128.0.2)
- Remote health check IP: 242.1.255.254

**Complete Flow:**

```
1. control-plane-0: RouteAgent pinger pod
   - Source: 10.128.x.x (actual pod IP)
   - Destination: 242.1.255.254 (remote health check)
   - Packet generated with ICMP Echo Request

2. control-plane-0: Kernel routing
   - IP rule matches: "from all to 242.1.0.0/16 lookup 150"
   - Lookup table 150: "default via 10.128.0.1 dev ovn-k8s-mp0"
   - Kernel selects source IP: 10.128.0.2 (ovn-k8s-mp0's own IP)
   - Packet: src=10.128.0.2, dst=242.1.255.254

3. control-plane-0: ovn-k8s-mp0 (ENTER OVN)
   - Packet submitted to OVS bridge
   - OVS delivers to OVN cluster router

4. control-plane-0: OVN cluster router
   - Match: ip4.dst == 242.1.0.0/16
   - Logical Router Policy (priority 20000): nexthop = 10.131.0.3 (gateway transit IP)
   - Decision: Route to gateway node via OVN transit network

5. OVN transit network
   - GENEVE encapsulation
   - Tunnel from control-plane-0 to compute-2 over underlay network
   - Packet still: src=10.128.0.2, dst=242.1.255.254 (inner packet)

6. compute-2: OVN receives packet
   - GENEVE decapsulation
   - OVN Static Route: ip_prefix=242.1.0.0/16, nexthop=10.131.0.2
   - Decision: Deliver to local ovn-k8s-mp0

7. compute-2: ovn-k8s-mp0 (EXIT OVN)
   - Packet emerges from OVS to kernel
   - Now in host network stack
   - Packet: src=10.128.0.2, dst=242.1.255.254

8. compute-2: Host routing + XFRM
   - Destination 242.1.255.254 matches XFRM policy
   - IPsec encapsulation (ESP)
   - Outer IP: src=<compute-2-public-IP>, dst=<remote-gateway-public-IP>
   - Inner IP: src=10.128.0.2, dst=242.1.255.254

9. Physical network
   - ESP packet traverses Internet/WAN
   - Arrives at remote gateway

10. Remote gateway
    - IPsec decryption
    - Inner packet extracted: src=10.128.0.2, dst=242.1.255.254
    - Table 149 routes to OVN
    - OVN delivers to health check service
    - Reply: src=242.1.255.254, dst=10.128.0.2

11. Return path (reverse flow)
    - Remote GW → IPsec → compute-2 → Table 149 → ovn-k8s-mp0 (enter OVN)
    - OVN routes to control-plane-0 via transit
    - control-plane-0: OVN → ovn-k8s-mp0 (exit) → kernel → pinger pod
    - Pinger receives ICMP Echo Reply
    - Health check: SUCCESS
```

**Source IP at Each Stage:**
- Stage 1: Pod IP (10.128.x.x)
- Stage 2: Becomes ovn-k8s-mp0 IP (10.128.0.2) ← **SNAT by kernel routing**
- Stages 3-7: Unchanged (10.128.0.2)
- Stage 8: Outer IP becomes public IP, inner still 10.128.0.2
- Stages 9-11: Inner IP unchanged through return path

**What This Shows:**
- Source IP changes ONLY at kernel routing (stage 2)
- OVN preserves source IP through transit network
- IPsec preserves inner IP (adds outer header)
- No additional SNAT by Submariner (Globalnet handles virtual IPs at different layer)

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

### Debugging OVN-Kubernetes Datapath

When investigating Submariner datapath issues with OVN-Kubernetes CNI, use this comprehensive guide. It covers:
- All traffic sources: host networking (hostNetwork pods) and pod networking
- All node types: gateway and non-gateway nodes
- SNAT handling: non-globalnet and globalnet configurations
- Verification: ensuring Submariner configured OVN-K correctly

This systematic top-down approach helps identify whether issues are in Submariner configuration or OVN-K platform behavior.

#### Step 1: Detect OVN-Kubernetes Topology

First, understand which OVN topology is deployed.

**Method 1: Check transit switch configuration**

From diagnostics:
```bash
cat cluster1/gather/cluster1/<worker-node>_ovn_nbctl_show.log | grep -E "switch.*transit|port tstor"
```

**Single Zone (Global) - Transit switch exists but NOT used for routing:**
```
switch <uuid> (transit_switch)
    port tstor-compute-0
        type: ""                    ← Empty = local
        addresses: ["... 169.254.0.1/16"]
    port tstor-compute-2
        type: ""                    ← All nodes have type: ""
        addresses: ["... 169.254.0.1/16"]  ← Same IP for all
```

**Characteristics:**
- All nodes have transit switch port with `type: ""` (empty = local)
- All nodes share same transit IP (e.g., 169.254.0.1)
- Transit switch exists but forwarding doesn't use it
- Direct routing between nodes within same OVN database

**Multi-Zone (OVN Interconnect) - Transit switch IS used for routing:**
```
switch <uuid> (transit_switch)
    port tstor-compute-0
        type: ""                    ← Local node
        addresses: ["... 100.88.0.2/16"]
    port tstor-compute-2
        type: remote                ← Remote = different zone
        addresses: ["... 100.88.0.5/16"]  ← Different IP per zone
```

**Characteristics:**
- Each zone has different transit IP range
- Gateway node port has `type: remote` from worker's perspective
- Transit switches connect zones via GENEVE tunnels
- Multiple OVN databases, one per zone

**Method 2: Check node annotations**

```bash
kubectl get node <gateway-node> -o yaml | grep -E "ovn-zone|transit-switch"
```

**Single zone:**
```yaml
k8s.ovn.org/ovn-zone: global
k8s.ovn.org/node-transit-switch-port-ifaddr: '{"ipv4":"169.254.0.1/16"}'
```

**Multi-zone:**
```yaml
k8s.ovn.org/zone-name: az2
k8s.ovn.org/node-transit-switch-port-ifaddr: '{"ipv4":"100.88.0.5/16"}'
```

---

#### Step 2: Understand Submariner Declarative APIs

Submariner uses Custom Resources to declare desired routing configuration.

**On Gateway Nodes: GatewayRoute CR**

Created by gateway RouteAgent for each remote cluster:

```bash
cat cluster1/gather/cluster1/gatewayroutes_submariner-operator_*.yaml
```

**Example:**
```yaml
apiVersion: submariner.io/v1
kind: GatewayRoute
metadata:
  name: cluster2  # Remote cluster name
  namespace: submariner-operator
spec:
  nextHops:
  - 10.131.0.2     # ovn-k8s-mp0 nexthop on gateway node
  remoteCIDRs:
  - 10.130.0.0/16  # Remote cluster pod CIDR
  - 172.31.0.0/16  # Remote cluster service CIDR
  # OR with Globalnet:
  # - 242.1.0.0/16  # Remote cluster globalnet CIDR
```

**Purpose:**
- Gateway declares: "Traffic to remote cluster CIDRs should be routed via ovn-k8s-mp0"
- GatewayRouteController programs OVN logical router on gateway node
- NextHop is the ovn-k8s-mp0 interface IP/nexthop

**On Non-Gateway Nodes: NonGatewayRoute CR**

Created by gateway RouteAgent (not by worker nodes!) for consumption by worker nodes:

```bash
cat cluster1/gather/cluster1/nongatewayroutes_submariner-operator_*.yaml
```

**Example (Multi-Zone):**
```yaml
apiVersion: submariner.io/v1
kind: NonGatewayRoute
metadata:
  name: cluster2
  namespace: submariner-operator
spec:
  nextHops:
  - 100.88.0.5     # Transit switch IP to gateway zone
  remoteCIDRs:
  - 10.130.0.0/16  # Remote cluster pod CIDR
  - 172.31.0.0/16  # Remote cluster service CIDR
```

**Example (Single Zone):**
```yaml
spec:
  nextHops:
  - 10.131.0.2     # Gateway node management IP
  remoteCIDRs:
  - 10.130.0.0/16
```

**Purpose:**
- Declares: "Workers should route remote traffic via transit switch (multi-zone) or gateway management IP (single-zone)"
- NonGatewayRouteController on workers programs OVN logical router
- NextHop depends on OVN topology (transit switch IP vs gateway IP)

**Key Difference:**
- **GatewayRoute**: Created on gateway, consumed by gateway
- **NonGatewayRoute**: Created on gateway, consumed by ALL nodes (including gateway)

---

#### Step 3: Verify Actual OVN Datapath Configuration

Now verify that Submariner correctly programmed OVN based on the CRs.

**A. Host Networking Layer (Programmed by RouteAgent)**

Submariner supports **two traffic sources**:

1. **Pod networking** - Pods with regular CNI networking  
   Traffic goes through OVN logical switches/routers naturally.

2. **Host networking** - Pods with `hostNetwork: true` (e.g., RouteAgent health check pods)  
   Traffic originates from host networking stack, must be routed to OVN.

For **host networking use case**, RouteAgent programs **IP rules + routing table 150**:

**IP Rules** (code: `pkg/routeagent_driver/handlers/ovn/south_rules.go:59-84`):
```bash
# Check IP rules - one per remote CIDR
ip rule show | grep 150

# Expected (example with Globalnet):
150:    from all to 242.1.0.0/16 lookup 150   # Remote globalnet CIDR

# OR without Globalnet (multiple rules):
150:    from all to 10.130.0.0/16 lookup 150  # Remote pod CIDR
150:    from all to 172.31.0.0/16 lookup 150  # Remote service CIDR
```

**Routing Table 150** (code: `pkg/routeagent_driver/handlers/ovn/host_networking.go:80-99`):
```bash
# Check default route in table 150
ip route show table 150

# Expected:
default via <ovn-k8s-mp0-nexthop> dev ovn-k8s-mp0
```

**What this does**:
- IP rules match traffic destined for **each remote cluster CIDR**
- Matched traffic routed via table 150 to ovn-k8s-mp0 (enters OVN dataplane)
- Traffic flows through ovn_cluster_router → gateway via Submariner pipeline
- **Critical for hostNetwork pods** (RouteAgent health checks run with hostNetwork: true)

**Complete Flow for Gateway Node (Non-Globalnet):**

1. **Host networking packet generated** (e.g., RouteAgent health check to remote CIDR)
2. **IP rule 150 matches**: `from all to <remote-CIDR> lookup 150`
3. **Table 150 route**: `default via <ovn-k8s-mp0-nexthop> dev ovn-k8s-mp0`
4. **Packet enters OVN** via ovn-k8s-mp0 interface
5. **OVN-K auto-SNATs** source IP → ovn-k8s-mp0 IP (e.g., 10.129.2.2, in pod CIDR range)
   - This is OVN-K behavior, not Submariner
   - Remote cluster sees traffic from pod CIDR IP, not host IP
6. **OVN Logical Router Static Route** matches: `<remote-CIDR> via <ovn-k8s-mp0-nexthop>`
   - Created by GatewayRoute CR
   - Routes to local gateway's IPsec tunnel
7. **Packet forwarded** to IPsec tunnel → remote cluster

**Complete Flow for Non-Gateway Node (Non-Globalnet):**

1. **Host networking packet generated** (e.g., RouteAgent health check to remote CIDR)
2. **IP rule 150 matches**: `from all to <remote-CIDR> lookup 150`
3. **Table 150 route**: `default via <ovn-k8s-mp0-nexthop> dev ovn-k8s-mp0` (SAME as gateway)
4. **Packet enters OVN** via ovn-k8s-mp0 interface
5. **OVN-K auto-SNATs** source IP → ovn-k8s-mp0 IP (SAME as gateway)
6. **OVN Logical Router Policy** matches (priority 20000, action: reroute)
   - Created by NonGatewayRoute CR
   - Nexthop: transit switch IP (multi-zone) or gateway IP (single-zone)
7. **Packet rerouted** through OVN Interconnect → gateway node → IPsec tunnel → remote cluster

**Complete Flow for Gateway Node (Pod Networking, Non-Globalnet):**

1. **Pod packet generated** (pod uses default pod networking, not hostNetwork)
2. **Already inside OVN** - pod connected to OVN logical switch
3. **OVN logical switch** → ovn_cluster_router
4. **OVN Logical Router Static Route** matches: `<remote-CIDR> via <ovn-k8s-mp0-nexthop>`
   - Created by GatewayRoute CR
   - Routes to local gateway's IPsec tunnel
5. **Packet forwarded** to IPsec tunnel → remote cluster
6. **Source IP**: Pod's original IP (from pod CIDR) - NO SNAT by OVN-K (prevented by annotation)

**Complete Flow for Non-Gateway Node (Pod Networking, Non-Globalnet):**

1. **Pod packet generated** (pod uses default pod networking, not hostNetwork)
2. **Already inside OVN** - pod connected to OVN logical switch
3. **OVN logical switch** → ovn_cluster_router
4. **OVN Logical Router Policy** matches (priority 20000, action: reroute)
   - Created by NonGatewayRoute CR
   - Nexthop: transit switch IP (multi-zone) or gateway IP (single-zone)
5. **Packet rerouted** through OVN Interconnect → gateway node → IPsec tunnel → remote cluster
6. **Source IP**: Pod's original IP (from pod CIDR) - NO SNAT by OVN-K (prevented by annotation)

**Summary - 4 Traffic Scenarios:**

| Scenario | Entry Point | OVN Routing | Source IP After OVN |
| -------- | ----------- | ----------- | ------------------- |
| **Gateway + Host Networking** | IP rule 150 → table 150 → ovn-k8s-mp0 | Static Route → tunnel | ovn-k8s-mp0 IP (pod CIDR) |
| **Gateway + Pod Networking** | Already in OVN switch | Static Route → tunnel | Original pod IP (pod CIDR) |
| **Non-GW + Host Networking** | IP rule 150 → table 150 → ovn-k8s-mp0 | Policy reroute → GW | ovn-k8s-mp0 IP (pod CIDR) |
| **Non-GW + Pod Networking** | Already in OVN switch | Policy reroute → GW | Original pod IP (pod CIDR) |

**Key Points:**
- **Host networking** needs IP rules + table 150 to enter OVN
- **Pod networking** already in OVN, no IP rules needed
- **Gateway** uses OVN Static Routes (from GatewayRoute CR)
- **Non-Gateway** uses OVN Policies with reroute (from NonGatewayRoute CR)
- **OVN-K auto-SNATs** only traffic entering via ovn-k8s-mp0 (host networking case)
- **Pod networking** preserves original pod IP (SNAT prevented by node annotation)

**SNAT Handling:**

**Non-Globalnet (prevent unwanted SNAT):**
- Submariner PREVENTS OVN-K from SNATing traffic to remote cluster CIDRs:
  1. **Node annotation**: Adds remote CIDRs to `k8s.ovn.org/node-ingress-snat-exclude-subnets`
  2. **ACCEPT rules**: Adds ACCEPT rules in NAT/SmPostRouting chain for each remote CIDR
- Check: `kubectl get node <node-name> -o jsonpath='{.metadata.annotations.k8s\.ovn\.org/node-ingress-snat-exclude-subnets}'`
- This prevents SNAT for **pod networking** traffic
- **Host networking** traffic still gets SNATed to ovn-k8s-mp0 IP (OVN-K behavior when entering via management port)

**With Globalnet (enforce SNAT):**
- All egress traffic SNATed to local cluster's globalnet CIDR via nftables
- Configured by Globalnet component (not RouteAgent OVN handlers)
- Applies to both host networking and pod networking traffic
- Not visible in diagnostics logs

**If IP rules missing:** RouteAgent failed to configure host networking.  
→ Check RouteAgent logs for errors  
→ Health checks from RouteAgent will fail (they use hostNetwork)

**B. OVN Logical Router Policy (Programmed by NonGatewayRouteController)**

On non-gateway nodes, verify OVN policy matches NonGatewayRoute CR:

From diagnostics:
```bash
cat cluster1/gather/cluster1/<worker-node>_ovn_policies.log | grep -B10 -A10 "submariner"
```

**Look for Submariner policy:**
```
_uuid               : <uuid>
action              : reroute
external_ids        : {submariner=release-0.24}
match               : "ip4.dst == <remote-cidr>"
nexthop             : "<nexthop-from-NonGatewayRoute>"
priority            : 20000
```

**Example (Multi-Zone):**
```
match               : "ip4.dst == 10.130.0.0/16"
nexthop             : "100.88.0.5"  # Transit switch IP
```

**Example (Single Zone):**
```
match               : "ip4.dst == 10.130.0.0/16"
nexthop             : "10.131.0.2"  # Gateway management IP
```

**Verify:**
- Policy exists ✓
- `match` includes remote cluster CIDR ✓
- `priority` is 20000 (higher than default OVN policies) ✓
- `nexthop` is not empty ✓
- `external_ids` contains "submariner" marker ✓

**What this does:**
- OVN logical router matches traffic to remote cluster CIDRs
- Reroutes to nexthop (either transit switch IP or gateway management IP)
- Priority 20000 ensures it overrides default OVN routing

**If policy missing:** NonGatewayRouteController on worker failed to program OVN. Check for:
- OVN connection errors in RouteAgent logs
- RBAC permission issues
- libovsdb errors

**C. Verify Configuration Consistency (CRITICAL)

This verifies that the declarative API (NonGatewayRoute) matches the actual datapath configuration (OVN policy).

**Check 1: NonGatewayRoute CR exists and has nextHops**

```bash
cat cluster1/gather/cluster1/nongatewayroutes_submariner-operator_*.yaml
```

Verify:
- CR exists ✓
- `spec.nextHops` is not empty ✓
- `spec.remoteCIDRs` matches remote cluster CIDRs ✓

**If nextHops is empty:** Gateway RouteAgent couldn't determine:
- Transit switch IP (multi-zone), OR
- Gateway management IP (single-zone)

Check gateway node OVN configuration and annotations.

**Check 2: OVN policy nexthop matches NonGatewayRoute nextHops[0]**

Compare values from Step 2 (NonGatewayRoute) and Step 3 (OVN policy):

| NonGatewayRoute nextHops[0] | OVN Policy nexthop | Diagnosis |
| --------------------------- | ----------------- | --------- |
| 100.88.0.5 | "100.88.0.5" | ✅ Configuration correct |
| 100.88.0.5 | "10.129.2.2" | ❌ Mismatch - NonGatewayRouteController failed to reconcile |
| 100.88.0.5 | (empty/missing) | ❌ No OVN policy created - OVN API access issue |
| [] (empty) | (any) | ❌ NonGatewayRoute invalid - gateway setup issue |

**If mismatch:** This indicates either:
1. NonGatewayRouteController bug (failed to reconcile)
2. OVN API access issue
3. RBAC permission problem

**D. Verify Transit Switch Topology (Multi-Zone Only)

When NonGatewayRoute uses transit switch nexthop (100.88.X or 169.254.X range), verify the transit switch topology:

**From diagnostics:**
```bash
cat cluster1/gather/cluster1/<worker-node>_ovn_nbctl_show.log | grep -B2 -A3 "tstor-"
```

**Expected for Multi-Zone (gateway node port from worker's view):**
```
port tstor-<gateway-node>
    type: remote        ← MUST be "remote"
    addresses: ["... 100.88.0.5/16"]
```

**What this means:**
- `type: remote` = gateway is in different OVN zone
- Traffic will use GENEVE tunnel (genev_sys_6081) to reach gateway zone
- This matches multi-zone OVN Interconnect topology

**If type is "" (empty):**
- Gateway is in SAME OVN zone as worker (single-zone)
- NonGatewayRoute nexthop should be gateway management IP, NOT transit switch IP
- Configuration error: NextHop doesn't match topology

---

#### Step 4: Verify Packet Flow (When Configuration is Correct)

When Steps 1-3 show configuration is correct but health checks still fail, verify actual packet flow.

**Understanding the expected flow:**

**For Host Networking Pods (e.g., RouteAgent health checks):**

Multi-Zone:
```
Host network stack → IP rule 150 → table 150 → ovn-k8s-mp0 → 
OVN reroute to transit switch → genev_sys_6081 → Gateway
```

Single-Zone:
```
Host network stack → IP rule 150 → table 150 → ovn-k8s-mp0 → 
OVN reroute to gateway IP → Gateway
```

**For Pod Networking Pods (regular pods):**

Multi-Zone:
```
Pod → OVN logical switch → OVN router policy → 
Reroute to transit switch → genev_sys_6081 → Gateway
```

Single-Zone:
```
Pod → OVN logical switch → OVN router policy → 
Reroute to gateway IP → Gateway
```

**Key difference:**
- Host networking: Uses IP rules + table 150 to enter OVN via ovn-k8s-mp0
- Pod networking: Already in OVN logical network, no IP rules needed

**Setup privileged debug pod on worker node:**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: ovn-debug
spec:
  hostNetwork: true
  nodeName: <worker-node>
  containers:
  - name: debug
    image: nicolaka/netshoot
    command: ["/bin/sleep", "3600"]
    securityContext:
      privileged: true
```

**Capture at key checkpoints:**
```bash
# In debug pod
# Checkpoint 1: Entering OVN
tcpdump -i ovn-k8s-mp0 -w /tmp/ovn-mp0.pcap 'icmp and host <remote-ip>' &

# Checkpoint 2: Geneve tunnel (check if packets use it)
tcpdump -i genev_sys_6081 -w /tmp/geneve.pcap icmp &

# Checkpoint 3: Physical egress
tcpdump -i ens192 -w /tmp/physical.pcap 'icmp or esp or (udp port 4500)' &

# Wait 5 minutes (RouteAgent health check pings every ~1 minute)
sleep 300
pkill tcpdump
```

**Note:** `<remote-ip>` can be:
- Remote cluster pod IP (e.g., 10.130.0.15)
- Remote cluster globalnet health check IP (e.g., 242.1.255.254)
- Remote cluster service IP (e.g., 172.31.0.10)

**Interpreting Results:**

**Pattern 1: Normal (Working)**
```
ovn-k8s-mp0:      10 packets (5 requests + 5 replies)
genev_sys_6081:   10 packets (encapsulated)  ← Multi-zone only
ens192:           Multiple ESP packets (IPsec encrypted)
```
✅ Full datapath works correctly.

**Pattern 2: Packets Not Entering OVN**
```
ovn-k8s-mp0:      0 packets
genev_sys_6081:   0 packets
ens192:           0 ICMP packets
```
❌ Host networking (IP rules or routing table 150) not configured.

**Pattern 3: Configuration Correct but OVN Not Forwarding**
```
ovn-k8s-mp0:      5 packets (requests only, no replies)
genev_sys_6081:   0 packets  (if multi-zone expected)
ens192:           5 ICMP packets (unencrypted! dest=<remote-ip>)
```
❌ **OVN-Kubernetes platform issue:** Packets are:
- Entering OVN via ovn-k8s-mp0 ✓
- NOT following configured OVN routing ✗  
- Exiting to physical network incorrectly ✗

**Analysis:**
- Steps 1-3 confirmed **Submariner configured everything correctly**:
  - OVN topology detected ✓
  - NonGatewayRoute CR exists with correct nextHops ✓  
  - OVN Logical Router Policy exists with matching nexthop ✓
  - Host networking (IP rules + table 150) configured ✓
- But OVN dataplane not honoring the configured policies ✗

**Conclusion:**  
→ **This does not appear to be a Submariner bug** - Submariner configuration looks correct.  
→ **This appears to be an OVN-Kubernetes platform issue** - OVN may not be forwarding per policies.  
→ Contact Submariner community with evidence from Steps 1-3:

- [Slack](https://kubernetes.slack.com/archives/C010RJV694M)
- [GitHub Issues](https://github.com/submariner-io/submariner/issues)

---

#### Summary: Top-Down Analysis Flow

1. **Detect OVN Topology** → Understand single-zone vs multi-zone
2. **Check Submariner APIs** → Verify NonGatewayRoute CR is created and valid
3. **Verify OVN Configuration** → Confirm RouteAgent programmed OVN correctly
4. **Test Packet Flow** → If config correct but failing, verify actual forwarding

This approach distinguishes:
- **Submariner issues**: API not created, or OVN not programmed to match API
- **Potential OVN-K platform issues**: Configuration correct but dataplane may not honor it
- **Setup issues**: Topology mismatch, missing annotations, RBAC problems

---

#### Common OVN Datapath Issues

**Issue 1: NonGatewayRoute Not Created**
- Gateway RouteAgent failed to create CR
- Check gateway node has transit switch IP annotation
- Verify gateway node is labeled as gateway

**Issue 2: NonGatewayRoute Has Empty NextHops**
- Gateway node couldn't determine transit switch IP
- Check gateway node OVN configuration
- Verify transit switch topology

**Issue 3: OVN Policy Not Created**
- Worker RouteAgent failed to program OVN
- Check RouteAgent logs for OVN API errors
- Verify RBAC permissions for OVN access

**Issue 4: Nexthop Mismatch**
- NonGatewayRoute was updated but worker hasn't reconciled
- Delete NonGatewayRoute (gateway will recreate it)
- If persists, report RouteAgent reconciliation bug

**Issue 5: Configuration Correct but Dataplane Broken**
- NonGatewayRoute correct ✓
- OVN policy correct ✓
- Nexthops match ✓
- Packet capture shows packets not following expected path ✗
- ovn-trace shows correct logical flow ✓

→ **Could indicate OVN dataplane issue** where logical configuration doesn't match actual forwarding.  
→ Report to OVN-Kubernetes/platform vendor with:
- NonGatewayRoute CR
- OVN policy listing (`ovn-nbctl list Logical_Router_Policy`)
- ovn-trace output
- Packet captures showing mismatch

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

## OVN-Kubernetes Troubleshooting Insights (from Testing)

### Table 150 Failure Symptoms

**What happens when table 150 route is missing on a node:**

1. **No packets reach ovn-k8s-mp0** - Kernel doesn't know how to route to remote CIDRs
2. **RouteAgent pinger fails** - "Failed to successfully ping the remote endpoint IP"
3. **Tcpdump shows zero packets** - `tcpdump -i ovn-k8s-mp0` captures nothing
4. **Segment 1 failure** - Local routing broken (Node → OVN entry point)

**Example:**
```bash
# Normal (working):
$ ip route show table 150
default via 10.130.2.1 dev ovn-k8s-mp0

# Broken (missing route):
$ ip route show table 150
<empty>

# Result: RouteAgent status = error, no packets on ovn-k8s-mp0
```

### Auto-Repair Mechanism

**route_config_syncer** automatically repairs deleted routes:
- Runs periodically in RouteAgent
- Recreates table 150 routes if missing
- Recovery time: seconds to minutes (depending on sync interval)
- Makes testing difficult - deleted routes may restore before diagnostics collected

**Implication for diagnostics:**
- Transient failures may not appear in offline analysis
- RouteAgent CR status persists longer than the actual failure
- Empty table 150 + RouteAgent error = recent failure or ongoing issue

### RouteAgent Pinger Timing

**Critical for tcpdump collection:**

- **Gateway node:** Pings frequently (~continuous stream)
- **Worker node (non-gateway):** Pings every **60 seconds**

**Impact on diagnostics:**
- Tcpdump on worker needs ≥90s capture window to catch 1-2 pings
- Gateway tcpdump can use shorter 30s window
- If table 150 missing: Zero packets regardless of capture duration

**Collection script timing:**
```bash
# Gateway: 30s capture (sufficient for frequent pings)
timeout 30 tcpdump -i ovn-k8s-mp0 -c 50

# Worker: 90s capture (catches 1-2 pings from 60s interval)
timeout 90 tcpdump -i ovn-k8s-mp0 -c 20
```

### Diagnostic File Locations

**Supplemental collection (bypasses subctl limitation):**

subctl gather only collects table 150 from gateway nodes. Offline diagnostics collection supplements this:

```
diagnostics/
├── cluster1/gather/cluster1/
│   ├── cluster1-worker_ip-routes-table150.log      ← Supplemental
│   ├── cluster1-worker2_ip-routes-table150.log     ← Supplemental
│   ├── cluster1-control-plane_ip-routes-table150.log ← Supplemental
│   └── ... (subctl gather files)
└── ovnk-pinger/
    ├── cluster1-worker-nodename-ovnk8smp0.pcap     ← Multi-checkpoint
    ├── cluster1-worker-nodename-any.pcap
    ├── cluster1-gateway-nodename-ovnk8smp0.pcap
    ├── cluster1-gateway-nodename-brex.pcap
    └── cluster1-gateway-nodename-any.pcap
```

**Analysis approach:**
1. Check table 150 on ALL nodes (not just gateway)
2. Check tcpdump for packet flow evidence
3. Correlate: missing table 150 + zero packets = Segment 1 failure

---

## References

- Non-OVN code: `pkg/routeagent_driver/handlers/kubeproxy/`
- OVN code: `pkg/routeagent_driver/handlers/ovn/`
- OVN design: [SEP-0027 OVN Interconnect](https://github.com/submariner-io/enhancements/blob/devel/seps/SEP-0027-ovn-interconnect.md)
- VXLAN interface: `pkg/routeagent_driver/handlers/kubeproxy/vxlan/`
