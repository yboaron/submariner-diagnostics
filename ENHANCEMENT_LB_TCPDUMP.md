# Enhancement: LoadBalancer tcpdump Collection

## Summary

Enhanced tcpdump collection to capture NodePort traffic when Submariner gateway is exposed via LoadBalancer service. This helps diagnose connectivity issues in LoadBalancer deployments, particularly when using `externalTrafficPolicy: Cluster`.

## Problem Statement

When Submariner gateway uses a LoadBalancer service, the traffic flow is:

```
Remote Gateway → Remote LB → Local LB → NodePort (any node) → OVN → Gateway Pod (targetPort)
```

Previous tcpdump collection only captured traffic on gateway pod ports (4500, 4490), missing the critical NodePort layer where:
- LoadBalancer forwards traffic to NodePorts on cluster nodes
- OVN must forward from NodePort to gateway pod targetPort

This made it difficult to diagnose whether:
1. Traffic is reaching NodePorts from the LoadBalancer
2. OVN is forwarding NodePort traffic to the gateway pod

## Changes

### 1. LoadBalancer Service Detection

Added automatic detection of LoadBalancer service configuration:
- Service type (`LoadBalancer`)
- NodePort mappings (e.g., 30443 → 4500, 32567 → 4490)
- LoadBalancer IP
- External traffic policy (`Cluster` or `Local`)

### 2. Enhanced Capture Filters

When LoadBalancer is detected, tcpdump now captures:
- **Tunnel traffic** (UDP 4500/4490 or ESP) - existing
- **ICMP traffic** - existing
- **NodePort traffic** (e.g., UDP 30443, 32567) - **NEW**

Example capture filter with LoadBalancer:
```
udp port 4500 or icmp or udp port 30443 or udp port 32567
```

### 3. Enhanced Analysis

The analysis file now includes:

**LoadBalancer Configuration:**
```
LoadBalancer Service: Yes (IP: 169.63.205.145)
  NodePort mappings: 30443 -> 4500, 32567 -> 4490
  External Traffic Policy: Cluster
```

**NodePort Traffic Statistics:**
```
CAPTURE STATISTICS:
  Total packets captured: 1234
  Tunnel packets: 456
  ICMP packets: 12
  NodePort packets: 766

NODEPORT TRAFFIC ANALYSIS:
  ✓ Traffic IS arriving on NodePorts (before OVN forwarding)
  ⚠ WARNING: NodePort traffic seen, but NO tunnel traffic on ports 4500/4490
     This suggests OVN is NOT forwarding NodePort -> gateway pod ports
```

**NodePort Traffic Details:**
- First 30 packets with full details
- Source IPs (shows where traffic originates)
- Destination IPs (shows which nodes receive traffic)

## Diagnostic Value

This enhancement enables pinpointing the exact failure point:

| Scenario | NodePort Packets | Tunnel Packets | Diagnosis |
|----------|------------------|----------------|-----------|
| ✓ Both present | > 0 | > 0 | Normal operation |
| ✗ None arrive | 0 | 0 | LB not forwarding or firewall blocking |
| ✗ OVN not forwarding | > 0 | 0 | **OVN forwarding issue** (NodePort → pod) |
| ✗ Missing NodePorts | 0 | > 0 | Unexpected (pod receiving direct traffic?) |

## Use Cases

Particularly valuable for:
1. **Hosted Control Plane (HCP) deployments** - where LB is provided by host cluster
2. **IBM ROKS on KubeVirt** - nested virtualization with LoadBalancer
3. **OVN-Kubernetes local gateway mode** - complex routing scenarios
4. **externalTrafficPolicy: Cluster** - traffic can land on any node

## Example Output

### With LoadBalancer (traffic arriving):
```
✓ LoadBalancer service detected:
  LB IP: 169.63.205.145
  NodePorts: 30443 (4500), 32567 (4490)
  External Traffic Policy: Cluster

CAPTURE STATISTICS:
  NodePort packets: 523
  Tunnel packets: 489

NODEPORT SOURCE IPs:
    203   52.118.40.241
    152   10.129.2.124
```

### With LoadBalancer (OVN forwarding failure):
```
NODEPORT TRAFFIC ANALYSIS:
  ✓ Traffic IS arriving on NodePorts (before OVN forwarding)
  ⚠ WARNING: NodePort traffic seen, but NO tunnel traffic on ports 4500/4490
     This suggests OVN is NOT forwarding NodePort -> gateway pod ports
```

## Testing

Test scenarios:
1. ✅ Submariner with NodePort service (no LoadBalancer) - existing behavior unchanged
2. ✅ Submariner with LoadBalancer service - NodePorts captured
3. ✅ LoadBalancer with `externalTrafficPolicy: Local` - NodePorts captured
4. ✅ LoadBalancer with `externalTrafficPolicy: Cluster` - NodePorts captured on all nodes

## Files Modified

### 1. `collect-full-diagnostics.sh` (tcpdump collection)
  - Lines ~186-211: Added LoadBalancer detection
  - Lines ~212-240: Enhanced capture filters
  - Lines ~246-295: Enhanced analysis with NodePort statistics
  - Lines ~296-320: NodePort traffic detail analysis

### 2. `analyze-basic.py` (Python analyzer)
  - Added `extract_nodeport_packet_count()` method (line ~1450)
  - Added `check_ovn_forwarding_issue()` method (line ~1460)
  - Enhanced LoadBalancer analysis section (lines ~1276-1395):
    - Extracts NodePort packet counts from tcpdump analysis
    - Detects OVN forwarding failures (NodePort traffic but no pod traffic)
    - Detects LoadBalancer/firewall issues (no NodePort traffic)
    - Provides specific remediation steps for each issue type
    - Backward compatible with old tcpdump format

### 3. `docs/analysis/tunnel-analysis.md` (Claude-powered analysis knowledge base)
  - Added "Enhanced tcpdump collection (with NodePort capture)" section
  - Added analysis table for NodePort vs Tunnel packet patterns
  - Added OVN forwarding failure remediation steps
  - Added LoadBalancer/firewall issue remediation steps
  - Updated to reference new enhanced tcpdump capabilities

## Analyzer Enhancement (analyze-basic.py)

### New Methods

**`extract_nodeport_packet_count(analysis_content)`**
- Extracts NodePort packet count from tcpdump analysis file
- Returns 0 if not present (backward compatible)

**`check_ovn_forwarding_issue(analysis_content)`**
- Detects if analysis contains OVN forwarding warning
- Returns True if NodePort traffic present but no tunnel traffic

### Enhanced LoadBalancer Analysis

The analyzer now provides precise diagnosis:

#### Scenario 1: OVN Forwarding Failure
```
✗ Cluster1:
  NodePort traffic: 523 packets arriving
  Gateway pod traffic: 0 packets
  → OVN NOT forwarding NodePort -> gateway pod

OVN Forwarding Issue Detected:
  Traffic arrives at NodePorts but doesn't reach gateway pod

Recommendations:
  1. Restart ovnkube-node: oc delete pod -n openshift-ovn-kubernetes...
  2. Check OVN load balancer: oc debug node/<node> ovn-nbctl list load_balancer
  3. Check OVS flows: oc debug node/<node> ovs-ofctl dump-flows br-int
  4. Clear conntrack: oc debug node/<node> conntrack -F
```

#### Scenario 2: LoadBalancer/Firewall Issue
```
✗ Cluster2:
  NodePort traffic: 0 packets
  Gateway pod traffic: 0 packets
  → LoadBalancer not forwarding or firewall blocking

LoadBalancer/Firewall Issue Detected:
  No traffic arriving at NodePorts from LoadBalancer

Recommendations:
  1. Verify LoadBalancer backend pool includes cluster nodes
  2. Check cloud provider security groups allow UDP to NodePorts
  3. Verify firewall rules between LoadBalancers
  4. Check LoadBalancer health checks are passing
```

#### Scenario 3: Old Format Detection
```
⚠ PATTERN DETECTED:
  Outgoing UDP packets detected, no incoming on port 4500
  → LoadBalancer service is enabled - incoming traffic arrives on NodePort
  → Cannot reliably determine infrastructure blocking from tcpdump alone

Note: Old tcpdump format - recommend re-collecting with enhanced version
```

### Backward Compatibility

✅ Fully backward compatible:
- Non-LoadBalancer deployments unchanged
- Existing capture filters preserved
- Only adds additional filters when LoadBalancer is detected
- Analysis format extended (existing fields unchanged)
- Old tcpdump files still analyzed (with recommendation to re-collect)
- New methods return sensible defaults for old format

## Related Issues

- Addresses diagnostics gap identified in troubleshooting LoadBalancer deployments
- Complements existing tunnel traffic analysis
- Helps diagnose OVN forwarding issues in complex networking topologies
