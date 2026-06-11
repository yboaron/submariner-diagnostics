# Gateway HA Status Analysis

How to verify correct Gateway High Availability configuration.

## Critical Principle

**Submariner only supports Active/Passive HA mode.**  
There should be EXACTLY 1 gateway labeled as "active" per cluster.

## Data Sources (In Priority Order)

### 1. Gateway CR (Authoritative Source)

File: `cluster*/gather/cluster*/submariners_submariner-operator_submariner.yaml`

```yaml
status:
  gateways:
  - haStatus: active
    localEndpoint:
      hostname: kube-xxxxx-node1  # Expected active node
  - haStatus: passive
    localEndpoint:
      hostname: kube-xxxxx-node2  # Expected passive node
```

**CRITICAL:** Gateway CR `status.gateways[].haStatus` is the source of truth, NOT pod labels.

### 2. Gateway Pod Labels (Secondary Check)

File: `cluster*/gather/cluster*/pods_submariner-operator_submariner-gateway-*.yaml`

```yaml
metadata:
  labels:
    gateway.submariner.io/status: active   # OR passive
  name: submariner-gateway-xxxxx
spec:
  nodeName: kube-xxxxx-node1
```

### 3. Load Balancer Configuration

File: `cluster*/gather/cluster*/submariners_submariner-operator_submariner.yaml`

```yaml
spec:
  hostedCluster: true          # Hosted cluster deployment
  loadBalancerEnabled: true    # Using LoadBalancer service
```

## Analysis Steps

### Step 1: Check Gateway CR HA Status

Read the Gateway CR and count how many gateways have `haStatus: active`:

**Expected:** Exactly 1 gateway with `haStatus: active`, rest with `haStatus: passive`  
**Critical Issue:** Multiple gateways with `haStatus: active` → Gateway HA election failure

### Step 2: Cross-Check Between Clusters

Verify both clusters agree on which gateway is active.

Compare `status.gateways[]` in both cluster1 and cluster2 Submariner CRs.

### Step 3: Check Load Balancer Usage

Determine if LoadBalancer service is in use:

```yaml
spec:
  hostedCluster: true
  loadBalancerEnabled: true
```

**Severity depends on LoadBalancer usage** (see below).

### Step 4: Check Pod Label Sync

Compare Gateway CR `haStatus` with pod labels `gateway.submariner.io/status`.

**Expected:** Pod labels should match CR haStatus  
**Issue:** Pod labels out of sync (multiple pods labeled "active")

## Severity Assessment

### WITHOUT LoadBalancer

```yaml
hostedCluster: false
# OR
loadBalancerEnabled: false
```

**Multiple pods labeled "active" = MINOR issue**

- Pod label sync issue
- Does NOT affect traffic routing
- Gateway CR is used for HA logic, not pod labels
- Impact: None (cosmetic issue)
- Recommendation: Monitor - pod labels should sync eventually

### WITH LoadBalancer

```yaml
hostedCluster: true
loadBalancerEnabled: true
```

**Multiple pods labeled "active" = CRITICAL issue**

Why this matters:

```yaml
# Load Balancer Service selector
spec:
  selector:
    app: submariner-gateway
    gateway.submariner.io/status: active  # Matches ALL pods labeled "active"
```

- If 2 pods labeled "active" → LB routes to both nodes
- Packets to correct node (actually active per Gateway CR) → succeed
- Packets to wrong node (labeled active, but passive per Gateway CR) → dropped
- Results in **~50% packet loss**
- Could explain intermittent connectivity issues

## Detection Patterns

### Pattern: Multiple Active Pods (Gateway CR Level)

```text
Gateway CR shows:
  - haStatus: active (hostname: node1)
  - haStatus: active (hostname: node2)
```

**Severity:** CRITICAL  
**Root Cause:** Gateway HA election failure  
**Impact:** Affects all traffic, regardless of LoadBalancer usage

### Pattern: Pod Label Sync Issue (LoadBalancer Disabled)

```text
Gateway CR shows: 1 active, 1 passive (CORRECT)
Pod labels show: 2 active, 0 passive (OUT OF SYNC)
LoadBalancer: DISABLED
```

**Severity:** MINOR  
**Root Cause:** Pod label sync delay  
**Impact:** None (Gateway CR is authoritative)

### Pattern: Pod Label Sync Issue (LoadBalancer Enabled)

```text
Gateway CR shows: 1 active, 1 passive (CORRECT)
Pod labels show: 2 active, 0 passive (OUT OF SYNC)
LoadBalancer: ENABLED
```

**Severity:** CRITICAL  
**Root Cause:** Pod label sync issue affecting LoadBalancer routing  
**Impact:** ~50% packet loss

## Recommended Fixes

### If LoadBalancer Enabled + Multiple Active Pod Labels

```bash
# IMMEDIATE FIX: Correct the passive pod label
kubectl label pod -n submariner-operator <passive-pod-name> \
  gateway.submariner.io/status=passive --overwrite
```

**Workaround (if issue recurs):**

⚠️ **This is a workaround, not a root-cause fix.** Enables cross-node forwarding and cluster-level load balancing
so ingress can reach pods on other nodes.

**Trade-offs:**

- Client source IP may no longer be preserved (SNAT may occur)
- Traffic paths change (potential hotspots or longer routes)
- Possible connection affinity issues
- May have security/audit implications

**Use temporarily while investigating the underlying gateway/node routing issue.**

```bash
# Change externalTrafficPolicy to allow cross-node forwarding
kubectl patch service -n submariner-operator submariner-gateway \
  --type merge -p '{"spec": {"externalTrafficPolicy": "Cluster"}}'
```

**Collect logs for bug report:**

```bash
# 1. Operator logs
kubectl logs -n submariner-operator deployment/submariner-operator > operator.log

# 2. Gateway pod logs (ALL pods)
kubectl logs -n submariner-operator submariner-gateway-xxxxx > gateway1.log
kubectl logs -n submariner-operator submariner-gateway-yyyyy > gateway2.log

# 3. File bug with Submariner project
# Title: "Gateway HA label sync race condition - multiple active pods with LoadBalancer"
# Include: Gateway CR, pod YAMLs, operator logs, gateway pod logs, release version
```

## Special Cases

### Random/Intermittent Failures

If the complaint mentions:

- "random failures"
- "intermittent connectivity"
- "works sometimes, fails other times"
- "breaks ODF-RDR randomly"
- "tunnel flapping"

**→ IMMEDIATELY CHECK:** Gateway HA labels for multiple active pods

This is the #1 cause of random/intermittent tunnel failures:

- Multiple active pods → load balancer splits traffic → ~50% packet loss
- Explains random success/failure pattern

### Incomplete Data (Gateway CR Missing)

If Gateway CR is not available:

```text
Cannot Determine Severity: Multiple Active Gateway Pods
  - subctl diagnose reports: Multiple gateway pods labeled "active"
  - Gateway CR: NOT AVAILABLE (gather failed)
  - Cannot determine: Which node is truly active per Gateway CR
  - Cannot check: If LoadBalancer service is enabled
  - Severity: UNKNOWN

RECOMMENDATION:
  1. Re-collect diagnostics to get Gateway CR
  2. OR manually check: kubectl get submariner -n submariner-operator -o yaml
  3. Check for LoadBalancer: spec.hostedCluster and spec.loadBalancerEnabled
  4. THEN apply severity logic based on LoadBalancer usage

DO NOT assume this is critical without verifying LoadBalancer usage.
```

## Important Notes

- Gateway CR is the authoritative source for HA status
- Pod labels are secondary - mismatches may not be critical
- LoadBalancer usage determines severity of pod label sync issues
- Multiple active pods in LoadBalancer mode = ~50% packet loss
