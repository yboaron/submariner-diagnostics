# Special Cases and Edge Scenarios

## Context Name Conflicts (Informational)

### What It Is

Read manifest.txt for "Context Name Handling:" section. If present, both clusters had the same context name in their kubeconfig files.

```text
Context Name Handling:
  ⚠ Overlapping context names detected and auto-fixed
  Original cluster1 context: default-context
  Original cluster2 context: default-context
  Renamed cluster1 context: default-context-cluster1
  Action: Created temporary kubeconfig copy with renamed context
  Note: This was required because subctl verify needs unique context names
```

### Why This Matters

- `subctl verify` requires unique context names to distinguish between clusters
- If both kubeconfig files use the same context name (e.g., "default-context"), the verify command will fail
- The collection script automatically detects this and creates a temporary copy of one kubeconfig with a renamed context
- This is purely a collection-time fix; it doesn't affect the actual cluster configuration

### Analysis Implications

- **This is informational, not a fault**
- It means the diagnostic collection handled the prerequisite automatically
- Recommend users rename contexts permanently for clarity in future collections
- Not related to Submariner functionality issues

## OpenShift on OpenStack UDP Port Conflict

### When to Check

**Only check if ALL conditions are met:**

1. Tunnel is NOT connected on one or both clusters, OR NAT discovery failed in gateway logs
2. Environment is OpenShift on OpenStack (check for "openshift" + "openstack"/"nova" indicators in gathered data)

### Detection Steps

#### Step 1: Check Environment

Look for indicators in gathered data:

- Cluster version/platform information
- Node names containing "openstack" or "nova"
- Infrastructure provider indicators

#### Step 2: Check Gateway Logs

File: `cluster*/gather/cluster*/submariner-gateway-*-submariner-gateway.log`

Search for NAT discovery timeout:

```bash
grep -i "nat.*discovery.*timeout\|nat.*discovery.*failed" gateway.log
```

### If NAT Discovery Timeout Found

Add this to the ADDITIONAL RECOMMENDATIONS section of your analysis:

```text
HEADS-UP: Potential UDP Port Conflict (OpenShift on OpenStack)

Your environment appears to be OpenShift running on OpenStack, and we detected NAT
discovery timeout failures in the gateway logs. This could indicate a UDP port conflict
between Submariner and OpenStack infrastructure services.

**Known Issue:**
OpenStack infrastructure sometimes uses UDP ports in the 4490-4510 range, which conflicts
with Submariner's default ports:
  - ceIPSecNATTPort: 4500 (IPsec NAT-T)
  - nattDiscoveryPort: 4490 (NAT discovery)

**Evidence:**
  - Environment: OpenShift on OpenStack
  - NAT discovery timeout in gateway logs: <file:line>
  - Tunnel status: <error/connecting/not connected>

**Recommended Investigation:**

This could be the root cause of your tunnel connectivity issues. Consider investigating:

1. **Check if using ACM for Submariner deployment:**

   Look for SubmarinerConfig CR in gathered data (acm-addons.txt or submarinerconfig.yaml).

   If ACM deployment (SubmarinerConfig exists):
   → Changes must be made to **SubmarinerConfig CR on ACM hub cluster**
   → DO NOT modify Submariner CR directly (ACM addon will override it)

   If standalone deployment (no SubmarinerConfig):
   → Changes should be made to **Submariner CR** in each cluster

2. **Suggested port changes:**

   Use non-conflicting UDP ports outside the 4490-4510 range, for example:
   - ceIPSecNATTPort: 4500 → change to 4520
   - nattDiscoveryPort: 4490 → change to 4480

   **For ACM-Managed:**
   ```bash
   # On the ACM hub cluster
   kubectl patch submarinerconfig -n <managed-cluster-namespace> <config-name> \
     --type merge \
     -p '{"spec": {"ceIPSecNATTPort": 4520, "nattDiscoveryPort": 4480}}'
   ```

   **For Standalone:**

   ```bash
   # On each managed cluster
   kubectl patch submariner -n submariner-operator submariner \
     --type merge \
     -p '{"spec": {"ceIPSecNATTPort": 4520, "nattDiscoveryPort": 4480}}'

   kubectl delete pods -n submariner-operator -l app=submariner-gateway
   ```

1. **Further investigation:**

   - Verify which UDP ports OpenStack is using in your environment
   - Test connectivity with different port combinations
   - Monitor gateway logs after port changes for NAT discovery success

**Documentation:**
Refer to Submariner documentation for updating these settings.

```

### Important Notes

- This is a **potential** root cause, not a definitive diagnosis
- Use cautious language: "could indicate", "might be related to"
- Only mention this if NAT discovery timeout is actually detected
- This is environment-specific to OpenShift on OpenStack
- Not all OpenShift on OpenStack deployments will have this issue
