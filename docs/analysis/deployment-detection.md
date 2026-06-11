# Deployment Type Detection

How to detect whether Submariner is deployed via ACM (ACM-Managed) or standalone.

## Why This Matters

**CRITICAL:** The deployment type determines where configuration changes must be made.

- **ACM-Managed:** Changes MUST be made to SubmarinerConfig CR on ACM hub cluster
  - DO NOT modify Submariner CR directly (ACM addon will override it)
- **Standalone:** Changes made to Submariner CR in each managed cluster

## Data Sources

Read both files from cluster1:

- `cluster1/acm-addons.txt`
- `cluster1/submarinerconfig.yaml`

## Detection Logic

### ACM-Managed Deployment

**If EITHER file contains actual resources** (not "No ... resources found"):

```text
Deployment Type: ACM-Managed

Configuration Requirements:
  - All changes must be made to SubmarinerConfig CR on ACM hub cluster
  - DO NOT modify Submariner CR directly (will be overridden)
  - ACM addon controller propagates changes to managed clusters
```

### Standalone Submariner Deployment

**If BOTH files say "No ... resources found":**

```text
Deployment Type: Standalone Submariner

Configuration Requirements:
  - Changes made to Submariner CR in each managed cluster
  - Direct kubectl patch/edit of Submariner CR
  - No ACM hub cluster involvement
```

## Example Detection

### Example 1: ACM-Managed

File: `cluster1/acm-addons.txt`

```yaml
apiVersion: addon.open-cluster-management.io/v1alpha1
kind: ManagedClusterAddOn
metadata:
  name: submariner
  namespace: cluster1
```

File: `cluster1/submarinerconfig.yaml`

```yaml
apiVersion: submarineraddon.open-cluster-management.io/v1alpha1
kind: SubmarinerConfig
metadata:
  name: submariner
  namespace: cluster1
spec:
  cableDriver: libreswan
```

→ **Deployment Type: ACM-Managed**

### Example 2: Standalone

File: `cluster1/acm-addons.txt`

```text
No resources found
```

File: `cluster1/submarinerconfig.yaml`

```text
No resources found
```

→ **Deployment Type: Standalone Submariner**

## Providing Deployment-Specific Instructions

### ACM-Managed Example

```bash
# INCORRECT (will be overridden):
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

# CORRECT (on ACM hub cluster):
kubectl patch submarinerconfig -n <managed-cluster-namespace> <config-name> \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

# ACM will propagate changes automatically to managed clusters
```

### Standalone Example

```bash
# CORRECT (on each managed cluster):
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

kubectl delete pods -n submariner-operator -l app=submariner-gateway
```

## Important Notes

- Always detect deployment type before providing configuration instructions
- Never give generic instructions that could apply to both
- ACM-managed deployments require hub cluster access
- Standalone deployments require access to each managed cluster
