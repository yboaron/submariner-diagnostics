# MTU Issues Analysis

How to detect and diagnose MTU/fragmentation problems in Submariner connectivity.

## The Classic MTU Pattern (DEFINITIVE)

**CRITICAL:** Always compare both verify test results to detect MTU issues.

### Data Sources

- `verify/connectivity.txt` - Default packet size (~3000 bytes)
- `verify/connectivity-small-packet.txt` - Small packet size (400 bytes)

### Pattern That Confirms MTU Issue

```text
✗ Default packet test FAILS (may have stopped early after 6 failures)
✓ Small packet test SUCCEEDS
```

→ **ROOT CAUSE: MTU/fragmentation issue** (high confidence)

## Why This Indicates MTU

1. Large packets (~3KB) cannot traverse the network path due to MTU restrictions
2. Small packets (400 bytes) fit within MTU limits and succeed
3. If tunnels are connected but large packets fail, issue is NOT at tunnel level
4. Infrastructure allows the tunnel protocol (ESP/UDP) but fragments/drops large packets

## Important Distinctions

### Health Check Pings vs Data Transfer

**Health check pings:**

- Use small ICMP packets
- If health checks fail, MTU is NOT the root cause
- MTU issues only appear with large data transfers, not control plane

**Large data transfers:**

- Use full-size packets (~3KB in verify tests)
- Will fail if MTU is too low
- This is where MTU issues manifest

### Tunnel Status

- Tunnels may show "connected" status even with MTU issues
- Health checks still work (small packets)
- Only large data transfers reveal the problem

## Analysis Steps

### Step 1: Read Verify Test Results

File: `verify/connectivity.txt`

```text
Verification stopped early after 6 consecutive test failures
```

File: `verify/connectivity-small-packet.txt`

```text
✓ All tests passed
```

### Step 2: Confirm Pattern

If default fails but small packet succeeds → MTU issue confirmed

### Step 3: Check for Log Symptoms

Gateway logs may show:

```text
CREATE_CHILD_SA failed with TS_UNACCEPTABLE
```

**Important:** This is a SYMPTOM, not the root cause. The root cause is MTU restriction.

## Recommended Solutions

### Apply TCP MSS Clamping

Use Submariner's built-in MSS clamping feature to handle fragmentation:

```bash
# Apply MSS clamping annotation to gateway node
kubectl annotate node <gateway-node> submariner.io/tcp-clamp-mss=1300

# Restart routeagent pods to apply the changes
kubectl delete pod -n submariner-operator -l app=submariner-routeagent
```

**Recommended MSS value:** 1300 (conservative value for most networks)

**Documentation:** <https://submariner.io/getting-started/architecture/gateway-engine/> (Customize TCP MSS Clamping)

## Diagnostic Checklist

- [ ] Default packet verify test failed
- [ ] Small packet verify test succeeded
- [ ] Tunnels show "connected" status
- [ ] Health checks are passing
- [ ] Large data transfers fail

If all checked → **MTU issue confirmed**

## References

- Submariner troubleshooting: <https://submariner.io/operations/troubleshooting/>
- MTU and fragmentation issues in overlay networks
