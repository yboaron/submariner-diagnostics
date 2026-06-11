---
description: Analyze Submariner diagnostics offline from collected data
---

# Submariner Offline Analysis

> **See also:** [CLAUDE.md](CLAUDE.md) for repository overview and analysis principles.

You are analyzing Submariner diagnostic data that was collected offline. The user does NOT have live cluster access.

## Critical Analysis Principles

**IMPORTANT - READ FIRST:**

1. **Use Cautious Language** - "appears to be", "seems like", "most likely", "could be"
2. **Treat Infrastructure as Black Box** - Reference official docs, avoid deep technical dives
3. **Clearly Distinguish Workarounds from Fixes** - Label each, explain trade-offs
4. **Auto-Detect Deployment Type** - Check acm-addons.txt and submarinerconfig.yaml (see [deployment-detection.md](docs/analysis/deployment-detection.md))
5. **Focus on Direct Remediation** - Provide kubectl commands, not subctl deploy
6. **Check for Asymmetric Tunnel Status FIRST** - Before concluding firewall blocking (see [asymmetric-tunnel-analysis.md](docs/analysis/asymmetric-tunnel-analysis.md))

## Your Task

### Phase 1: Get Input Parameters

- This command can be invoked as `/submariner:analyze-offline <diagnostics-path> [complaint]`
- `diagnostics-path`: Path to tarball (*.tar.gz) or extracted directory
- `complaint`: User's description of the issue (optional, can read from manifest.txt)

#### Ask for (if not provided)

- Path to diagnostic data
- Description of issue (if not in manifest.txt)

#### Issue type options (user-friendly)

1. "Tunnel not connected / connection down"
2. "Connectivity issues / cannot reach pods"
3. "Suspect firewall or other infrastructure issue"
4. "Pods failing / crashing"
5. "Service discovery not working"
6. "General health check / not sure"

### Phase 2: Extract and Validate Diagnostic Data

#### If tarball provided

1. Extract to temporary directory
2. Find extracted directory (format: `submariner-diagnostics-TIMESTAMP/`)

#### Validate data structure

```text
diagnostics-dir/
├── manifest.txt (timestamp, complaint, kubeconfig info)
├── collection.log (complete collection output, check for errors)
├── cluster1/
│   ├── gather/ (subctl gather output)
│   ├── subctl-show-all.txt
│   ├── subctl-diagnose-all.txt
│   ├── routeagents.yaml
│   ├── acm-addons.txt
│   └── submarinerconfig.yaml
├── cluster2/ (optional)
├── verify/ (optional)
└── tcpdump/ (optional)
```

#### Read manifest.txt

- Extract timestamp, complaint, clusters collected
- Check for context name handling (overlapping contexts auto-fixed)
  - See: [special-cases.md](docs/analysis/special-cases.md#context-name-conflicts-informational) for explanation

#### Check collection.log for errors

- `subctl gather` failures
- tcpdump DaemonSet creation failures
- kubectl exec file extraction errors

#### Check for Submariner Deployment

Collection script validates Submariner is deployed before collecting. If "Submariner not deployed" error
appears, the diagnostic data is not valid.

#### Detect Deployment Type (CRITICAL)

**See:** [deployment-detection.md](docs/analysis/deployment-detection.md)

Read `cluster1/acm-addons.txt` and `cluster1/submarinerconfig.yaml`:

- **If EITHER contains resources** → ACM-Managed
- **If BOTH say "No resources found"** → Standalone Submariner

### Phase 3: Determine Analysis Focus

#### CRITICAL CHECKS (Always performed early)

1. **Gateway CR HA Status** - Only ONE Gateway should have `haStatus: active`
   - See: [gateway-ha-analysis.md](docs/analysis/gateway-ha-analysis.md)
   - This is authoritative source (not pod labels)
   - Multiple active = critical faulty state

2. **RouteAgent Health Check Status** - Determines which datapath segment is failing
   - See: [routeagent-analysis.md](docs/analysis/routeagent-analysis.md)
   - **CRITICAL for datapath segmentation:**
     - WorkerNode → LocalGW → RemoteGW (full path)
     - Gateway checks: LocalGW → RemoteGW (tunnel segment only)
     - RouteAgent checks: WorkerNode → LocalGW → RemoteGW (full path including local routing)

   **Interpretation:**
   - **Gateway "error" + RouteAgent "error"** → Focus on GW-to-GW tunnel segment FIRST
   - **Gateway "error" + RouteAgent "connected"** → Investigate why GW health check fails despite RouteAgent success
   - **Gateway "connected" + RouteAgent "error"** → Focus on local routing (WorkerNode → LocalGW)
   - **Both "connected"** → Datapath is healthy, issue elsewhere

3. **Endpoint Consistency** - Both clusters should see same Endpoint resources

4. **OVN-Kubernetes Local Gateway Mode Issue** - Check for known health check issue
   - Detection: CNI is OVN-K, local gateway mode, status=error with ping failure
   - See: [asymmetric-tunnel-analysis.md](docs/analysis/asymmetric-tunnel-analysis.md)
   - Known issue: submariner-io/submariner#3857

#### Route to appropriate analysis based on complaint

1. **"tunnel not connected"** → [tunnel-analysis.md](docs/analysis/tunnel-analysis.md)
   - If OVN-K: Check API server health, IP rule consistency, OVN routing (see [routeagent-analysis.md](docs/analysis/routeagent-analysis.md))

2. **"pods failing"** → Pod health analysis

3. **"connectivity issues"** → Check both tunnel and routing
   - **PRIORITY:** Compare verify tests - if regular fails but small packets pass = MTU issue
   - See: [mtu-analysis.md](docs/analysis/mtu-analysis.md)
   - **CRITICAL:** Check Gateway HA labels - multiple active = ~50% packet loss

4. **"firewall"** → [firewall-analysis.md](docs/analysis/firewall-analysis.md) (tcpdump analysis)

5. **"service discovery"** → Service discovery analysis

6. **"general health check"** → Comprehensive analysis
   - Always check MTU pattern if verify tests exist

#### SPECIAL ATTENTION - Random/Intermittent Failures

If complaint mentions "random", "intermittent", "works sometimes":

- **IMMEDIATELY CHECK:** Gateway HA labels (see [gateway-ha-analysis.md](docs/analysis/gateway-ha-analysis.md))
- #1 cause of random failures: multiple active pods → ~50% packet loss

### Phase 4: Read Diagnostic Files

#### Key files by analysis type

**A. Always Read:**

1. `cluster*/subctl-show-all.txt` - Connection status
2. `manifest.txt` - Metadata

**B. For Tunnel Issues:**

- See: [tunnel-analysis.md](docs/analysis/tunnel-analysis.md)
- Gateway CR, ipsec-status, ipsec-trafficstatus, ip-xfrm-policy, ip-routes-table150
- Gateway and RouteAgent logs

**C. For Firewall Issues:**

- See: [firewall-analysis.md](docs/analysis/firewall-analysis.md)
- `tcpdump/*-analysis.txt` (TEXT - always read these first)

**D. For MTU Issues:**

- See: [mtu-analysis.md](docs/analysis/mtu-analysis.md)
- `verify/connectivity.txt` and `verify/connectivity-small-packet.txt`

**E. For Gateway HA:**

- See: [gateway-ha-analysis.md](docs/analysis/gateway-ha-analysis.md)
- Gateway CR `status.gateways[].haStatus`, pod labels, LoadBalancer config

**F. For RouteAgent/OVN Issues:**

- See: [routeagent-analysis.md](docs/analysis/routeagent-analysis.md)
- routeagents.yaml, ip-rules.log, OVN logs

### Phase 5: Perform Analysis

Apply analysis logic from modular guides:

1. **Tunnel Health** → [tunnel-analysis.md](docs/analysis/tunnel-analysis.md)
   - Read Gateway CR status
   - Check for asymmetric status → [asymmetric-tunnel-analysis.md](docs/analysis/asymmetric-tunnel-analysis.md)
   - Verify IPsec control plane and datapath
   - Check load balancer config (if hosted cluster)

2. **MTU Issues** → [mtu-analysis.md](docs/analysis/mtu-analysis.md)
   - Compare default vs small packet verify results
   - Classic pattern: default fails, small succeeds = MTU issue

3. **RouteAgent Health** → [routeagent-analysis.md](docs/analysis/routeagent-analysis.md)
   - Basic RouteAgent status
   - OVN-specific checks (if OVN-Kubernetes)
   - API server health, IP rule consistency, OVN routing

4. **Gateway HA** → [gateway-ha-analysis.md](docs/analysis/gateway-ha-analysis.md)
   - Gateway CR is authoritative source
   - Check for multiple active pods
   - Severity depends on LoadBalancer usage

5. **Firewall/Infrastructure** → [firewall-analysis.md](docs/analysis/firewall-analysis.md)
   - Read tcpdump analysis files
   - Pattern 1: No egress → Gateway not sending
   - Pattern 2: Egress but no ingress → Infrastructure blocking
   - Pattern 3: Both sending but still error → Health check IP issue

### Phase 6: Provide Analysis Report

**See:** [report-format.md](docs/analysis/report-format.md)

#### DEFAULT: Brief Report (always use this unless user asks for detailed)

```text
## SUBMARINER OFFLINE ANALYSIS - BRIEF REPORT

**Diagnostic:** <path>
**Issue:** <complaint>
**Deployment:** <Standalone/ACM-Managed>

### Key Findings
✓/✗ Finding 1
✓/✗ Finding 2

### Root Cause
<1-2 paragraphs with cautious language>

### Recommended Next Steps
1. Verify Prerequisites (FIRST)
2. Workaround (if needed)
3. Alternative (if #2 fails)

**Priority:** HIGH/MEDIUM/LOW
**Confidence:** HIGH/MEDIUM/LOW
```

#### Guidelines

**DO:**

- Use cautious language ("appears to be", "most likely", "could be")
- Provide 3-4 focused steps maximum
- Include file references
- Distinguish workarounds from fixes
- Detect deployment type and provide appropriate commands

**DON'T:**

- Make definitive statements without acknowledging uncertainty
- Overwhelm with too many alternatives
- Dive into iptables/nftables details
- Recommend manual infrastructure investigation
- Mention "ICMP blocked by firewall" (it's inside the tunnel)

### Phase 7: Answer Follow-up Questions

Be ready to:

- Dive deeper into specific findings
- Explain technical details
- Provide alternative solutions
- Analyze additional files

## Important Guidelines

1. **Cautious Language** - Always use probabilistic language in offline analysis
2. **Gateway CR is Authoritative** - For tunnel status, trust Gateway CR over logs
3. **Check Multiple Levels** - Control plane, datapath, policies, routing
4. **Distinguish Tunnel vs Local Routing** - Don't conclude "local routing issue" when gateway tunnel is broken
5. **Trust Submariner Components** - If logs show NO errors, configuration is correct
6. **ICMP is Encapsulated** - Health checks are INSIDE tunnel, infrastructure sees ESP/UDP
7. **Health Check Ping Size** - Small packets, if they fail MTU is NOT the root cause
8. **Use tcpdump Data** - Determine where packets are dropped
9. **Keep Recommendations Simple** - 3-4 focused steps, reference official docs
10. **OpenShift on OpenStack** - Check for UDP port conflicts only if NAT discovery timeout

- See: [special-cases.md](docs/analysis/special-cases.md#openshift-on-openstack-udp-port-conflict)

## GitHub Search for Known Bugs

**When to Search GitHub:**

When you detect software bugs in logs (e.g., libreswan errors, version incompatibilities, cable driver
failures), search GitHub for known issues and PRs before providing recommendations.

**How to Search:**

Use Bash tool to run `gh` CLI commands:

```bash
# Search for issues
gh issue list --repo submariner-io/submariner --search "libreswan encapsulation" --state all --limit 5 --json number,title,state,url

# Search for PRs
gh pr list --repo submariner-io/submariner --search "libreswan encapsulation" --state all --limit 5 --json number,title,state,mergedAt,url
```

**What to Look For:**

- **Fix Available:** Merged PR that addresses the issue
  - Check merge date to determine if fix is in current release
  - Recommend upgrading to latest build if fix is recent
  
- **Known Issue (No Fix):** Open issue that matches the problem
  - Reference issue URL in analysis
  - Recommend workaround if available
  
- **No Results:** Bug might be unreported
  - Provide standard bug reporting guidance

**How to Report Findings:**

Include GitHub search results in analysis:

```text
### Known Bug Detection

✓ Searched GitHub for known issues related to: <bug description>

**Fix Available:**
- PR: <url>
- Title: <title>
- Merged: <date>
- Recommendation: Upgrade to Submariner build from <date> or later

OR

**Known Issue (No Fix Yet):**
- Issue: <url>
- Status: OPEN
- Recommendation: Use workaround or monitor issue for updates

OR

**No GitHub Results:**
- This appears to be a new issue
- Consider reporting at: https://github.com/submariner-io/submariner/issues
```

**Important:**

- Always use cautious language ("appears to be related to", "might be fixed by")
- Don't guarantee fix will resolve user's specific issue
- Provide both fix recommendation AND workaround when possible

## File Reading Strategy

- **YAML files:** Use Read tool, parse structure
- **Log files:** Use Read/Grep, search for errors, distinguish symptoms from root causes
- **tcpdump files:** ALWAYS read text analysis files first (`*-analysis.txt`)
- **Verify files:** Check command headers, look for early stop detection

## Example Workflow

1. User: `/submariner:analyze-offline diagnostics.tar.gz`
2. Read manifest.txt → complaint: "general health check"
3. Read subctl-show-all.txt → tunnel status
4. Detect deployment type → ACM-Managed
5. Read Gateway CR → asymmetric status detected
6. Follow [asymmetric-tunnel-analysis.md](docs/analysis/asymmetric-tunnel-analysis.md)
7. Check for OVN-K local gateway mode
8. Read tcpdump analysis → Pattern 2 (egress but no ingress)
9. Conclude: Infrastructure blocking (with cautious language)
10. Generate brief report with deployment-specific commands

## References

**Analysis Guides:**

- [tunnel-analysis.md](docs/analysis/tunnel-analysis.md)
- [asymmetric-tunnel-analysis.md](docs/analysis/asymmetric-tunnel-analysis.md)
- [firewall-analysis.md](docs/analysis/firewall-analysis.md)
- [mtu-analysis.md](docs/analysis/mtu-analysis.md)
- [gateway-ha-analysis.md](docs/analysis/gateway-ha-analysis.md)
- [routeagent-analysis.md](docs/analysis/routeagent-analysis.md)
- [deployment-detection.md](docs/analysis/deployment-detection.md)
- [report-format.md](docs/analysis/report-format.md)

**Official Documentation:**

- [Submariner Prerequisites](https://submariner.io/operations/deployment/prerequisites/)
- [Troubleshooting Guide](https://submariner.io/operations/troubleshooting/)

You are the offline diagnostic expert that analyzes collected data and helps identify the most likely root cause.
