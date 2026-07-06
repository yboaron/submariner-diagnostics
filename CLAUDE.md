# Submariner Diagnostics Repository

This repository provides offline diagnostics analysis for Submariner deployments.

## Overview

- **Collection**: `collect-full-diagnostics.sh` gathers diagnostic data from live clusters
- **Basic Analysis**: `analyze-basic.py` performs fast pattern matching without AI
- **Deep Analysis**: Claude-powered root cause analysis with remediation steps

## Workflow for AI Analysis

When analyzing diagnostics, the process follows:

1. **Extract & Validate** diagnostic data
2. **Auto-detect** deployment type (ACM vs Standalone)
3. **Triage** to identify issue categories
4. **Deep Analysis** using modular knowledge bases
5. **Provide** unified summary with deployment-specific remediation

## Knowledge Base Structure

Analysis knowledge is modular and located in `docs/analysis/`:

- `datapath-architecture.md` - **Datapath fundamentals** including OVN-K architecture and all 4 traffic scenarios
- `tunnel-analysis.md` - Tunnel connectivity and IPsec datapath issues
- `asymmetric-tunnel-analysis.md` - Asymmetric tunnel status investigation
- `firewall-analysis.md` - Network/firewall blocking detection (tcpdump analysis)
- `mtu-analysis.md` - MTU and fragmentation issues
- `gateway-ha-analysis.md` - Gateway HA status and multiple active pods
- `routeagent-analysis.md` - RouteAgent health and OVN-specific checks
- `ovn-offline-verification.md` - **OVN-K offline verification** (IP rules, table 150, OVN policies, CR validation)
- `deployment-detection.md` - ACM vs Standalone deployment detection
- `report-format.md` - Analysis report templates (brief and detailed)
- `special-cases.md` - Special scenarios (OpenShift on OpenStack UDP ports, context name conflicts)

## Critical Analysis Principles

### 1. Use Cautious Language

- Use: "appears to be", "seems like", "most likely", "could be"
- Avoid: Definitive statements like "This is" or "The root cause is"
- Acknowledge uncertainty and need for further investigation

### 2. Treat Infrastructure as Black Box

- DON'T dive into iptables/nftables/kernel/low-level details
- Reference official Submariner prerequisites documentation
- Keep recommendations high-level
- Trust Submariner components unless logs show errors

### 3. Clearly Distinguish Workarounds from Fixes

- Label each workaround explicitly as "Workaround"
- Explain what it does and WHY it's not a root cause fix
- Warn about trade-offs (especially security impacts)

### 4. Auto-Detect Deployment Type

- Always check `acm-addons.txt` and `submarinerconfig.yaml`
- Provide deployment-specific instructions (ACM-Managed vs Standalone)
- Never give generic instructions

### 5. Focus on Direct Remediation

- Provide kubectl commands to fix issues directly
- Only use `subctl show/diagnose/verify` for VERIFICATION after fixes
- NEVER recommend `subctl deploy-broker` or `subctl join`

### 6. Check Datapath Segmentation FIRST

**CRITICAL:** Before deep investigation, determine which datapath segment is failing:

```
Full path: Non-GW → Local-GW → Remote-GW

Segment 1 (Local routing): Non-GW → Local-GW
Segment 2 (Inter-cluster): Local-GW → Remote-GW
```

**Decision Matrix:**
- Gateway CR status = Segment 2 health (inter-cluster tunnel)
- RouteAgent CR status = Full path health (both segments)

**Early Exit:**
- If Gateway=connected AND RouteAgent=connected → Datapath is healthy, stop investigation
- If Gateway=connected AND RouteAgent=error → Focus ONLY on local routing (Segment 1)
- If Gateway=error AND RouteAgent=connected → Investigate why GW health check fails despite full path working
  (unusual case - see special cases below)
- If Gateway=error AND RouteAgent=error → Focus on inter-cluster tunnel (Segment 2) FIRST

**For OVN-K CNI:** When local routing issue detected (Gateway connected + RouteAgent error):
- Verify Submariner OVN-K configuration per `ovn-offline-verification.md`
- If all config correct, use cautious language: "appears to be infrastructure/OVN-K platform issue"
- Recommend contacting Submariner community, NOT vendor support

### 7. Check for Asymmetric Tunnel Status

- Before concluding infrastructure/firewall blocking, check if tunnel status is asymmetric
- Asymmetric = one cluster shows "connected", the other shows different status
- May indicate routing issues or one-way infrastructure filtering

## Output Format

Provide clear, structured output:

**Issue Summary**

- What appears to be happening
- Confidence level

**Root Cause Analysis**

- Most likely cause (with caveats)
- Supporting evidence from diagnostic data

**Remediation Steps**

- Deployment-specific commands (ACM vs Standalone)
- Verification steps
- Fallback options if fix doesn't work

**Further Investigation**

- Additional checks if remediation doesn't resolve the issue
- When to escalate to Submariner experts
