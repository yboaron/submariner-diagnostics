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

- `datapath-architecture.md` - **Datapath fundamentals** (for understanding flow, NOT for manual fixes in reports)
- `tunnel-analysis.md` - Tunnel connectivity and IPsec datapath issues
- `asymmetric-tunnel-analysis.md` - Asymmetric tunnel status investigation
- `firewall-analysis.md` - Network/firewall blocking detection (tcpdump analysis)
- `mtu-analysis.md` - MTU and fragmentation issues
- `gateway-ha-analysis.md` - Gateway HA status and multiple active pods
- `routeagent-analysis.md` - RouteAgent health and OVN-specific checks
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

### 6. Check for Asymmetric Tunnel Status FIRST

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
