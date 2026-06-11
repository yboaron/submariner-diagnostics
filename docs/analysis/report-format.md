# Analysis Report Formats

Templates for generating analysis reports.

## Default Format: Brief Report

**IMPORTANT:** Always provide a **brief, actionable report** as the default output format.

Only provide the detailed report if the user explicitly requests it.

### Brief Report Template

```text
## SUBMARINER OFFLINE ANALYSIS - BRIEF REPORT

**Diagnostic:** <diagnostics-path>
**Issue:** <complaint from manifest>
**Deployment:** <Standalone Submariner / ACM-Managed>

### Key Findings

✓/✗ **Finding 1** - Brief description with file reference
✓/✗ **Finding 2** - Brief description with file reference
✓/✗ **Finding 3** - Brief description with file reference
✓/✗ **Finding 4** - Brief description with file reference

### Root Cause

<1-2 paragraph explanation using cautious language like "appears to be", "most likely", "seems to indicate">

Key evidence:
- Evidence point 1 (file:line reference)
- Evidence point 2 (file:line reference)
- Evidence point 3 (file:line reference)

### Recommended Next Steps

**1. Verify Submariner Prerequisites (FIRST PRIORITY)**

Check if required protocols are allowed between gateway nodes:
- **ESP (IP protocol 50)** OR **UDP port 4500**
- Provide specific verification commands for the environment

📖 [Submariner Prerequisites](https://submariner.io/operations/deployment/prerequisites/)

**2. <Workaround Name> (If Prerequisites Cannot Be Met)**

<Brief explanation of workaround - what it does and why it's a workaround>

**Security Impact:** <✓ Maintains encryption / ❌ Removes encryption>

```bash
<Concrete commands to apply workaround>
```

**3. <Alternative Workaround> (If #2 Doesn't Work)**

<Brief explanation>

```bash
<Concrete commands>
```

### Files Analyzed

- List key files examined for transparency

**Priority:** <HIGH/MEDIUM/LOW> - <reason>
**Confidence:** <HIGH/MEDIUM/LOW> - <reason>

```

### Brief Report Guidelines

#### DO Include
- 3-5 bullet point findings
- 1-2 paragraph root cause analysis using cautious language
- Top 2-3 most likely solutions in priority order
- File references for transparency
- Priority and confidence levels

#### DO NOT Include
- Massive detailed reports with 10+ sections
- Extensive workaround options (pick top 2 most likely)
- Speculative deep-dives into all possible causes
- Workarounds before verifying prerequisites

## Optional Format: Detailed Report

Only provide this if user explicitly requests detailed analysis.

### Detailed Report Structure

```text
========================================
SUBMARINER OFFLINE ANALYSIS REPORT
========================================

DIAGNOSTIC DATA:
  Timestamp: <from manifest>
  Complaint: <user complaint>
  Clusters Analyzed: cluster1, cluster2
  Deployment Type: <Standalone Submariner / ACM-Managed>

========================================
EXECUTIVE SUMMARY
========================================

<One-paragraph summary using cautious language>
<Focus on whether it appears to be configuration or infrastructure issue>
<Which segment seems to have the problem>

========================================
DETAILED FINDINGS
========================================

1. TUNNEL STATUS
   [tunnel-analysis.md findings]

2. IPSEC CONTROL PLANE STATUS
   [IPsec status findings]

3. DATAPATH STATUS
   [firewall-analysis.md findings]

4. POD HEALTH
   [pod health findings]

5. COMPONENT LOGS ANALYSIS
   [log analysis findings]

6. TCPDUMP ANALYSIS
   [firewall-analysis.md tcpdump patterns]

7. CONNECTIVITY VERIFICATION
   [mtu-analysis.md findings]

========================================
ROOT CAUSE ANALYSIS
========================================

Issue Type: <Gateway-to-Gateway / Local Routing / Configuration Error>

**What IS Working:**
  ✓ <List working components>

**What IS NOT Working:**
  ✗ <List failing components>

**Key Evidence:**
  1. <Evidence with file reference>
  2. <Evidence with file reference>

**Most Likely Root Cause:**
<Use cautious language: "appears to be", "most probably", "seems like">

**Alternative Possibilities:**
<1-2 other possible causes>

**Next Steps for Investigation:**
1. **Verify Submariner Prerequisites**
2. **Confirm Network Path Requirements**

========================================
RECOMMENDED SOLUTION
========================================

**Step 1: Verify Prerequisites (FIRST)**
<Verification commands>

**Step 2: Apply Workaround (If Prerequisites Cannot Be Met)**
<Deployment-specific commands from deployment-detection.md>

**Step 3: Alternative Workaround**
<Alternative solution>

========================================
FURTHER INVESTIGATION STEPS
========================================

1. **Verify Infrastructure Connectivity**
2. **Collect Live Packet Captures**
3. **Check for Additional Blocking**
4. **Engage Submariner Community**

========================================
FILES ANALYZED
========================================

<List of key files examined>

========================================
SUMMARY
========================================

<2-3 paragraph summary using cautious language>

Priority: <HIGH/MEDIUM/LOW> - <reason>
Confidence: <HIGH/MEDIUM/LOW> - <reason>

**Note:** This analysis is based on offline diagnostic data.
```

## Language Guidelines

### Use Cautious, Probabilistic Language

**Good Examples:**

- "appears to be"
- "most likely"
- "seems to indicate"
- "could be"
- "worth checking"
- "might be related to"

**Bad Examples (too definitive):**

- "This is"
- "The root cause is"
- "Definitely"
- "Certainly"

### Acknowledge Uncertainty

- Present most likely scenario first
- Acknowledge other possibilities
- Recommend further investigation steps
- Consider that proposed solutions might also fail
- Be humble about conclusions

### Example Comparison

❌ **Bad (too definitive):**

```text
This is a gateway-to-gateway datapath failure. ESP protocol packets are being 
blocked by network infrastructure. The solution is to enable UDP encapsulation.
```

✓ **Good (appropriately cautious):**

```text
Based on the evidence, this **appears to be** a gateway-to-gateway datapath 
failure, **most likely caused by** ESP protocol packets being blocked at the 
infrastructure level. **Recommended first step** is to try UDP encapsulation, 
though further investigation may be needed if UDP port 4500 is also restricted.
```

## Deployment-Specific Instructions

Always detect deployment type (see deployment-detection.md) and provide appropriate commands:

### For ACM-Managed

```bash
# On the ACM hub cluster
kubectl patch submarinerconfig -n <managed-cluster-namespace> <config-name> \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

# ACM will propagate changes automatically
```

### For Standalone

```bash
# On each managed cluster
kubectl patch submariner -n submariner-operator submariner \
  --type merge \
  -p '{"spec": {"ceIPSecForceUDPEncaps": true}}'

kubectl delete pods -n submariner-operator -l app=submariner-gateway
```

## Priority and Confidence Levels

### Priority

- **HIGH:** Service is down, no connectivity
- **MEDIUM:** Degraded performance, intermittent issues
- **LOW:** Minor issues, cosmetic problems

### Confidence

- **HIGH:** Clear evidence, definitive pattern (e.g., MTU pattern)
- **MEDIUM:** Strong evidence but multiple possible causes
- **LOW:** Incomplete data, multiple unknowns

## Important Notes

- Always use cautious language in offline analysis
- Provide file references for transparency
- Keep recommendations simple (3-4 steps maximum)
- Reference official Submariner documentation
- Trust Submariner components unless logs show errors
- Distinguish workarounds from root cause fixes
