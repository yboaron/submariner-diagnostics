# submariner-diagnostics

Contains tools and scripts for collecting data and diagnosing issues in Submariner deployments

Collect diagnostics once from live clusters, then analyze **offline** anytime -
no cluster access needed for analysis.

## Features

- **Smart Automated Collection**: Intelligently gathers diagnostic data from both
  clusters
- **Basic Analysis** (Python): Fast pattern-matching for common issues - no AI
  required
- **Advanced Analysis** (Claude Code): Deep AI-powered root cause analysis

## Getting Started

### Installation

#### 1. Clone the repository

```bash
git clone https://github.com/submariner-io/submariner-diagnostics.git
cd submariner-diagnostics
```

#### 2. Verify prerequisites

```bash
# Required for collection
kubectl version --client
subctl version

# Required for basic analysis (optional)
python3 --version
pip install pyyaml
```

#### Prerequisites

- `kubectl` - [Installation Guide](https://kubernetes.io/docs/tasks/tools/)
- `subctl` - [Installation Guide](https://github.com/submariner-io/subctl)
- `python3` - Optional, needed for:
  - Basic analysis (`analyze-basic.py`)
  - Sanitization (`--sanitize` flag)
- `pyyaml` - Only needed for basic analysis (install with `pip install pyyaml`)
- Access to both Submariner clusters with valid kubeconfig files

## Quick Start

### 1. Collect Diagnostics

```bash
./collect-full-diagnostics.sh [--sanitize] <cluster1-context> <cluster1-kubeconfig> <cluster2-context> <cluster2-kubeconfig> [issue-description]
```

#### Options

- `--sanitize`: Sanitize IP addresses and domain names in collected diagnostics (optional)

#### Parameters

- `cluster1-context`: Context name for cluster 1 (from kubeconfig)
- `cluster1-kubeconfig`: Path to kubeconfig file for cluster 1
- `cluster2-context`: Context name for cluster 2 (from kubeconfig)
- `cluster2-kubeconfig`: Path to kubeconfig file for cluster 2
- `issue-description`: Optional description of the issue

#### Examples

```bash
# Separate kubeconfig files
./collect-full-diagnostics.sh \
  prod-east /path/to/kubeconfig-east \
  prod-west /path/to/kubeconfig-west \
  "tunnel not connected"

# Single kubeconfig with multiple contexts
./collect-full-diagnostics.sh \
  context-cluster1 /path/to/merged-kubeconfig \
  context-cluster2 /path/to/merged-kubeconfig \
  "connectivity issues"

# With sanitization (for sharing diagnostics externally)
./collect-full-diagnostics.sh --sanitize \
  context-cluster1 /path/to/merged-kubeconfig \
  context-cluster2 /path/to/merged-kubeconfig \
  "connectivity issues"

# Without issue description (defaults to "undefined")
./collect-full-diagnostics.sh \
  prod-east /path/to/kubeconfig-east \
  prod-west /path/to/kubeconfig-west
```

**Output:** `submariner-diagnostics-TIMESTAMP.tar.gz`

#### Sanitization

When `--sanitize` is used:

- **IP addresses** are replaced with context-aware placeholders:
  - `PUBLIC-IP-N` for public IPs
  - `PRIVATE-IP-N` for RFC1918 private IPs
  - `POD-IP-N` for pod CIDRs
  - `SVC-IP-N` for service CIDRs
- **Domain names** are replaced with `DOMAIN-N` placeholders
- Mapping files (`ip-mappings.txt`, `domain-mappings.txt`) are included for reference
- Diagnostic value is preserved (traffic flow remains understandable)
- No changes to analyzer needed (works with both sanitized and non-sanitized data)

### 2. Analyze (Basic - No AI)

```bash
./analyze-basic.py submariner-diagnostics-TIMESTAMP.tar.gz
```

#### What it detects

- Version compatibility issues (subctl vs Submariner)
- **Submariner software bugs with automatic GitHub search**
  - Detects known bugs (e.g., libreswan version incompatibility)
  - Searches GitHub for existing fixes or workarounds
  - Shows PR merge dates and issue status
  - Prevents duplicate bug reports
- Tunnel connectivity status
- ESP/UDP protocol blocking
- Firewall blocking (inter-cluster and intra-cluster)
- MTU/fragmentation issues
- Pod health issues
- Packet flow patterns (from tcpdump)
- RouteAgent connectivity with gateway correlation
  - Distinguishes intra-cluster vs inter-cluster issues
  - Detects control plane connectivity patterns
  - Identifies root cause segment (local routing vs inter-cluster)
- Network topology analysis (when RouteAgent errors detected)
  - Detects potential non-flat networking scenarios
  - Analyzes node subnet distribution
- Common misconfigurations

**No setup required** - just Python 3 with PyYAML:

```bash
pip install pyyaml
```

### 3. Analyze (Advanced - AI-Powered)

For deeper analysis with Claude AI:

#### Installation

```bash
# Install the Claude Code skill (creates /submariner:analyze-offline command)
mkdir -p ~/.claude/commands/submariner
cp analyze-offline.md ~/.claude/commands/submariner/analyze-offline.md
```

**Restart Claude Code**, then verify the command is available:

```text
/submariner:analyze-offline
```

**Note:** The command will appear as `/submariner:analyze-offline` in Claude Code.

**How it works:** The skill uses modular analysis guides from `docs/analysis/` in this repository. These are
automatically accessible when the skill runs - no need to copy them separately.

#### Usage

```text
/submariner:analyze-offline submariner-diagnostics-TIMESTAMP.tar.gz

# Or with specific issue description
/submariner:analyze-offline submariner-diagnostics-TIMESTAMP.tar.gz "tunnel not connected"
```

#### Prerequisites

- [Claude Code](https://claude.com/claude-code) installed
- Claude subscription

#### What it detects (in addition to basic analysis)

- **MTU/fragmentation issues** (classic pattern: small packets pass, large
  packets fail)
- **Submariner software bugs with GitHub search**
  - Automatically searches for known issues and fixes
  - Provides upgrade recommendations when fix is available
  - Links to relevant PRs and issues
- Infrastructure-level blocking patterns from tcpdump analysis
- All issues detected by basic analysis

#### What it provides

- Deep root cause analysis with context
- Probabilistic reasoning ("most likely", "appears to be")
- Step-by-step solutions with deployment-specific commands (ACM vs Standalone)
- Official documentation references
- Further investigation steps if initial solution fails
- Guidance on contacting Submariner experts for software bugs

## What Gets Collected

### Always Collected

- `collection.log` - Complete collection output including any errors
- `subctl gather` - Comprehensive cluster data including:
  - Submariner CRs (Gateway, Endpoints, RouteAgents)
  - Pod logs and status
  - IPsec status and traffic counters
  - Network configuration (routes, iptables, XFRM policies)
- `subctl show` - Connection status overview
- `subctl show versions` - Component version information
- `subctl diagnose` - Health check results
- Gateway and RouteAgent status
- ACM resources (if present)
- Version compatibility check (in manifest.txt)

### Conditional Collection

#### When Tunnels NOT Connected

**tcpdump packet captures** from gateway nodes (80-second capture)

- Automatically captured if either tunnel shows `status != connected`
- Helps diagnose infrastructure-level blocking (ESP/UDP)
- Includes text analysis summaries for offline review
- **Benefit**: Identifies *where* packets are being dropped

**Firewall inter-cluster diagnostics** (`subctl diagnose firewall
inter-cluster`)

- Runs when: Tunnel not connected + UDP encapsulation (VxLAN or IPSec NAT-T)
- Skipped when: Using ESP (protocol 50) - test only checks UDP ports
- **Benefit**: Verifies if UDP ports are open between gateway nodes
- **Cross-referenced with**: tcpdump data (UDP traffic) + IPsec counters
  (ipsec-trafficstatus.log)

#### When Tunnels Connected

#### subctl verify connectivity tests

- Default packet size tests
- Small packet size tests (MTU detection)
- Service discovery tests (if enabled)
- **Benefit**: Validates end-to-end connectivity

#### When CNI is NOT OVN-Kubernetes

**Firewall intra-cluster diagnostics** (`subctl diagnose firewall
intra-cluster`)

- Runs per cluster when CNI is not OVNK (checked independently)
- Runs regardless of tunnel status
- **Benefit**: Verifies VXLAN traffic allowed on vx-submariner interface
- **Expected failures**: RouteAgent issues + verify test failures from
  non-gateway pods

## Repository Structure

The analysis logic is organized into modular, focused guides:

- **`CLAUDE.md`** - Repository overview and analysis principles
- **`analyze-offline.md`** - Claude Code skill entry point (install this)
- **`docs/analysis/`** - Modular analysis guides:
  - `datapath-architecture.md` - **Submariner datapath fundamentals** (non-OVN vs OVN)
  - `tunnel-analysis.md` - Tunnel connectivity and IPsec datapath
  - `asymmetric-tunnel-analysis.md` - Asymmetric tunnel investigation
  - `firewall-analysis.md` - Network/firewall blocking (tcpdump)
  - `mtu-analysis.md` - MTU and fragmentation issues
  - `gateway-ha-analysis.md` - Gateway HA status checks
  - `routeagent-analysis.md` - RouteAgent and OVN-specific checks
  - `deployment-detection.md` - ACM vs Standalone detection
  - `report-format.md` - Analysis report templates
  - `special-cases.md` - Edge cases and special scenarios

This modular structure makes the codebase easier to maintain while keeping the user experience simple (`/submariner:analyze-offline`).

## Requirements

### Collection Script

- `bash`
- `kubectl`
- `subctl` - [Installation Guide](https://github.com/submariner-io/subctl)
- Access to both Submariner clusters

**Note:** Packet captures are performed inside the cluster using containers - no
local `tcpdump` installation required.

### Basic Analysis

- `python3` (3.6+)
- `pyyaml` - Install: `pip install pyyaml`

### Advanced Analysis

- [Claude Code](https://claude.com/claude-code)
- Claude subscription

## Disconnected/Airgap Environments

For airgap environments, ensure the following container image is mirrored to your internal registry:

- **`quay.io/submariner/nettest:devel`** - Used by several components in the collection script
  (firewall diagnostics, tcpdump collection, connectivity verification)

## Contributing

Contributions welcome! Please submit issues or PRs to:
<https://github.com/submariner-io/submariner-diagnostics>

## Support

- **Collection/Analysis Issues**: [GitHub
  Issues](https://github.com/submariner-io/submariner-diagnostics/issues)
- **Submariner Bugs**: [Submariner
  GitHub](https://github.com/submariner-io/submariner/issues)
- **Community Help**: [Submariner
  Slack](https://kubernetes.slack.com/archives/C010RJV694M)

## License

Apache 2.0
