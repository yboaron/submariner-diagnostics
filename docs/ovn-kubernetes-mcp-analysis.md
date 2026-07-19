# OVN-Kubernetes MCP Analysis for Submariner-Diagnostics

**Date:** 2026-07-12  
**Source:** https://github.com/ovn-kubernetes/ovn-kubernetes-mcp

This document analyzes the OVN-Kubernetes MCP project to identify ideas and patterns we can adopt for submariner-diagnostics.

---

## A. Ideas for Offline Diagnostics

### 1. **MCP Server Integration** ⭐ HIGH PRIORITY

**What they do:**
- Provide MCP (Model Context Protocol) server for Claude Code integration
- Support both `offline` and `live-cluster` modes
- MCP tools are automatically available in Claude Code when connected

**What we can adopt:**
```
submariner-diagnostics/
├── mcp-server/
│   ├── cmd/
│   │   └── submariner-mcp-server/
│   │       └── main.go
│   └── pkg/
│       ├── offline/          # Offline diagnostic analysis
│       │   ├── gather-parser/
│       │   ├── routeagent-analyzer/
│       │   └── gateway-analyzer/
│       └── tools/            # MCP tool registry
│           ├── gateway-status.go
│           ├── routeagent-status.go
│           ├── tcpdump-analysis.go
│           └── verify-results.go
```

**Benefits:**
- **Better Claude Code integration** - Tools are native MCP, not markdown skill files
- **Type-safe tool schemas** - MCP provides structured input/output
- **Automatic tool discovery** - Claude sees all available tools
- **Real-time diagnostics** - Can add live-cluster mode later

**Implementation:**
```go
// Tool example: submariner-gateway-status
mcp.AddTool(server, &mcp.Tool{
    Name: "submariner-gateway-status",
    Description: `Analyze Submariner gateway status from diagnostics.
    
Parameters:
- diagnostic_path (required): Path to submariner-diagnostics-*.tar.gz
- cluster (optional): Which cluster to analyze (cluster1, cluster2, or both)

Returns gateway connection status, HA configuration, and potential issues.`,
}, s.AnalyzeGatewayStatus)
```

### 2. **Structured Tool Categories** ⭐ MEDIUM PRIORITY

**What they do:**
- Organize tools by category: `kubernetes`, `ovn`, `ovs`, `kernel`, `network-tools`, `sosreport`, `must-gather`
- Allow selective tool exposure via `--disable-categories`

**What we can adopt:**
```
Categories for submariner-diagnostics:
- submariner-gateway    : Gateway CR analysis, tunnel status, IPsec
- submariner-route      : RouteAgent status, OVN-K verification
- submariner-network    : tcpdump, firewall, MTU analysis
- submariner-deployment : ACM vs Standalone detection, version compat
- submariner-verify     : Connectivity test results
```

**Benefits:**
- Users can focus on specific areas
- Easier to navigate when many tools
- Can disable irrelevant categories

### 3. **Head/Tail Filtering Pattern** ⭐ LOW PRIORITY

**What they do:**
- All log-reading tools support `head`, `tail`, `apply_tail_first` parameters
- Prevents overwhelming LLM with huge logs

**What we can adopt:**
```python
def read_gateway_logs(self, diagnostic_path, head=None, tail=None):
    """Read gateway logs with optional head/tail filtering.
    
    Args:
        head: Return first N lines
        tail: Return last N lines
        apply_tail_first: Apply tail before head
    """
    # Already partially implemented in our collect script
    # Can add to Python analyzer
```

**Benefits:**
- Reduce token usage
- Focus on relevant log sections
- Match OVN-K MCP UX

### 4. **Pattern/Regex Search Across Files** ⭐ MEDIUM PRIORITY

**What they do:**
- `sos-search-commands` - Regex search across all sosreport commands
- Returns matching files WITHOUT contents (discovery pattern)

**What we can adopt:**
```python
def search_diagnostic_pattern(self, diagnostic_path, pattern, max_results=50):
    """Search for pattern across all diagnostic files.
    
    Returns:
        List of matching files with context, NOT full contents
        
    Example:
        pattern="sendmsg: operation not permitted"
        Returns: [{"file": "gateway-pod/logs.txt", "line_number": 42, "context": "..."}]
    """
```

**Benefits:**
- Claude can discover where to look
- Reduces unnecessary file reads
- Enables exploratory analysis

---

## B. Sensitive Data Handling

### Current State in OVN-K MCP

**What they DO:**
- ✅ Network isolation via NetworkPolicy (deny-all ingress by default)
- ✅ RBAC-based access control (kubectl port-forward permissions)
- ✅ Security warning in README about TLS/auth
- ✅ Timeout controls for tool execution
- ✅ Selective tool exposure (`--disable-tools`, `--disable-categories`)

**What they DON'T do:**
- ❌ **No data sanitization/redaction** - Raw cluster data exposed to MCP tools
- ❌ **No PII detection** - No automatic masking of sensitive values
- ❌ **No audit logging** - No record of what data was accessed
- ❌ **No encryption at rest** - Must-gather/sosreport stored unencrypted

### Recommendations for Submariner-Diagnostics

#### 1. **Sanitization Flag** (Already Implemented!) ✅

Our `--sanitize` flag is **MORE comprehensive** than OVN-K MCP:

```bash
./collect-full-diagnostics.sh --sanitize \
  context1 kubeconfig1 \
  context2 kubeconfig2
```

**What we sanitize:**
- ✅ IP addresses (context-aware: PUBLIC-IP-N, PRIVATE-IP-N, POD-IP-N, SVC-IP-N)
- ✅ Domain names (DOMAIN-N with mappings file)
- ✅ Preserves diagnostic value

**OVN-K MCP:** No equivalent feature

#### 2. **Add Data Classification Documentation** 📝 NEW

Create `docs/data-privacy.md`:

```markdown
# Data Privacy and Sensitive Information

## What Gets Collected

### Always Collected:
- Pod logs (may contain cluster names, IPs, errors)
- Kubernetes resource definitions (ConfigMaps, Secrets metadata)
- Network configuration (routes, iptables, IPsec status)
- Gateway and RouteAgent CRs

### Conditionally Collected:
- tcpdump packet captures (when tunnels not connected)
- Firewall diagnostics (UDP/ESP traffic)

## Sensitive Data Categories

### HIGH SENSITIVITY:
- **IP addresses** - Can reveal network topology
- **Domain names** - Can identify organizations
- **Cluster names** - May contain customer/project identifiers
- **Certificate subjects** - May contain organizational info

### MEDIUM SENSITIVITY:
- Pod names (may contain app names)
- Namespace names (may reveal workload types)
- Node names (may reveal infrastructure details)

### LOW SENSITIVITY:
- Submariner versions
- CNI type (OVN-Kubernetes, etc.)
- Error messages

## Recommendations

### For Internal Use (Same Organization):
```bash
# No sanitization needed
./collect-full-diagnostics.sh cluster1-ctx kubeconfig1 ...
```

### For External Sharing (Support Tickets, GitHub Issues):
```bash
# Always use --sanitize
./collect-full-diagnostics.sh --sanitize cluster1-ctx kubeconfig1 ...
```

### For Public Documentation:
- Always sanitize
- Review mappings files before sharing
- Remove or generalize cluster-specific details
```

#### 3. **Add Sensitive Field Detection** 📝 NEW

Enhance Python analyzer to detect potentially sensitive data:

```python
def detect_sensitive_fields(self):
    """Detect if diagnostic contains non-sanitized sensitive data."""
    findings = {
        'public_ips': [],
        'cluster_names': [],
        'domain_names': [],
    }
    
    # Check for non-sanitized IPs
    # Real IP pattern vs sanitized "PUBLIC-IP-1"
    if self._contains_real_ips():
        findings['public_ips'].append("Found non-sanitized IP addresses")
    
    # Check for domain names
    if self._contains_real_domains():
        findings['domain_names'].append("Found non-sanitized domain names")
    
    if any(findings.values()):
        return {
            'title': 'Potentially Sensitive Data Detected',
            'severity': 'info',
            'description': 'Diagnostic may contain non-sanitized data',
            'details': findings,
            'recommendation': 'Consider re-collecting with --sanitize flag before external sharing'
        }
    
    return None
```

#### 4. **Add Security Section to README** 📝 NEW

```markdown
## Security and Privacy

### Collected Data

Submariner diagnostics contain operational data from your Kubernetes clusters:
- Network configuration and routing tables
- Pod logs and status
- Kubernetes resource definitions
- Packet captures (when troubleshooting connectivity)

### Sanitization

**Always use `--sanitize` when sharing diagnostics externally:**

```bash
./collect-full-diagnostics.sh --sanitize ...
```

This replaces:
- IP addresses → `PUBLIC-IP-N`, `PRIVATE-IP-N`, `POD-IP-N`
- Domain names → `DOMAIN-N`

Mapping files are included for reference.

### Best Practices

1. **Internal troubleshooting:** No sanitization needed
2. **Support tickets:** Always use `--sanitize`
3. **GitHub issues:** Always use `--sanitize`
4. **Documentation/examples:** Review mappings, generalize cluster details

See [Data Privacy Guide](docs/data-privacy.md) for details.
```

---

## C. Other Ideas to Adopt

### 1. **Timeout Controls** ⭐ HIGH PRIORITY

**What they do:**
```go
--tool-timeout=120  // Timeout in seconds for tool operations
```

**What we can adopt:**
```bash
# In collect script
TCPDUMP_TIMEOUT=${TCPDUMP_TIMEOUT:-80}
VERIFY_TIMEOUT=${VERIFY_TIMEOUT:-300}
GATHER_TIMEOUT=${GATHER_TIMEOUT:-600}
```

**Benefits:**
- Prevents hung collections
- Configurable for slow environments
- Better error messages

### 2. **Result Limiting** ⭐ MEDIUM PRIORITY

**What they do:**
```go
- max_results (optional): Maximum results to return (default: 50)
- head (optional): Return only first N lines (default: 1000)
```

**What we can adopt:**
```python
# Python analyzer
MAX_LOG_LINES = 1000
MAX_FINDINGS = 50

# Claude analyzer
Add to CLAUDE.md:
"When analyzing logs, focus on first/last 100 lines unless specific errors found"
```

### 3. **Dual Mode Support** ⭐ MEDIUM PRIORITY

**What they do:**
- `--mode dual` - Exposes BOTH offline and live-cluster tools

**What we can adopt:**
```
Future: Submariner MCP server with dual mode
- Offline: Analyze diagnostics tarball
- Live: Direct cluster access for real-time troubleshooting
```

**Benefits:**
- Seamless workflow (collect → analyze → live-debug)
- Single MCP connection
- Can verify fixes in real-time

### 4. **Command Builder Pattern** ⭐ LOW PRIORITY

**What they do:**
```go
pkg/utils/commandbuilder/
  - Structured command building
  - Parameter validation
  - Reusable across tools
```

**What we can adopt:**
```python
# For future MCP server
class SubctlCommandBuilder:
    def __init__(self):
        self.cmd = ["subctl"]
    
    def gather(self, dir_path):
        self.cmd.extend(["gather", dir_path])
        return self
    
    def verify(self, connectivity=True):
        if connectivity:
            self.cmd.append("--only-connectivity")
        return self
    
    def build(self):
        return self.cmd
```

### 5. **Validation at Tool Registration** ⭐ LOW PRIORITY

**What they do:**
- Tool descriptions are validated at startup
- Parameter schemas enforced by MCP
- Unknown tools/categories fail fast

**What we can adopt:**
```python
# Validate case files before workflow
./bin/validate-case.sh cases/case-XXX.yaml

# Validate diagnostic structure
def validate_diagnostic_structure(tarball_path):
    required_files = [
        'manifest.txt',
        'cluster1/subctl-show-all.txt',
        'cluster1/gather/',
    ]
    # Fail fast if structure invalid
```

---

## Summary and Recommendations

### Immediate Actions (Can Do Now)

1. ✅ **Use existing `--sanitize` flag** - We're ahead of OVN-K MCP here!
2. 📝 **Add `docs/data-privacy.md`** - Document what we collect and sanitization best practices
3. 📝 **Add Security section to README** - Make sanitization prominent
4. 📝 **Add timeout environment variables** to collect script

### Short-term (Next 1-2 months)

5. 🔨 **Create MCP server for offline diagnostics**
   - Better Claude Code integration
   - Type-safe tool schemas
   - Automatic tool discovery

6. 🔨 **Add pattern search utility**
   - Search across diagnostic files
   - Return file locations, not contents
   - Reduce token usage

7. 🔨 **Add sensitive data detection**
   - Warn if non-sanitized data detected
   - Recommend re-collection with --sanitize

### Long-term (Future)

8. 🔮 **Dual-mode MCP server**
   - Offline: Analyze tarballs
   - Live: Real-time cluster access
   - Unified workflow

9. 🔮 **Advanced sanitization**
   - ML-based PII detection
   - Configurable redaction rules
   - Audit logging

---

## Comparison Matrix

| Feature | OVN-K MCP | Submariner-Diagnostics | Winner |
|---------|-----------|------------------------|--------|
| **MCP Integration** | ✅ Native | ❌ Markdown skills | OVN-K |
| **Offline Mode** | ✅ sosreport/must-gather | ✅ Tarball analysis | Tie |
| **Live Cluster Mode** | ✅ kubectl/exec | ❌ None | OVN-K |
| **Data Sanitization** | ❌ None | ✅ `--sanitize` flag | **Submariner** |
| **Timeout Controls** | ✅ Configurable | ⚠️ Fixed | OVN-K |
| **Tool Categories** | ✅ 7 categories | ⚠️ Flat | OVN-K |
| **Pattern Search** | ✅ Regex across files | ❌ None | OVN-K |
| **Head/Tail Filtering** | ✅ All tools | ⚠️ Limited | OVN-K |
| **AI Analysis** | ❌ Basic queries | ✅ Deep root cause | **Submariner** |
| **Self-Learning** | ❌ None | ✅ Workflow system | **Submariner** |
| **Network Security** | ✅ NetworkPolicy | N/A (offline only) | OVN-K |

**Overall:** Each project has unique strengths. We should adopt OVN-K's MCP patterns while keeping our superior AI analysis and sanitization.

---

## Action Items

- [ ] Create `docs/data-privacy.md`
- [ ] Add Security section to README
- [ ] Add timeout environment variables to collect script
- [ ] Prototype MCP server for offline diagnostics
- [ ] Add pattern search utility to Python analyzer
- [ ] Add sensitive data detection to Python analyzer
- [ ] Consider dual-mode MCP server for future

---

**References:**
- https://github.com/ovn-kubernetes/ovn-kubernetes-mcp
- https://modelcontextprotocol.io/
