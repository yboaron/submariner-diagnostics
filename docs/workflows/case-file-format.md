# Case File Format

This document describes the YAML format for Submariner diagnostic case files.

## Purpose

Case files capture investigated Submariner issues in a structured format that enables:
1. Automatic enhancement of both Python and Claude analyzers
2. Knowledge preservation across investigations
3. Consistent documentation
4. Test case generation

## How Case Files Are Created

Case files are created through the `learn-from-investigation` workflow.

**Setup (one-time):**

```bash
# Clone the repository
git clone https://github.com/submariner-io/submariner-diagnostics.git
cd submariner-diagnostics

# Workflows are now automatically available!
```

**Usage:**

```bash
# Run the workflow (from submariner-diagnostics directory)
/workflow learn-from-investigation
```

This workflow conducts an AI-guided interview to extract all necessary information from your investigation.

**Note:** The workflow is automatically discovered by Claude Code when you're in the repo directory. No installation or copying needed!

## File Structure

```yaml
# Case file template

metadata:
  case_id: "XXX-descriptive-slug"
  created_date: "YYYY-MM-DD"
  confidence: "high" | "medium" | "low"

issue:
  complaint: "What the end-user reported"
  symptoms:
    - tunnel_not_connected
    - connectivity_failed
    # ... etc

root_cause:
  summary: "One sentence root cause"
  explanation: |
    Detailed explanation of WHY this happened.
    Can be multiple lines.

  category: "infrastructure_misconfiguration" | "software_bug" | ...
  issue_type: "bug" | "misconfiguration" | "infrastructure" | "deployment_method"

  bug_info:  # Only if issue_type is "bug"
    github_issue: "https://github.com/submariner-io/..."
    affected_versions: "0.20-0.23"
    fixed_in_version: "0.24.0"
    fix_pr: "https://github.com/submariner-io/..."

  platform_specific: "aws" | "gcp" | "azure" | "any" | ...

indicators:
  required:  # Must be present for detection
    - name: "Short indicator name"
      file_location: "relative/path/in/diagnostic/*"
      actual_path: "resolved/path/without/wildcards"
      pattern: "text pattern to match"
      regex: "optional regex pattern"
      significance: "Why this matters for root cause"
      excerpt: |
        Actual log lines found (with context)

  optional:  # Boost confidence but not required
    - name: "..."
      # ... same structure

  detection_logic:
    pseudo_code: |
      def detect():
          confidence = 0
          if required_pattern_1:
              confidence += 40
          # ...
          return detection if confidence >= threshold

    confidence_thresholds:
      high: 80
      medium: 60
      low: 40

    scoring_rules: |
      Explanation of how confidence is calculated

remediation:
  solutions:
    - type: "permanent_fix" | "workaround" | "upgrade" | "escalate"
      name: "Solution name"
      description: "What this solution does"

      steps:  # For permanent_fix and workaround
        - description: "Step description"
          command: "oc patch <resource> -n <namespace> ..."
          context: "Where to run (ACM hub, managed cluster, etc)"
          expected_output: "What to expect"

      verification:  # How to verify it worked
        - "Check X"
        - "Verify Y"

      expected_duration: "2-5 minutes"

      caveats:  # Important warnings
        - "May cause X"
        - "Does not address Y"

      trade_offs:  # For workarounds
        - "Security: Reduces isolation"
        - "Performance: Adds overhead"

      when_to_use: "When to choose this solution"

false_positives:
  - similar_symptom: "What looks similar"
    actual_different_cause: "But is actually this"
    how_to_distinguish: "Look for this difference"

related_information:
  platform: "aws" | ...
  affected_versions:
    acm: "2.17.0" | "all" | "2.15+"
    submariner: "0.24.0" | ...
    ocp: "4.21.22" | ...

diagnostic_file:
  path: "path/to/original/diagnostic.tar.gz"
  analyzed: true

analysis_notes: |
  Any additional context or learnings
```

## Field Descriptions

### metadata

- **case_id**: Unique identifier (auto-generated)
- **created_date**: When case was created
- **confidence**: How confident we are in this root cause

### issue

- **complaint**: What the user reported (their words, not technical)
- **symptoms**: List of observable symptoms

### root_cause

- **summary**: One-sentence root cause
- **explanation**: Detailed WHY this happened
- **category**: What type of issue
- **issue_type**: Bug vs user error vs infrastructure
- **bug_info**: Details if it's a software bug
- **platform_specific**: Cloud platform or "any"

### indicators

Lists the key evidence that led to the root cause.

**required**: Indicators that MUST be present for confident detection
**optional**: Indicators that boost confidence but aren't essential

Each indicator includes:
- **name**: Short descriptive name
- **file_location**: Where in diagnostic (can use wildcards)
- **actual_path**: Resolved path (from validation)
- **pattern**: Text to match
- **regex**: Optional regex for complex patterns
- **significance**: Why this matters
- **excerpt**: Actual log lines found

### remediation

**solutions**: List of ways to fix/workaround the issue

Each solution specifies:
- **type**:
  - `permanent_fix`: Resolves root cause
  - `workaround`: Bypasses issue without fixing
  - `upgrade`: Fixed in newer version
  - `escalate`: Needs expert help

- **steps**: Commands to run (with placeholders like `<cluster-name>`)
- **verification**: How to confirm it worked
- **caveats**: Important warnings
- **trade_offs**: Impacts of workarounds

### false_positives

Documents similar-looking issues to help distinguish them.

## Example

See `docs/workflows/examples/case-001-aws-missing-gateway-sg.yaml` for a complete example.

## Validation

Before using a case file for enhancement, validate it:

```bash
./bin/validate-case.sh cases/case-XXX.yaml
```

## Workflow Integration

1. **Create**: `/workflow learn-from-investigation`
2. **Review**: Edit `cases/case-XXX.yaml`
3. **Enhance**: `/workflow review-and-enhance-case cases/case-XXX.yaml`

The enhancement workflow:
- Validates the case file
- Generates Python detection code
- Updates Claude documentation
- Creates tests
- Prepares PR

## Best Practices

### Indicators

- Provide at least 3-5 strong indicators
- Mark truly required ones as `required: true`
- Include enough context in excerpts
- Use wildcards for pod names: `pods/submariner-gateway-*/logs.txt`

### Remediation

- Always provide a primary solution
- Include alternatives if primary might fail
- Be specific with commands
- Use placeholders: `<cluster-name>`, `<namespace>`
- Document where each command runs

### False Positives

- Think about what else could cause similar symptoms
- Document how to distinguish
- This prevents false positive detections

### Language

- Use cautious language in explanations
- "appears to be", "most likely", "could be"
- Acknowledge uncertainty
- This carries through to generated docs

## See Also

- [Learn From Investigation Workflow](.claude/workflows/learn-from-investigation.md)
- [Review and Enhance Workflow](.claude/workflows/review-and-enhance-case.md)
- [Example Case File](../docs/workflows/examples/case-001-aws-missing-gateway-sg.yaml)
