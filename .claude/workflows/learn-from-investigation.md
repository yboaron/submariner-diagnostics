# Learn From Investigation

This workflow conducts an AI-guided interview to document an investigated Submariner issue and create a structured case file.

## How to Access This Workflow

This workflow is **automatically available** when you're in the submariner-diagnostics directory with Claude Code:

1. Clone the repository: `git clone https://github.com/submariner-io/submariner-diagnostics.git`
2. Navigate to it: `cd submariner-diagnostics`
3. Open Claude Code in this directory
4. The workflow is now available - just type `/workflow learn-from-investigation`

**No installation or copying needed!** Workflows in `.claude/workflows/` are automatically discovered by Claude Code.

## Purpose

When you investigate a Submariner issue manually and determine the root cause, this workflow helps you:
1. Document all key findings systematically
2. Extract evidence from the diagnostic file
3. Create a structured case file for future enhancement
4. Ensure all necessary information is captured

## Usage

```bash
/workflow learn-from-investigation
```

The AI will interview you about your investigation.

## What You Need

Before running this workflow, you should have:
- Completed your investigation
- Determined the root cause
- Tested remediation steps
- The diagnostic tarball you analyzed

## Workflow

```javascript
export const meta = {
  name: 'learn-from-investigation',
  description: 'AI-guided interview to create case file from investigation',
  phases: [
    { title: 'Interview', detail: 'Gather investigation details' },
    { title: 'Analyze', detail: 'Validate indicators in diagnostic' },
    { title: 'Generate', detail: 'Create structured case file' },
  ],
}

// Schema for structured interview output
const INTERVIEW_SCHEMA = {
  type: "object",
  required: ["diagnostic_path", "user_complaint", "root_cause", "key_indicators", "remediation"],
  properties: {
    diagnostic_path: {
      type: "string",
      description: "Path to diagnostic tarball"
    },

    user_complaint: {
      type: "string",
      description: "What the end-user reported (their words, not root cause)"
    },

    symptoms: {
      type: "array",
      items: {
        enum: ["tunnel_not_connected", "connectivity_failed", "pod_crashloop",
               "service_discovery_broken", "performance_degraded", "other"]
      }
    },

    root_cause: {
      type: "object",
      required: ["summary", "issue_type", "category"],
      properties: {
        summary: {
          type: "string",
          description: "One sentence summary of root cause"
        },
        detailed_explanation: {
          type: "string",
          description: "Detailed explanation of WHY this happened"
        },
        category: {
          enum: ["infrastructure_misconfiguration", "software_bug", "network_policy",
                 "deployment_method", "version_incompatibility", "resource_constraints"]
        },
        issue_type: {
          enum: ["bug", "misconfiguration", "infrastructure", "deployment_method"],
          description: "Is this a bug or user error?"
        },
      },
    },

    bug_info: {
      type: "object",
      description: "Required if issue_type is 'bug'",
      properties: {
        github_url: { type: "string" },
        affected_versions: { type: "string" },
        fixed_in_version: { type: "string" },
        fix_pr: { type: "string" },
      },
    },

    key_indicators: {
      type: "array",
      minItems: 3,
      description: "At least 3 key indicators required",
      items: {
        type: "object",
        required: ["name", "file_location", "pattern", "significance", "required"],
        properties: {
          name: {
            type: "string",
            description: "Short name for this indicator"
          },
          file_location: {
            type: "string",
            description: "Path within diagnostic (can use wildcards)"
          },
          pattern: {
            type: "string",
            description: "Text pattern to match"
          },
          regex_pattern: {
            type: "string",
            description: "Optional: regex if simple pattern not enough"
          },
          significance: {
            type: "string",
            description: "Why is this significant? How does it relate to root cause?"
          },
          required: {
            type: "boolean",
            description: "Must this indicator be present (true) or is it optional (false)?"
          },
        },
      },
    },

    remediation: {
      type: "array",
      minItems: 1,
      description: "At least one remediation solution",
      items: {
        type: "object",
        required: ["type", "name", "description"],
        properties: {
          type: {
            enum: ["permanent_fix", "workaround", "upgrade", "escalate"],
            description: "Type of solution"
          },
          name: { type: "string" },
          description: { type: "string" },
          steps: {
            type: "array",
            description: "Step-by-step commands",
            items: {
              type: "object",
              properties: {
                description: { type: "string" },
                command: { type: "string" },
                context: { type: "string", description: "Where to run (hub/managed cluster/etc)" },
                expected_output: { type: "string" },
              }
            }
          },
          verification_steps: {
            type: "array",
            items: { type: "string" }
          },
          expected_duration: { type: "string" },
          caveats: {
            type: "array",
            items: { type: "string" }
          },
          trade_offs: {
            type: "array",
            items: { type: "string" },
            description: "Important for workarounds: security, performance impacts"
          },
          when_to_use: { type: "string" },
        },
      },
    },

    platform: {
      enum: ["aws", "gcp", "azure", "openstack", "baremetal", "vmware", "any"]
    },

    affected_versions: {
      type: "object",
      properties: {
        acm: { type: "string" },
        submariner: { type: "string" },
        ocp: { type: "string" },
      }
    },
  },
}

phase('Interview')

log('Starting AI-guided case creation interview...')
log('This will help document your investigation for future enhancement.')
log('')

const caseInfo = await agent(
  `You are interviewing a Submariner expert who just investigated an issue.

  Conduct a thorough, structured interview to extract ALL necessary information.

  INTERVIEW GUIDELINES:

  1. Ask questions ONE AT A TIME
  2. Wait for answer before asking next question
  3. Probe for specifics when answers are vague
  4. Confirm understanding by paraphrasing
  5. Be thorough but efficient

  INFORMATION TO GATHER:

  ═══════════════════════════════════════════════════════════════
  SECTION 1: BASIC INFORMATION
  ═══════════════════════════════════════════════════════════════

  Ask: "What is the path to the diagnostic tarball you investigated?"
       Example: submariner-diagnostics-20260707-093439.tar.gz

  Ask: "What did the end-user report? What were they seeing?"
       (Get their exact words, not the technical root cause)
       Example: "Gateway pod failing with sendmsg: operation not permitted"

  Ask: "What symptoms did they observe?"
       Options: tunnel_not_connected, connectivity_failed, pod_crashloop,
                service_discovery_broken, performance_degraded, other

  ═══════════════════════════════════════════════════════════════
  SECTION 2: ROOT CAUSE ANALYSIS
  ═══════════════════════════════════════════════════════════════

  Ask: "What is the root cause of this issue?"
       (Get a clear, one-sentence summary)

  Ask: "Can you explain in detail WHY this happened?"
       (Get the deeper explanation)

  Ask: "What category does this fall under?"
       Options: infrastructure_misconfiguration, software_bug, network_policy,
                deployment_method, version_incompatibility, resource_constraints

  Ask: "Is this a Submariner software bug, user misconfiguration,
        infrastructure issue, or deployment method problem?"

  If BUG:
    Ask: "Is there a GitHub issue for this bug?"
    Ask: "Which Submariner versions are affected?"
    Ask: "Has it been fixed? If so, in which version?"
    Ask: "Is there a fix PR?"

  If MISCONFIGURATION/DEPLOYMENT:
    Ask: "What exactly was misconfigured?"
    Ask: "Why did the user make this mistake?"
         (Unclear docs? Common misconception? Tool limitation?)

  ═══════════════════════════════════════════════════════════════
  SECTION 3: KEY INDICATORS (MOST IMPORTANT)
  ═══════════════════════════════════════════════════════════════

  Ask: "What were the key clues that led you to this root cause?"
       "Let's go through them one by one. What was the FIRST key indicator?"

  For EACH indicator (get at least 3-5):
    Ask: "What is a short name for this indicator?"
         Example: "Gateway sendmsg error"

    Ask: "Where EXACTLY in the diagnostic did you find this?"
         Example: "cluster1/gather/submariner-operator/pods/submariner-gateway-*/logs.txt"
         (Encourage wildcards like * for pod names)

    Ask: "What EXACT text or pattern did you see?"
         Example: "sendmsg: operation not permitted"

    Ask: "Can you show me the actual log line you found?"
         (This helps validate and create test cases)

    Ask: "Why is this significant? How does it relate to the root cause?"
         Example: "Gateway cannot send packets because node lacks network config"

    Ask: "Is this indicator ALWAYS present (required) or just commonly present (optional)?"

    Ask: "Are there more indicators? What's the next one?"
    (Continue until they say no more)

  PROBE for thoroughness:
    - "Did you check the Gateway CR status?"
    - "Did you look at RouteAgent CRs?"
    - "Any patterns in tcpdump analysis?"
    - "Did you check deployment type (ACM vs Standalone)?"

  ═══════════════════════════════════════════════════════════════
  SECTION 4: REMEDIATION
  ═══════════════════════════════════════════════════════════════

  Ask: "How did you fix or work around this issue?"

  Ask: "Is this a permanent fix, workaround, or does it require upgrade?"

  For EACH solution:
    Ask: "What's a good name for this solution?"

    Ask: "Can you describe it briefly?"

    Ask: "What are the exact steps? Include commands with placeholders."
         Example: "oc patch submarinerconfig submariner -n <cluster-name> ..."

    Ask: "Where should each command be run? (ACM hub, managed cluster, etc.)"

    Ask: "How do you verify it worked?"

    Ask: "How long should this take?"

    If WORKAROUND:
      Ask: "What are the caveats or trade-offs?"
           (Security implications? Performance impact? Technical debt?)

    Ask: "When should someone use this solution vs alternatives?"

  Ask: "Are there alternative solutions if this doesn't work?"

  ═══════════════════════════════════════════════════════════════
  SECTION 5: FALSE POSITIVES
  ═══════════════════════════════════════════════════════════════

  Ask: "What other issues have similar symptoms but different root causes?"
       "How would you distinguish this issue from those?"

  Example: "sendmsg errors can also be caused by SELinux, how is this different?"

  ═══════════════════════════════════════════════════════════════
  SECTION 6: ADDITIONAL CONTEXT
  ═══════════════════════════════════════════════════════════════

  Ask: "Is this specific to a platform? (AWS, GCP, Azure, any cloud, bare metal?)"

  Ask: "Which versions were affected? ACM? Submariner? OpenShift?"

  Ask: "Are there any related GitHub issues or documentation?"

  ═══════════════════════════════════════════════════════════════

  OUTPUT FORMAT:

  Return structured data matching this schema:
  ${JSON.stringify(INTERVIEW_SCHEMA, null, 2)}

  Be conversational but thorough. Thank them for their time at the end.`,
  {
    schema: INTERVIEW_SCHEMA,
    phase: 'Interview',
    model: 'opus'  // Use best model for interviewing
  }
)

log('')
log('✓ Interview complete! Analyzing diagnostic file...')

phase('Analyze')

// Validate indicators exist in diagnostic
const validation = await agent(
  `Validate indicators by analyzing the diagnostic file.

  Diagnostic file: ${caseInfo.diagnostic_path}

  Reported indicators:
  ${JSON.stringify(caseInfo.key_indicators, null, 2)}

  TASKS:

  1. Extract the diagnostic tarball
  2. For EACH reported indicator:
     - Verify the file exists at reported location
     - Search for the pattern in that file
     - Extract the actual log excerpt (5 lines of context)
     - If regex provided, test it matches correctly
     - Note exact file path (resolve wildcards)

  3. Look for ADDITIONAL indicators not mentioned:
     - Related error messages
     - Status fields in CRs
     - Missing expected data
     - Correlated patterns

  4. Identify FALSE POSITIVE scenarios:
     - Find patterns that look similar but mean different things
     - Document how to distinguish them

  5. Assess overall confidence:
     - How strong is the evidence?
     - How unique are the patterns?
     - Risk of false positives?

  RETURN:
  {
    validated_indicators: [
      {
        name: "...",
        found: true/false,
        actual_file_path: "...",  // Resolved path (no wildcards)
        log_excerpt: "...",       // Actual text found with context
        line_number: 123,
        required: true/false,
      }
    ],
    additional_indicators: [
      // Any indicators you found that weren't mentioned
    ],
    false_positive_scenarios: [
      {
        symptom: "...",
        actual_cause: "...",
        how_to_distinguish: "...",
      }
    ],
    confidence_level: "high" | "medium" | "low",
    analysis_notes: "...",
  }`,
  {
    phase: 'Analyze',
  }
)

if (validation.validated_indicators.filter(i => !i.found).length > 0) {
  log('⚠️  Warning: Some indicators were not found in diagnostic:')
  validation.validated_indicators
    .filter(i => !i.found)
    .forEach(i => log(`  - ${i.name}: Not found at ${i.actual_file_path || 'unknown path'}`))

  log('')
  log('Please verify the file paths are correct.')
  log('You may need to extract the diagnostic manually to check.')
}

log('')
log('✓ Diagnostic analysis complete')

phase('Generate')

log('Generating structured case file...')

// Generate detection logic
const detectionLogic = await agent(
  `Generate programmatic detection logic for Python analyzer.

  Root cause: ${caseInfo.root_cause.summary}
  Validated indicators: ${JSON.stringify(validation.validated_indicators, null, 2)}

  Create PYTHON-STYLE pseudo-code for detection:

  def detect_issue(diagnostic_data):
      \"\"\"
      Detects: [summary]

      Confidence scoring:
      - Required indicators: X points each
      - Optional indicators: Y points each
      - Threshold: Z points for detection
      \"\"\"
      confidence = 0
      findings = []

      # Check required indicators
      if check_pattern_1:
          confidence += 40
          findings.append("...")
      else:
          return None  # Required - must have this

      if check_pattern_2:
          confidence += 30
          findings.append("...")
      else:
          return None

      # Check optional indicators (boost confidence)
      if check_optional_1:
          confidence += 20
          findings.append("...")

      # Thresholds
      if confidence >= 70:
          return {
              "issue_id": "...",
              "confidence": "high" if confidence >= 80 else "medium",
              "findings": findings
          }

      return None

  Make it:
  - Robust (handles missing files)
  - Specific (avoids false positives)
  - Well-documented

  RETURN:
  {
    pseudo_code: "...",
    confidence_thresholds: {
      high: 80,
      medium: 60,
      low: 40
    },
    scoring_rules: "..."
  }`,
  {
    phase: 'Generate',
  }
)

// Assign case ID with full timestamp for uniqueness
const timestamp = Date.now()
const slug = caseInfo.root_cause.summary
  .toLowerCase()
  .replace(/[^a-z0-9]+/g, '-')
  .replace(/^-|-$/g, '')
  .slice(0, 40)
const caseId = `${timestamp}-${slug}`

log(`Assigned case ID: ${caseId}`)

// Assemble complete case file
const caseYAML = `# Submariner Diagnostic Case File
# Generated by learn-from-investigation workflow
# Date: ${new Date().toISOString().split('T')[0]}

metadata:
  case_id: "${caseId}"
  created_date: "${new Date().toISOString().split('T')[0]}"
  confidence: "${validation.confidence_level}"

issue:
  complaint: "${caseInfo.user_complaint}"
  symptoms:
${(caseInfo.symptoms || []).map(s => `    - ${s}`).join('\n')}

root_cause:
  summary: "${caseInfo.root_cause.summary}"
  explanation: |
    ${caseInfo.root_cause.detailed_explanation || 'No detailed explanation provided'}

  category: "${caseInfo.root_cause.category}"
  issue_type: "${caseInfo.root_cause.issue_type}"

  ${caseInfo.bug_info ? `bug_info:
    github_issue: "${caseInfo.bug_info.github_url || ''}"
    affected_versions: "${caseInfo.bug_info.affected_versions || ''}"
    fixed_in_version: "${caseInfo.bug_info.fixed_in_version || ''}"
    fix_pr: "${caseInfo.bug_info.fix_pr || ''}"
  ` : '# Not a software bug'}

  platform_specific: "${caseInfo.platform}"

indicators:
  required:
${validation.validated_indicators.filter(i => i.required).map(ind => {
      const ki = caseInfo.key_indicators.find(k => k.name === ind.name) || {}
      return `    - name: "${ind.name}"
      file_location: "${ki.file_location || 'unknown'}"
      actual_path: "${ind.actual_file_path || 'unknown'}"
      pattern: "${ki.pattern || ''}"
      ${ki.regex_pattern ? `regex: "${ki.regex_pattern}"` : ''}
      significance: "${ki.significance || ''}"
      excerpt: |
        ${(ind.log_excerpt || '').split('\n').join('\n        ')}`
    }).join('\n\n')}

  optional:
${validation.validated_indicators.filter(i => !i.required).map(ind => {
      const ki = caseInfo.key_indicators.find(k => k.name === ind.name) || {}
      return `    - name: "${ind.name}"
      file_location: "${ki.file_location || 'unknown'}"
      actual_path: "${ind.actual_file_path || 'unknown'}"
      pattern: "${ki.pattern || ''}"
      significance: "${ki.significance || ''}"`
    }).join('\n\n')}

  detection_logic:
    pseudo_code: |
${detectionLogic.pseudo_code.split('\n').map(l => `      ${l}`).join('\n')}

    confidence_thresholds:
      high: ${detectionLogic.confidence_thresholds.high}
      medium: ${detectionLogic.confidence_thresholds.medium}
      low: ${detectionLogic.confidence_thresholds.low}

    scoring_rules: |
      ${detectionLogic.scoring_rules}

remediation:
  solutions:
${caseInfo.remediation.map((sol, idx) => `    - type: "${sol.type}"
      name: "${sol.name}"
      description: "${sol.description}"
      ${sol.steps ? `
      steps:
${sol.steps.map(step => `        - description: "${step.description}"
          command: "${step.command}"
          context: "${step.context}"
          ${step.expected_output ? `expected_output: "${step.expected_output}"` : ''}`).join('\n')}
      ` : ''}
      ${sol.verification_steps ? `
      verification:
${sol.verification_steps.map(v => `        - "${v}"`).join('\n')}
      ` : ''}
      ${sol.expected_duration ? `expected_duration: "${sol.expected_duration}"` : ''}
      ${sol.caveats?.length ? `
      caveats:
${sol.caveats.map(c => `        - "${c}"`).join('\n')}
      ` : ''}
      ${sol.trade_offs?.length ? `
      trade_offs:
${sol.trade_offs.map(t => `        - "${t}"`).join('\n')}
      ` : ''}
      ${sol.when_to_use ? `when_to_use: "${sol.when_to_use}"` : ''}`).join('\n\n')}

false_positives:
${(validation.false_positive_scenarios || []).map(fp => `  - similar_symptom: "${fp.symptom}"
    actual_different_cause: "${fp.actual_cause}"
    how_to_distinguish: "${fp.how_to_distinguish}"`).join('\n\n')}

related_information:
  platform: "${caseInfo.platform}"
  affected_versions:
    acm: "${caseInfo.affected_versions?.acm || 'unknown'}"
    submariner: "${caseInfo.affected_versions?.submariner || 'unknown'}"
    ocp: "${caseInfo.affected_versions?.ocp || 'unknown'}"

diagnostic_file:
  path: "${caseInfo.diagnostic_path}"
  analyzed: true

analysis_notes: |
  ${validation.analysis_notes || 'No additional notes'}
`

// Write case file
const caseFilePath = `cases/case-${caseId}.yaml`

// (Write file using agent or direct file write)
await agent(
  `Write case file to: ${caseFilePath}

  Content:
  ${caseYAML}`,
  { phase: 'Generate' }
)

log('')
log('═'.repeat(70))
log('✓ CASE FILE GENERATED!')
log('═'.repeat(70))
log('')
log(`Case ID: ${caseId}`)
log(`File: ${caseFilePath}`)
log('')
log('NEXT STEPS:')
log('')
log('1. Review the case file:')
log(`   cat ${caseFilePath}`)
log('')
log('2. Edit if needed:')
log(`   vim ${caseFilePath}`)
log('')
log('3. When ready, generate analyzer enhancements:')
log(`   /workflow review-and-enhance-case ${caseFilePath}`)
log('')
log('═'.repeat(70))

return {
  status: 'success',
  case_id: caseId,
  case_file: caseFilePath,
  confidence: validation.confidence_level,
  indicators_validated: validation.validated_indicators.filter(i => i.found).length,
  indicators_missing: validation.validated_indicators.filter(i => !i.found).length,
  next_workflow: 'review-and-enhance-case',
}
```

This workflow creates a systematic interview process and generates a complete case file ready for enhancement.
