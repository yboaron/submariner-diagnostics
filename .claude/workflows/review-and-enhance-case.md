# Review and Enhance Case

This workflow takes a reviewed case file and automatically generates enhancements for both Python and Claude analyzers.

## How to Access This Workflow

This workflow is **automatically available** when you're in the submariner-diagnostics directory with Claude Code.
See [learn-from-investigation.md](learn-from-investigation.md) for setup details.

**TL;DR:** Just clone the repo, `cd` into it, and type `/workflow review-and-enhance-case cases/case-XXX.yaml`

## Purpose

After you've reviewed and approved a case file from `learn-from-investigation`, this workflow:
1. Generates Python detection code for `analyze-basic.py`
2. Updates Claude analysis documentation
3. Creates test cases
4. Runs all verification (lint + tests)
5. Creates a local git branch with changes
6. Prepares PR description

## Usage

```bash
/workflow review-and-enhance-case cases/case-XXX.yaml
```

## What It Does

- ✅ Validates case file completeness
- ✅ Generates Python detection function
- ✅ Creates/updates Claude documentation
- ✅ Generates pytest test cases
- ✅ Runs lint checks (Python, shell, markdown)
- ✅ Runs pytest
- ✅ Tests Python analyzer on original diagnostic
- ✅ Tests Claude analyzer integration
- ✅ Runs regression tests
- ✅ Creates git branch and commits
- ✅ Generates PR description

## Prerequisites

```bash
pip install pytest flake8 pylint black isort pyyaml
npm install -g markdownlint-cli
```

## Workflow

```javascript
export const meta = {
  name: 'review-and-enhance-case',
  description: 'Auto-generate analyzer enhancements from reviewed case',
  phases: [
    { title: 'Validate', detail: 'Check case file completeness' },
    { title: 'Python Code', detail: 'Generate detection for analyze-basic.py' },
    { title: 'Claude Docs', detail: 'Update analysis guides' },
    { title: 'Tests', detail: 'Generate test cases' },
    { title: 'Verify', detail: 'Run lint and tests' },
    { title: 'Prepare PR', detail: 'Create branch and PR description' },
  ],
}

// Read case file path from arguments
const caseFilePath = args[0]

if (!caseFilePath) {
  throw new Error('Usage: /workflow review-and-enhance-case cases/case-XXX.yaml')
}

phase('Validate')

log(`Validating case file: ${caseFilePath}`)

// Use existing validator script
const validateResult = await agent(
  `Run the validation script on the case file:
  
  ./bin/validate-case.sh ${caseFilePath}
  
  Then read and parse the YAML file to extract case data.
  
  RETURN:
  {
    valid: true,  // validator exited 0
    case_data: { ... parsed YAML content ... }
  }
  
  If validation fails, throw error with validator output.`,
  { phase: 'Validate', label: 'validate-case' }
)

if (!validateResult.valid) {
  throw new Error('Case file validation failed - see validator output above')
}

const caseData = validateResult.case_data
const caseId = caseData.metadata.case_id

log(`✓ Case validated: ${caseId}`)
log(`  Root cause: ${caseData.root_cause.summary}`)
log(`  Indicators: ${caseData.indicators.required?.length || 0} required, ${caseData.indicators.optional?.length || 0} optional`)

phase('Python Code')

log('Generating Python detection code...')

const pythonCode = await agent(
  `Generate Python detection function for analyze-basic.py

  Case data: ${JSON.stringify(caseData, null, 2)}

  REQUIREMENTS:

  1. Function name: detect_${caseId.replace(/-/g, '_')}()

  2. Implement detection logic from case file

  3. Follow existing patterns in analyze-basic.py:
     - Use self._read_file() to read files
     - Handle missing files gracefully
     - Return structured finding dict or None
     - Include comprehensive docstring

  4. Return format:
     {
         'issue_id': '${caseId}',
         'title': '...',
         'confidence': 'high' | 'medium' | 'low',
         'category': '${caseData.root_cause.category}',
         'description': '...',
         'evidence': [...],
         'remediation': '...',
     }

  5. Integration point:
     - Determine which section to add to (infrastructure, deployment, etc.)
     - Provide line number or section name

  GENERATE:
  {
    function_code: "...",  // The complete function
    insert_location: "...",  // Where to add in analyze-basic.py
    helper_functions: [...],  // Any helpers needed
    imports: [...],  // Any new imports needed
  }`,
  {
    phase: 'Python Code',
  }
)

log(`✓ Generated detect_${caseId.replace(/-/g, '_')}()`)

// Generate pytest tests
const pythonTests = await agent(
  `Generate pytest test cases for the detection function.

  Function: detect_${caseId.replace(/-/g, '_')}
  Case data: ${JSON.stringify(caseData, null, 2)}

  Create 4 test cases:

  1. test_detect_positive - Should detect the issue
     - Mock diagnostic with all required indicators
     - Should return detection with high confidence

  2. test_detect_negative - Should NOT detect when issue not present
     - Mock diagnostic without the indicators
     - Should return None

  3. test_partial_indicators - Some indicators present
     - Has some but not all required indicators
     - Should return None or low confidence

  4. test_false_positive_prevention - Similar symptoms, different cause
     - Use false positive scenarios from case file
     - Should return None

  GENERATE:
  {
    test_file_name: "test_case_${caseId.replace(/-/g, '_')}.py",
    test_code: "...",  // Complete test file
    test_count: 4,
  }`,
  {
    phase: 'Python Code',
  }
)

log(`✓ Generated ${pythonTests.test_count} test cases`)

phase('Claude Docs')

log('Updating Claude analysis documentation...')

const docsUpdate = await agent(
  `Update Claude analysis documentation for this case.

  Case data: ${JSON.stringify(caseData, null, 2)}

  TASKS:

  1. Determine which guide to update or if new guide needed:
     - Existing guides: tunnel-analysis.md, firewall-analysis.md,
       mtu-analysis.md, routeagent-analysis.md, gateway-ha-analysis.md,
       deployment-detection.md, special-cases.md
     - Platform-specific: aws-*.md, gcp-*.md, etc.
     - Issue-type specific: bug-*.md

  2. Generate markdown content:
     - Detection pattern section
     - Key indicators
     - Root cause explanation (use CAUTIOUS language!)
     - Remediation steps
     - False positive warnings
     - Cross-references to related docs

  3. For bugs: Add GitHub search recommendation

  GENERATE:
  {
    action: "update" | "create",
    file_path: "docs/analysis/...",
    content: "...",  // Markdown content to add/create
    summary: "...",  // What was changed
  }`,
  {
    phase: 'Claude Docs',
  }
)

log(`✓ ${docsUpdate.action === 'create' ? 'Created' : 'Updated'}: ${docsUpdate.file_path}`)

phase('Tests')

log('Creating test diagnostic files...')

const testDiagnostic = await agent(
  `Create minimal test diagnostic structure for this case.

  Case data: ${JSON.stringify(caseData, null, 2)}

  Steps:
  1. Create directory structure: tests/diagnostics/case-${caseId}/
  2. Include:
     - manifest.txt (basic metadata)
     - cluster1/ with only files needed for detection
     - Populate with realistic log excerpts from case file
     - Should trigger the new detection when analyzed
  3. Package as tar.gz: tests/diagnostics/case-${caseId}.tar.gz
     (analyze-basic.py requires .tar.gz format)

  GENERATE:
  {
    tarball_path: "tests/diagnostics/case-${caseId}.tar.gz",
    files: [
      { path: "...", content: "..." },
      ...
    ],
    description: "..."
  }`,
  {
    phase: 'Tests',
  }
)

log(`✓ Created test diagnostic: ${testDiagnostic.tarball_path}`)

phase('Verify')

log('Running automated verification...')
log('')

// Lint checks
log('→ Running lint checks...')

const lintResults = await parallel([
  () => agent(
    `Run Python linting:

    Command: make lint-python

    Check: analyze-basic.py

    If errors found:
    - Try auto-fix with: black analyze-basic.py && isort analyze-basic.py
    - Report remaining errors

    RETURN: { passed: true/false, errors: [...], auto_fixed: true/false }`,
    { label: 'lint-python', phase: 'Verify' }
  ),

  () => agent(
    `Run markdown linting:

    Command: make lint-markdown

    Check: ${docsUpdate.file_path}

    RETURN: { passed: true/false, errors: [...] }`,
    { label: 'lint-markdown', phase: 'Verify' }
  ),

  () => agent(
    `Run shell linting:

    Command: make lint-shell

    Check: bin/validate-case.sh and any other shell scripts

    RETURN: { passed: true/false, errors: [...] }`,
    { label: 'lint-shell', phase: 'Verify' }
  ),
])

const lintFailed = lintResults.filter(Boolean).filter(r => !r.passed)

if (lintFailed.length > 0) {
  log('❌ Lint checks failed:')
  lintFailed.forEach(r => log(JSON.stringify(r.errors, null, 2)))
  throw new Error('Lint errors - please fix manually')
}

log('✓ Lint checks passed')
log('')

// Run pytest
log('→ Running pytest...')

const pytestResult = await agent(
  `Run pytest on generated test file:

  Command: pytest tests/${pythonTests.test_file_name} -v

  Expected: All 4 tests pass

  RETURN: {
    all_passed: true/false,
    test_count: 4,
    failures: [...],
    output: "..."
  }`,
  { phase: 'Verify' }
)

if (!pytestResult.all_passed) {
  log('❌ Pytest failed:')
  log(pytestResult.output)
  throw new Error('Tests failing - review detection logic')
}

log(`✓ Pytest: ${pytestResult.test_count} tests passed`)
log('')

// Test on original diagnostic
log('→ Testing Python analyzer on original diagnostic...')

const pythonAnalyzerTest = await agent(
  `Run Python analyzer on original diagnostic:

  Command: ./analyze-basic.py ${caseData.diagnostic_file.path}

  Expected: Should detect issue "${caseId}"

  Verify:
  - Detection triggered
  - Correct issue ID
  - Appropriate confidence level

  RETURN: {
    detection_triggered: true/false,
    issue_found: "...",
    confidence: "...",
    output_snippet: "..."
  }`,
  { phase: 'Verify' }
)

if (!pythonAnalyzerTest.detection_triggered) {
  log('❌ Python analyzer did NOT detect the issue on original diagnostic!')
  throw new Error('Detection not working - check indicator patterns')
}

log(`✓ Python analyzer detected: ${pythonAnalyzerTest.issue_found}`)
log(`  Confidence: ${pythonAnalyzerTest.confidence}`)
log('')

// Regression tests
log('→ Running regression tests...')

const regressionTest = await agent(
  `Run analyze-basic.py on existing test diagnostics:

  Find: tests/diagnostics/*.tar.gz
  Run on each (exclude new case-${caseId}.tar.gz)

  Check:
  - No new false positives
  - Existing detections still work
  - No crashes

  RETURN: {
    test_count: N,
    regressions_found: 0,
    details: "..."
  }`,
  { phase: 'Verify' }
)

if (regressionTest.regressions_found > 0) {
  log('❌ Regression detected!')
  log(regressionTest.details)
  throw new Error('New code causes regressions')
}

log(`✓ No regressions in ${regressionTest.test_count} existing tests`)
log('')
log('✓ All verification passed!')

phase('Prepare PR')

log('Preparing pull request...')

// Generate PR description
const prDescription = await agent(
  `Generate comprehensive PR description:

  Case: ${JSON.stringify(caseData, null, 2)}

  Verification results:
  - Lint: ✓ Passed
  - Pytest: ✓ ${pytestResult.test_count} tests
  - Python analyzer: ✓ Detected on original diagnostic
  - Regression: ✓ No regressions (${regressionTest.test_count} tests)

  Create PR with conventional commits format:

  TITLE: feat: detect ${caseData.root_cause.summary.toLowerCase()}

  BODY should include:

  ## Summary
  [Brief description of what this detects]

  ## Case Information
  - **Case ID**: ${caseId}
  - **Root Cause**: ${caseData.root_cause.summary}
  - **Platform**: ${caseData.root_cause.platform_specific}
  - **Issue Type**: ${caseData.root_cause.issue_type}

  ## Detection Method
  **Key Indicators:**
  [List required indicators]

  **Confidence Scoring:**
  [Explain the scoring logic]

  ## Remediation
  [Summary of solutions]

  ## Changes
  - **Python Analyzer**: Added detect_${caseId.replace(/-/g, '_')}()
  - **Claude Docs**: ${docsUpdate.action === 'create' ? 'Created' : 'Updated'} ${docsUpdate.file_path}
  - **Tests**: Added ${pytestResult.test_count} test cases

  ## Verification
  ✓ Lint checks passed
  ✓ ${pytestResult.test_count} tests passed
  ✓ Detected on original diagnostic
  ✓ No regressions (${regressionTest.test_count} tests)

  ## Testing
  \`\`\`bash
  # Test detection
  ./analyze-basic.py ${caseData.diagnostic_file.path}

  # Run tests
  pytest tests/${pythonTests.test_file_name} -v
  \`\`\`

  ## Reviewer Checklist
  - [ ] Detection logic is clear and maintainable
  - [ ] No false positives
  - [ ] Documentation uses cautious language
  - [ ] Remediation is accurate
  - [ ] Tests cover edge cases

  ${caseData.root_cause.bug_info ? \`## Related
  - GitHub Issue: ${caseData.root_cause.bug_info.github_issue}
  ${caseData.root_cause.bug_info.fix_pr ? \`- Fix PR: ${caseData.root_cause.bug_info.fix_pr}\` : ''}
  \` : ''}

  ---
  Generated by learn-from-investigation workflow
  Case file: cases/approved/case-${caseId}.yaml

  COMMIT MESSAGE:
  feat: detect ${caseData.root_cause.summary.toLowerCase()}

  Add detection for ${caseId}:
  - ${pythonCode.function_code.split('\n')[0]}
  - ${docsUpdate.summary}
  - ${pytestResult.test_count} test cases

  ${caseData.root_cause.issue_type === 'bug' && caseData.root_cause.bug_info?.github_issue ?
    \`Related: ${caseData.root_cause.bug_info.github_issue}\` : ''}

  RETURN:
  {
    title: "...",
    body: "...",
    commit_message: "..."
  }`,
  { phase: 'Prepare PR' }
)

// Create branch
log('Creating local branch...')

const branchName = `enhance/case-${caseId}`

await agent(
  `Create git branch:

  Check current branch - if on main/devel, create: ${branchName}

  Command: git checkout -b ${branchName}`,
  { phase: 'Prepare PR' }
)

log(`✓ Branch created: ${branchName}`)

log('Writing generated files...')

// Write Python detection code to analyze-basic.py
await agent(
  `Append the generated Python detection function to analyze-basic.py:

  ${pythonCode.function_code}

  Insert before the main() function.
  
  RETURN: { success: true }`,
  { phase: 'Prepare PR', label: 'write-python-code' }
)
log(`✓ Updated analyze-basic.py`)

// Write Claude documentation
await agent(
  `Write or update the Claude analysis guide:
  
  File: ${docsUpdate.file_path}
  Content:
  ${docsUpdate.content}
  
  RETURN: { success: true }`,
  { phase: 'Prepare PR', label: 'write-docs' }
)
log(`✓ Updated ${docsUpdate.file_path}`)

// Write pytest test file
await agent(
  `Write the pytest test file:
  
  File: tests/${pythonTests.test_file_name}
  Content:
  ${pythonTests.test_code}
  
  RETURN: { success: true }`,
  { phase: 'Prepare PR', label: 'write-tests' }
)
log(`✓ Created tests/${pythonTests.test_file_name}`)

// Write test diagnostic files and create tarball
await agent(
  `Create test diagnostic files and package as tarball:
  
  Files: ${JSON.stringify(testDiagnostic.files, null, 2)}
  Tarball: ${testDiagnostic.tarball_path}
  
  1. Create directory structure
  2. Write all files
  3. Create .tar.gz archive
  4. Remove temporary directory
  
  RETURN: { success: true }`,
  { phase: 'Prepare PR', label: 'create-test-diagnostic' }
)
log(`✓ Created ${testDiagnostic.tarball_path}`)

// Move case file to approved
await agent(
  `Move case file to approved:

  From: ${caseFilePath}
  To: cases/approved/case-${caseId}.yaml
  
  RETURN: { success: true }`,
  { phase: 'Prepare PR', label: 'move-case-file' }
)
log(`✓ Moved case file to approved/`)

// Stage and commit
log('Staging and committing changes...')

await agent(
  `Stage all generated files and commit:

  Files to stage:
  - analyze-basic.py
  - ${docsUpdate.file_path}
  - tests/${pythonTests.test_file_name}
  - ${testDiagnostic.tarball_path}
  - cases/approved/case-${caseId}.yaml

  Commands:
  git add analyze-basic.py ${docsUpdate.file_path} tests/${pythonTests.test_file_name} ${testDiagnostic.tarball_path} cases/approved/case-${caseId}.yaml
  Command: git commit -s -m "${prDescription.commit_message}"

  RETURN: { commit_hash: "..." }`,
  { phase: 'Prepare PR' }
)

// Write PR description to file
const prDescFile = `pr-description-case-${caseId}.md`

await agent(
  `Write PR description to file: ${prDescFile}

  Content:
  # ${prDescription.title}

  ${prDescription.body}`,
  { phase: 'Prepare PR' }
)

log('')
log('═'.repeat(70))
log('✓ ALL AUTOMATED STEPS COMPLETE!')
log('═'.repeat(70))
log('')
log(`Case ID: ${caseId}`)
log(`Branch: ${branchName}`)
log(`PR Description: ${prDescFile}`)
log('')
log('VERIFICATION SUMMARY:')
log('  ✓ Lint checks: Passed')
log(`  ✓ Pytest: ${pytestResult.test_count}/${pytestResult.test_count} passed`)
log(`  ✓ Python analyzer: Detected on original diagnostic`)
log(`  ✓ Regression tests: No regressions (${regressionTest.test_count} tests)`)
log('')
log('NEXT STEPS:')
log('')
log('1. Review changes:')
log(`   git diff main..${branchName}`)
log('')
log('2. Review PR description:')
log(`   cat ${prDescFile}`)
log('')
log('3. Push branch:')
log(`   git push origin ${branchName}`)
log('')
log('4. Create PR (choose one):')
log('')
log('   METHOD 1 - GitHub CLI:')
log(`   gh pr create --title "${prDescription.title}" \\`)
log(`     --body-file ${prDescFile} \\`)
log(`     --label enhancement`)
log('')
log('   METHOD 2 - GitHub Web UI:')
log('   - GitHub will show "Compare & pull request" after push')
log(`   - Copy description from: ${prDescFile}`)
log('')
log('═'.repeat(70))

return {
  status: 'ready_for_pr',
  case_id: caseId,
  branch: branchName,
  pr_description_file: prDescFile,
  verification: {
    lint: 'passed',
    pytest: `${pytestResult.test_count} tests passed`,
    integration: 'detected on original diagnostic',
    regression: `no regressions (${regressionTest.test_count} tests)`,
  },
  files_changed: [
    'analyze-basic.py',
    docsUpdate.file_path,
    `tests/${pythonTests.test_file_name}`,
    `tests/diagnostics/case-${caseId}/`,
    `cases/approved/case-${caseId}.yaml`,
  ],
}
```

This workflow handles all the code generation, testing, and PR preparation automatically.
