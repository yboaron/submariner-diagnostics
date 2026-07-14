# Self-Learning Workflow Usage Guide

Quick reference for using the self-learning diagnostic enhancement workflows.

## One-Time Setup

```bash
# 1. Clone the repository
git clone https://github.com/submariner-io/submariner-diagnostics.git
cd submariner-diagnostics

# 2. Install development dependencies (for verification)
pip install pytest flake8 pylint black isort pyyaml

# 3. That's it! Workflows are automatically available
```

## How It Works

When you're in the `submariner-diagnostics` directory with Claude Code, workflows in `.claude/workflows/` are **automatically discovered**.

No copying, no installation - just use them with `/workflow <name>`.

## Available Workflows

### 1. learn-from-investigation

**Purpose:** Document an investigated issue through AI-guided interview

**When to use:** After you've manually investigated an issue and determined the root cause

**Command:**
```bash
/workflow learn-from-investigation
```

**What happens:**
1. AI asks structured questions about your investigation
2. Validates indicators exist in the diagnostic file
3. Generates a case file: `cases/case-XXX.yaml`

**Time:** ~5-10 minutes

### 2. review-and-enhance-case

**Purpose:** Auto-generate analyzer enhancements from a case file

**When to use:** After reviewing the case file from `learn-from-investigation`

**Command:**
```bash
/workflow review-and-enhance-case cases/case-XXX.yaml
```

**What happens:**
1. Validates case file
2. Generates Python detection code
3. Updates Claude documentation
4. Creates test cases
5. Runs all verification (lint + tests + regression)
6. Creates git branch
7. Prepares PR description
8. **Stops before GitHub** (you push manually)

**Time:** ~2-5 minutes

## Complete Example

```bash
# Navigate to repo
cd submariner-diagnostics

# After investigating an issue manually...

# Step 1: Document investigation
/workflow learn-from-investigation

# AI asks questions like:
# - What diagnostic file did you analyze?
# - What did the user report?
# - What's the root cause?
# - What are the key indicators?
# - How do you fix it?

# Output: cases/case-001-aws-gateway-sg.yaml

# Step 2: Review the case file
cat cases/case-001-aws-gateway-sg.yaml
vim cases/case-001-aws-gateway-sg.yaml  # Edit if needed

# Step 3: Auto-generate enhancements
/workflow review-and-enhance-case cases/case-001-aws-gateway-sg.yaml

# AI automatically:
# ✓ Generates detection code
# ✓ Updates docs
# ✓ Creates tests
# ✓ Runs verification
# ✓ Creates branch
# ✓ Prepares PR description

# Step 4: Push and create PR (manual)
git push origin enhance/case-001-aws-gateway-sg
gh pr create --fill
```

## FAQs

### Q: Do I need to install the workflows?

**A:** No! They're automatically available when you're in the submariner-diagnostics directory.

### Q: Can I use these from any directory?

**A:** No. You must be in the submariner-diagnostics directory (or a subdirectory) for Claude Code to find the workflows.

### Q: What if I'm on a different branch?

**A:** Workflows are part of the repository, so they're available on any branch that has them.
The enhancement workflow will create a new branch for you.

### Q: Do I need GitHub authentication?

**A:** Not for the workflows. They stop before pushing to GitHub. You'll manually run `git push` and create the PR yourself.

### Q: Can I modify the workflows?

**A:** Yes! They're just markdown files in `.claude/workflows/`. You can customize them for your needs.

### Q: What if the workflow fails?

**A:** The workflows include detailed error messages. Common issues:
- Case file validation failed → Fix validation errors in the case file
- Tests failing → Review detection logic in case file
- Lint errors → Workflows try to auto-fix, but some need manual fixes

### Q: Can I run multiple enhancements in parallel?

**A:** Each enhancement creates a git branch. You can run them sequentially, reviewing each case file before enhancement.

## Validation

Validate a case file before enhancement:

```bash
# Using script
./bin/validate-case.sh cases/case-XXX.yaml

# Or using Makefile
make -f Makefile.local validate-case CASE=cases/case-XXX.yaml
```

## Development Tasks

Local lint and test commands:

```bash
# Run all lint checks
make -f Makefile.local lint

# Run tests
make -f Makefile.local test

# Run everything
make -f Makefile.local verify

# Auto-fix Python formatting
make -f Makefile.local format-python
```

## Troubleshooting

### Workflow not found

**Problem:** `/workflow learn-from-investigation` says workflow not found

**Solution:**
1. Verify you're in the submariner-diagnostics directory: `pwd`
2. Check the file exists: `ls .claude/workflows/learn-from-investigation.md`
3. Restart Claude Code if needed

### AI can't read diagnostic file

**Problem:** Workflow says diagnostic file not found

**Solution:**
- Use relative path from current directory
- Or use absolute path: `/full/path/to/diagnostic.tar.gz`

### Verification fails

**Problem:** Lint or tests fail during enhancement

**Solution:**
1. Check the error message
2. Fix the case file if validation failed
3. For test failures, review indicator patterns
4. For lint errors, most are auto-fixed; remaining errors shown

## See Also

- [Case File Format](case-file-format.md)
- [learn-from-investigation workflow](../.claude/workflows/learn-from-investigation.md)
- [review-and-enhance-case workflow](../.claude/workflows/review-and-enhance-case.md)
- [Example Case](../docs/workflows/examples/case-001-aws-missing-gateway-sg.yaml)
