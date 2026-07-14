#!/bin/bash
# Validate case file format

set -e

CASE_FILE="$1"

if [ -z "$CASE_FILE" ]; then
    echo "Usage: $0 <case-file.yaml>"
    exit 1
fi

if [ ! -f "$CASE_FILE" ]; then
    echo "Error: File not found: $CASE_FILE"
    exit 1
fi

echo "Validating case file: $CASE_FILE"
echo ""

# Check if Python and PyYAML are available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 not found"
    exit 1
fi

if ! python3 -c "import yaml" 2>/dev/null; then
    echo "Error: PyYAML not installed. Run: pip install pyyaml"
    exit 1
fi

# Validate YAML syntax and required fields
python3 - "$CASE_FILE" <<'EOF'
import sys
import yaml

case_file = sys.argv[1]
errors = []
warnings = []

try:
    with open(case_file, 'r') as f:
        data = yaml.safe_load(f)
except yaml.YAMLError as e:
    print(f"❌ YAML syntax error: {e}")
    sys.exit(1)

# Check if file is empty
if data is None:
    print("❌ VALIDATION FAILED")
    print("  - File is empty or contains no YAML data")
    sys.exit(1)

# Check required top-level fields
required_fields = ['metadata', 'issue', 'root_cause', 'indicators', 'remediation']
for field in required_fields:
    if field not in data:
        errors.append(f"Missing required field: {field}")

if 'metadata' in data:
    if 'case_id' not in data['metadata']:
        errors.append("Missing metadata.case_id")
    if 'created_date' not in data['metadata']:
        errors.append("Missing metadata.created_date")

if 'root_cause' in data:
    if 'summary' not in data['root_cause']:
        errors.append("Missing root_cause.summary")
    if 'category' not in data['root_cause']:
        errors.append("Missing root_cause.category")
    if 'issue_type' not in data['root_cause']:
        errors.append("Missing root_cause.issue_type")

    # If bug, should have bug_info
    if data['root_cause'].get('issue_type') == 'bug':
        if 'bug_info' not in data['root_cause']:
            warnings.append("issue_type is 'bug' but bug_info is missing")

if 'indicators' in data:
    if 'required' not in data['indicators']:
        errors.append("Missing indicators.required")
    else:
        req_count = len(data['indicators']['required']) if data['indicators']['required'] else 0
        opt_count = len(data['indicators'].get('optional', []))
        total = req_count + opt_count

        if total < 3:
            warnings.append(f"Only {total} indicators - recommend at least 3-5")

        if req_count == 0:
            warnings.append("No required indicators - detection may be too weak")

        # Check indicator structure
        for idx, ind in enumerate(data['indicators'].get('required', [])):
            if not isinstance(ind, dict):
                errors.append(f"indicators.required[{idx}] is not a dict")
                continue

            for field in ['name', 'file_location', 'pattern', 'significance']:
                if field not in ind:
                    errors.append(f"indicators.required[{idx}] missing {field}")

if 'remediation' in data:
    if 'solutions' not in data['remediation']:
        errors.append("Missing remediation.solutions")
    elif not data['remediation']['solutions']:
        errors.append("remediation.solutions is empty - need at least one solution")
    else:
        for idx, sol in enumerate(data['remediation']['solutions']):
            if 'type' not in sol:
                errors.append(f"remediation.solutions[{idx}] missing type")
            if 'name' not in sol:
                errors.append(f"remediation.solutions[{idx}] missing name")

# Check detection_logic (needed for code generation)
if 'indicators' in data:
    if 'detection_logic' not in data['indicators']:
        warnings.append("Missing indicators.detection_logic - needed for code generation")

# Check false_positives (recommended for quality)
if 'false_positives' not in data:
    warnings.append("Missing false_positives section - recommend documenting similar issues")

# Check diagnostic_file (required for integration testing)
if 'diagnostic_file' not in data:
    errors.append("Missing diagnostic_file section - required for integration testing")
elif 'path' not in data['diagnostic_file']:
    errors.append("Missing diagnostic_file.path")

# Print results
if errors:
    print("❌ VALIDATION FAILED")
    print("")
    print("Errors:")
    for err in errors:
        print(f"  - {err}")

    if warnings:
        print("")
        print("Warnings:")
        for warn in warnings:
            print(f"  - {warn}")

    sys.exit(1)
else:
    print("✓ Case file is valid!")

    if warnings:
        print("")
        print("Warnings:")
        for warn in warnings:
            print(f"  - {warn}")

    print("")
    print("Summary:")
    print(f"  Case ID: {data['metadata']['case_id']}")
    print(f"  Root Cause: {data['root_cause']['summary']}")

    req_count = len(data['indicators']['required']) if data['indicators']['required'] else 0
    opt_count = len(data['indicators'].get('optional', []))
    print(f"  Indicators: {req_count} required, {opt_count} optional")

    sol_count = len(data['remediation']['solutions'])
    print(f"  Solutions: {sol_count}")

    print("")
    print("Ready for enhancement workflow:")
    print(f"  /workflow review-and-enhance-case {case_file}")

EOF

echo ""
echo "Validation complete!"
