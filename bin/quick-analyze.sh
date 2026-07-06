#!/usr/bin/env bash
# Quick analysis wrapper for engineers
# Auto-detects latest diagnostics file and runs analysis in Slack format

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/../analyze-basic.py"

# Auto-detect or use provided file
if [ "${1:-}" = "" ]; then
    # Auto-detect latest file in Downloads (BSD/macOS compatible)
    FILE=$(find ~/Downloads -maxdepth 1 -name "submariner-diagnostics-*.tar.gz" -type f 2>/dev/null | \
           xargs -r ls -t 2>/dev/null | head -1 || true)

    if [ -z "$FILE" ]; then
        echo "❌ No submariner-diagnostics-*.tar.gz found in ~/Downloads/"
        echo ""
        echo "Usage: $(basename "$0") [file.tar.gz]"
        echo ""
        echo "Examples:"
        echo "  $(basename "$0")  # Auto-detect latest file"
        echo "  $(basename "$0") ~/Downloads/submariner-diagnostics-20260701.tar.gz"
        exit 1
    fi

    echo "📁 Auto-detected: $(basename "$FILE")"
    echo ""
else
    FILE="$1"
    if [ ! -f "$FILE" ]; then
        echo "❌ File not found: $FILE"
        exit 1
    fi
fi

# Run analysis in Slack format (clean, condensed output)
python3 "$ANALYZER" "$FILE" --format slack

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Copy output above and paste to Slack thread"
echo ""
echo "For detailed analysis, run:"
echo "  python3 $ANALYZER \"$FILE\""
echo ""
