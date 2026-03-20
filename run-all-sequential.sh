#!/bin/bash
# Run all 24 benchmark cases sequentially, one at a time
# Passes --case-id to the adapter to avoid ambiguous HEAD resolution

BENCHMARK_REPO="/Users/sage/repos/openclaw-advisory-benchmark"
OPENCLAW_REPO="/Users/sage/repos/openclaw"
ADAPTER="/Users/sage/repos/securevibes-agent-adapter/adapter.py"
SV_REPO="/Users/sage/repos/securevibes-agent"
MODEL="openai-codex/gpt-5.3-codex"
RESULTS_DIR="$BENCHMARK_REPO/results-sequential"
STATUS_FILE="$RESULTS_DIR/status.txt"

mkdir -p "$RESULTS_DIR"

CASES=$(python3 -c "import json; m=json.load(open('$BENCHMARK_REPO/manifest.json')); print('\n'.join(c['id'] for c in m['cases']))")

TOTAL=$(echo "$CASES" | wc -l | tr -d ' ')
CURRENT=0
DETECTED=0
MISSED=0
ERRORS=0

echo "=== SecureVibes Agent Benchmark Run ===" > "$STATUS_FILE"
echo "Started: $(date)" >> "$STATUS_FILE"
echo "Model: $MODEL" >> "$STATUS_FILE"
echo "Total cases: $TOTAL" >> "$STATUS_FILE"
echo "---" >> "$STATUS_FILE"

for CASE_ID in $CASES; do
    CURRENT=$((CURRENT + 1))
    echo ""
    echo "[$CURRENT/$TOTAL] Running $CASE_ID..."
    echo "[$CURRENT/$TOTAL] $CASE_ID - RUNNING ($(date))" >> "$STATUS_FILE"

    python3 "$BENCHMARK_REPO/scripts/run.py" \
        --openclaw-repo "$OPENCLAW_REPO" \
        --scanner-cmd "python3 $ADAPTER scan --securevibes-repo $SV_REPO --benchmark-repo $BENCHMARK_REPO --repo . --case-id $CASE_ID --mode pr --llm-model $MODEL" \
        --baseline-cmd "python3 $ADAPTER baseline-setup --securevibes-repo $SV_REPO --benchmark-repo $BENCHMARK_REPO --repo . --case-id $CASE_ID --llm-model $MODEL" \
        --format simple \
        --filter "$CASE_ID" \
        --timeout 600 \
        --baseline-timeout 600 \
        --output "$RESULTS_DIR/$CASE_ID.json" \
        2>&1 | tee "$RESULTS_DIR/$CASE_ID.log"

    EXIT_CODE=$?

    # Parse result from the log output directly
    RESULT_LINE=$(grep -E "^\s+$CASE_ID" "$RESULTS_DIR/$CASE_ID.log" | head -1)
    if echo "$RESULT_LINE" | grep -q "DETECTED"; then
        RESULT="DETECTED"
        DETECTED=$((DETECTED + 1))
    elif echo "$RESULT_LINE" | grep -q "MISSED"; then
        RESULT="MISSED"
        MISSED=$((MISSED + 1))
    else
        RESULT="ERROR"
        ERRORS=$((ERRORS + 1))
    fi

    # Extract details from result JSON if it exists
    DETAIL=""
    if [ -f "$RESULTS_DIR/$CASE_ID.json" ]; then
        DETAIL=$(python3 -c "
import json
try:
    r=json.load(open('$RESULTS_DIR/$CASE_ID.json'))
    c=r['cases'][0]
    print(f\"path={c['pathMatch']} cls={c['classMatch']} sev={c['severityMatch']} findings={c['findingCount']} base={c.get('baselineStatus','n/a')}\")
except:
    print('')
" 2>/dev/null)
    fi

    echo "[$CURRENT/$TOTAL] $CASE_ID - $RESULT $DETAIL" >> "$STATUS_FILE"
    echo "--- Score: $DETECTED detected / $MISSED missed / $ERRORS errors (of $CURRENT run) ---" >> "$STATUS_FILE"
    echo "[$CURRENT/$TOTAL] $CASE_ID: $RESULT $DETAIL"
done

echo "" >> "$STATUS_FILE"
echo "=== FINAL ===" >> "$STATUS_FILE"
echo "Completed: $(date)" >> "$STATUS_FILE"
echo "Detected: $DETECTED/$TOTAL" >> "$STATUS_FILE"
echo "Missed: $MISSED/$TOTAL" >> "$STATUS_FILE"
echo "Errors: $ERRORS/$TOTAL" >> "$STATUS_FILE"

echo ""
echo "=== FINAL SCORE ==="
echo "Detected: $DETECTED/$TOTAL"
echo "Missed: $MISSED/$TOTAL"
echo "Errors: $ERRORS/$TOTAL"
echo "Full results: $RESULTS_DIR/"
