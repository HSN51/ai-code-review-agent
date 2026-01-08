
# Reliability & Scoring

## Deduplication Strategy
To provide trustworthy results, findings are deduplicated across agents (Quality, Security, Testing).

1. **Fingerprinting**: Each finding gets a stable fingerprint:
   `category:rule_id:line:normalized_message_hash`
   
2. **Prioritization**:
   - If **SecurityAgent** and **QualityAgent** report the same security issue (e.g. SQL Injection), the **SecurityAgent** finding takes precedence.
   - Otherwise, the finding with the highest confidence is kept.

3. **Source Tracking**: The `sources` field in a finding lists all agents that reported it (e.g., `['QualityAgent', 'SecurityAgent']`).

## Scoring Model
The code quality score (0-100) is calculated robustly:

1. **Deductions**: Based on unique findings after deduplication.
   - Critical: -15
   - High: -8
   - Medium: -3
   - Low: -1
   - Info: -0.5
   
2. **Confidence**: Deductions are scaled by the confidence of the finding (e.g., 50% confidence = 50% deduction).

3. **Density Scaling**:
   - Scores are scaled based on "findings density" (findings per LOC).
   - This prevents harsh penalties on very large files that naturally have more issues but low density.
   - Scale factor: 0.8x to 1.2x.

## Tool Availability
The system reports the status of underlying tools (Ruff, Pylint, Bandit, OpenAI).
- If a tool fails (e.g., `ruff` not installed), the status is reported.
- A "No issues found" result is valid only if tools actually ran successfully.
