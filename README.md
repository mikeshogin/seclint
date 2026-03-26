# seclint

Security and content classifier for AI prompts. Age-appropriate ratings, topic guidance, safety classification. No LLM required.

## API

### CLI (pipe-friendly)

```bash
# Rate: classify a prompt
echo "Help me write a school essay" | seclint rate

# Check: pass/fail threshold
echo "Explain SQL injection attacks" | seclint check --max-rating 12

# Filter: block or sanitize
echo "Some prompt text" | seclint filter --policy strict
```

### HTTP

```bash
# Start server
seclint serve 8091

# POST /rate - classify content
curl -X POST http://localhost:8091/rate \
  -H "Content-Type: application/json" \
  -d '{"text":"Help me write a school essay"}'

# POST /check - check threshold
curl -X POST http://localhost:8091/check \
  -H "Content-Type: application/json" \
  -d '{"text":"...", "max_rating":"12"}'

# GET /health - server status
curl http://localhost:8091/health
```

## Output Format

### Rate Response
```json
{
  "text": "Help me write a school essay about history",
  "rating": "6+",
  "safe": true,
  "flags": [],
  "confidence": 0.95
}
```

### Check Response
```json
{
  "text": "Explain SQL injection attacks",
  "rating": "16+",
  "max_rating": "12",
  "passes": false,
  "reason": "rating exceeds threshold"
}
```

### Filter Response
```json
{
  "text": "original text...",
  "policy": "strict",
  "action": "block",
  "blocked": true,
  "reason": "explicit content detected"
}
```

## Rating Levels

```
"6+"      - safe for all ages
"12+"     - mild themes (thriller plots, competitive topics)
"16+"     - mature themes (security, medical, business)
"18+"     - adult only (explicit content, weapons, drugs, violence)
"BLOCKED" - policy violation (illegal activities, harm, exploitation)
```

## Classification Signals

- **Keyword matching** - domain-specific word lists per rating category
- **Context analysis** - surrounding words modify severity
- **Intent detection** - educational vs malicious use
- **Combination rules** - certain word combinations escalate rating

## Integration

### As pre-filter in pipeline

```bash
# Guard first, then route
echo "prompt" | seclint check --max-rating 16 \
  && echo "prompt" | promptlint analyze \
  | route_to_agent
```

### With ccproxy (Claude Code Proxy)

```yaml
# ccproxy.yaml
middleware:
  - name: "security_gate"
    type: "seclint"
    endpoint: "http://localhost:8091/check"
    max_rating: "16+"
    action: "block"
```

### With agent pipeline

```
prompt -> seclint (safe?) -> promptlint (route) -> agent -> archlint (validate) -> costlint (track)
            |
         BLOCK if unsafe
```

## Install

```bash
go install github.com/mikeshogin/seclint/cmd/seclint@latest
```

## Policies

- **strict** - block 16+ and 18+ (safest, most false positives)
- **default** - block 18+ and explicit violations only
- **permissive** - only block BLOCKED status (least filtering)

## Ecosystem

Part of the AI agent safety and cost optimization ecosystem:

- **[promptlint](https://github.com/mikeshogin/promptlint)** - prompt routing by complexity
- **[costlint](https://github.com/mikeshogin/costlint)** - token cost tracking
- **[archlint](https://github.com/mshogin/archlint)** - code quality validation

See [ECOSYSTEM.md](ECOSYSTEM.md) for full integration.

## For Humans

Seclint is a content classification tool that rates the maturity level of prompts and other text using age-appropriate categories (6+, 12+, 16+, 18+) without needing to call any LLM. It's designed to be used as a safety gate in AI agent pipelines - you can block or flag prompts before they reach any model, identify content that's beyond a certain maturity level, and integrate it with routing and cost-tracking tools to build a complete safety and optimization system.
