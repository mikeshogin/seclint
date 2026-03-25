"""
seclint content filter for ccproxy.

Pre-filters prompts before they reach any model.
Blocks content that exceeds the configured age rating threshold.

Setup:
    1. Start seclint server: seclint serve 8091
    2. Copy this file to your ccproxy plugins directory
    3. Add to ccproxy.yaml rules section (before promptlint rule)
"""

import json
import urllib.request
import urllib.error

SECLINT_URL = "http://localhost:8091/rate"
TIMEOUT_SECONDS = 2
MAX_RATING = 16  # Block 18+ and BLOCKED content


def extract_prompt_text(request_body: dict) -> str:
    """Extract user message text from Anthropic API request."""
    messages = request_body.get("messages", [])
    if not messages:
        return ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):
                texts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        texts.append(block.get("text", ""))
                return " ".join(texts)
    return ""


def check_content(text: str) -> dict:
    """Call seclint HTTP API to rate content."""
    try:
        req = urllib.request.Request(
            f"{SECLINT_URL}",
            data=text.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None


def filter_request(request_body: dict) -> dict:
    """
    Pre-filter hook for ccproxy.
    Returns request unchanged if safe, or raises ValueError if blocked.
    """
    prompt_text = extract_prompt_text(request_body)

    if len(prompt_text) < 10:
        return request_body

    result = check_content(prompt_text)
    if result is None:
        # Filter failed, pass through (fail-open)
        return request_body

    rating = result.get("rating", "6+")
    safe = result.get("safe", True)

    # Map rating to numeric
    rating_map = {"6+": 6, "12+": 12, "16+": 16, "18+": 18, "BLOCKED": 99}
    rating_num = rating_map.get(rating, 0)

    if rating_num > MAX_RATING or not safe:
        # Block the request
        raise ValueError(
            f"Content blocked by seclint: rating={rating}, "
            f"flags={result.get('flags', [])}"
        )

    # Add metadata
    request_body["_seclint"] = {
        "rating": rating,
        "safe": safe,
        "flags": result.get("flags", []),
    }

    return request_body
