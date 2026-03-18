"""Conditional reference injection utility for framework packs."""

# Keywords for api_detected condition
API_KEYWORDS = [
    "rest",
    "graphql",
    "grpc",
    "api gateway",
    "endpoint",
    "openapi",
    "swagger",
]

# Keywords for llm_detected condition
LLM_KEYWORDS = [
    "langchain",
    "openai",
    "llm",
    "vector database",
    "embedding",
    "model serving",
    "prompt",
    "agent framework",
    "claude",
    "gpt",
]

# Keywords for mobile_detected condition
MOBILE_KEYWORDS = [
    "android",
    "ios",
    "react native",
    "flutter",
    "swift",
    "kotlin",
    "mobile",
]


def evaluate_reference_conditions(
    reference_config: list[dict], prior_outputs: dict
) -> list[str]:
    """Evaluate reference injection conditions against prior stage outputs.

    Args:
        reference_config: List of dicts with keys ``condition`` and ``reference``.
            Supported conditions: ``always``, ``api_detected``, ``llm_detected``,
            ``mobile_detected``.
        prior_outputs: Dict of prior stage output strings (values are searched
            for keyword matches).

    Returns:
        List of reference constant values whose conditions are satisfied.
    """
    combined = " ".join(v for v in prior_outputs.values() if v).lower()
    results = []
    for entry in reference_config:
        condition = entry["condition"]
        reference = entry["reference"]
        if condition == "always":
            results.append(reference)
        elif condition == "api_detected":
            if any(kw in combined for kw in API_KEYWORDS):
                results.append(reference)
        elif condition == "llm_detected":
            if any(kw in combined for kw in LLM_KEYWORDS):
                results.append(reference)
        elif condition == "mobile_detected":
            if any(kw in combined for kw in MOBILE_KEYWORDS):
                results.append(reference)
    return results
