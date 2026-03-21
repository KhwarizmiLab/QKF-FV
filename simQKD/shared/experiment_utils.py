"""
Shared utility module for QKD vulnerability experiments.
Provides common patterns: JSON output, MAC helpers, match rate computation.
"""

import json
import hmac
import hashlib

# Legend symbols for vulnerability replication results
SYMBOL_SUCCESS = "✓"      # Vulnerability demonstrated with tool's native APIs
SYMBOL_UNSUPPORTED = "*"  # Tool does not support (reason: No quantum layer implemented)
SYMBOL_UNAUTH_CHAN = "-"  # Vulnerability demonstrated; tool used unauthenticated channel (no built-in MAC)

LEGEND_TEXT = """Legend:
  ✓ = Vulnerability demonstrated with tool's native APIs
  * = Tool does not support (reason: No quantum layer implemented)
  - = Vulnerability demonstrated; tool used unauthenticated channel (no built-in MAC)"""


def compute_mac(key, message):
    """Compute HMAC-SHA256 for message authentication (V2, V4)."""
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()[:16]


def verify_mac(key, message, tag):
    """Verify HMAC tag."""
    expected = compute_mac(key, message)
    return hmac.compare_digest(expected, tag)


def compute_match_rate(bits_a, bits_b, exclude_value=None):
    """
    Compute match rate between two bit sequences.
    Optionally exclude a sentinel value (e.g., -1 for missing measurements).
    """
    if not bits_a or not bits_b:
        return 0.0
    min_len = min(len(bits_a), len(bits_b))
    if min_len == 0:
        return 0.0
    matches = 0
    compared = 0
    for i in range(min_len):
        a, b = bits_a[i], bits_b[i]
        if exclude_value is not None and (a == exclude_value or b == exclude_value):
            continue
        compared += 1
        if a == b:
            matches += 1
    return matches / compared if compared > 0 else 0.0


def create_result_template(vuln_id, tool_name, attack_name, protocol=""):
    """Create a standard results dict for experiment output."""
    return {
        "vulnerability": f"V{vuln_id}",
        "tool": tool_name,
        "attack": attack_name,
        "protocol": protocol,
        "expected_outcome": "",
        "attack_successful": False,
        "notes": [],
    }


def print_experiment_header(title, tool):
    """Print standard experiment header."""
    print("=" * 70)
    print(f"{title} [{tool}]")
    print("=" * 70)


def print_result_verdict(results, vuln_id, tool_name, symbol=None):
    """Print SUCCESS or FAIL verdict based on attack_successful. Symbol: ✓, *, or -."""
    sym = symbol or (SYMBOL_SUCCESS if results.get("attack_successful") else SYMBOL_UNSUPPORTED)
    if results.get("attack_successful"):
        print(f"\n>>> V{vuln_id} VULNERABILITY CONFIRMED ({sym}) <<<")
        print(f"{tool_name} successfully demonstrates V{vuln_id}.")
    else:
        print(f"\n>>> V{vuln_id} CANNOT BE REPLICATED ({sym}) <<<")
        if results.get("notes"):
            print("Reasons:")
            for i, note in enumerate(results["notes"], 1):
                print(f"  {i}. {note}")


def print_legend():
    """Print legend for result symbols."""
    print(LEGEND_TEXT)


def print_results_json(results, exclude_keys=None):
    """Print results as JSON, optionally excluding large fields."""
    exclude_keys = exclude_keys or ["eve_key_bits", "bob_key_bits", "alice_key_bits", "bob_basis", "alice_basis"]
    filtered = {k: v for k, v in results.items() if k not in exclude_keys}
    print(json.dumps(filtered, indent=2, default=str))


def json_serializable(obj):
    """Convert object to JSON-serializable form."""
    if hasattr(obj, "__iter__") and not isinstance(obj, (str, bytes)):
        try:
            return list(obj)
        except TypeError:
            pass
    return str(obj)
