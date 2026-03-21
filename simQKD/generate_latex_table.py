#!/usr/bin/env python3
"""
Generate a LaTeX evaluation table from QKD vulnerability experiment results.

Runs all 16 experiments (4 tools x 4 vulnerabilities), parses output,
and generates a LaTeX table matching the paper format.

Usage:
    python generate_latex_table.py              # run experiments & generate
    python generate_latex_table.py --cached     # use last run results
    python generate_latex_table.py --output results/eval_table.tex
"""

import subprocess
import sys
import os
import re
import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent

TOOLS = ["SimQN", "SeQUeNCe", "Quditto", "QKDNetSim"]
VULNS = ["V1", "V2", "V3", "V4"]

VULN_FILE_MAP = {
    "V1": "V1_entanglement_injection.py",
    "V2": "V2_identity_misbinding.py",
    "V3": "V3_basis_deferred_measurement.py",
    "V4": "V4_message_reflection.py",
}

# Symbols emitted by experiments
SYM_SUCCESS = "\u2713"     # ✓
SYM_UNSUPPORTED = "*"      # *
SYM_UNAUTH = "-"           # unauthenticated channel / manual MAC

# LaTeX symbol mapping
LATEX_VERIFIED = r"\verified{}"
LATEX_FALSIFIED = r"\falsified{}"
LATEX_NOQSUPPORT = r"$*$"
LATEX_NOCLASSICAL = r"$-$"


def run_experiment(tool, vuln):
    """Run a single experiment and return its stdout."""
    script = PROJECT_ROOT / f"_{tool}" / "experiments" / VULN_FILE_MAP[vuln]
    if not script.exists():
        return None

    # Determine which venv to use
    venv = PROJECT_ROOT / ".venv"
    python = venv / "bin" / "python"
    if not python.exists():
        python = sys.executable

    try:
        result = subprocess.run(
            [str(python), str(script)],
            capture_output=True, text=True, timeout=60,
            cwd=str(PROJECT_ROOT),
        )
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"ERROR: {e}"


def parse_result(output):
    """
    Parse experiment output and return a result dict.

    Returns:
        {
            "attack_successful": bool,
            "symbol": str,       # ✓, *, or -
            "reason": str,       # "confirmed", "no_quantum", "no_eb", "manual_mac", etc.
            "notes": list[str],
        }
    """
    if output is None:
        return {"attack_successful": False, "symbol": SYM_UNSUPPORTED,
                "reason": "script_missing", "notes": ["Experiment script not found"]}

    attack_successful = False
    symbol = SYM_UNSUPPORTED
    reason = "unknown"
    notes = []

    # Check for VULNERABILITY CONFIRMED or CANNOT BE REPLICATED
    if "VULNERABILITY CONFIRMED" in output:
        attack_successful = True
        # Extract the symbol used in the verdict
        m = re.search(r'VULNERABILITY CONFIRMED \((.)\)', output)
        if m:
            symbol = m.group(1)
        else:
            symbol = SYM_SUCCESS
        reason = "confirmed"
    elif "CANNOT BE REPLICATED" in output:
        attack_successful = False
        m = re.search(r'CANNOT BE REPLICATED \((.)\)', output)
        if m:
            symbol = m.group(1)
        else:
            symbol = SYM_UNSUPPORTED
        reason = "not_feasible"

    # Determine more specific reason from output
    if "no quantum" in output.lower() or "No quantum layer" in output:
        reason = "no_quantum"
    elif "no EB-QKD" in output or "no E91" in output or "no EB protocol" in output:
        reason = "no_eb_protocol"
    elif "KMS-layer" in output or "KMS analogue" in output:
        reason = "kms_analogue"

    # Check for manual MAC (can combine with other reasons)
    # Support both "-" and "†" for backwards compatibility with cached results
    if attack_successful and symbol in (SYM_UNAUTH, "\u2020"):
        reason = "confirmed_manual_mac"
    elif attack_successful and ("manual MAC" in output.lower()
                                 or "MAC added manually" in output
                                 or "Manual MAC" in output):
        reason = "confirmed_manual_mac"

    # Extract notes/reasons from output
    reason_lines = re.findall(r'^\s+\d+\.\s+(.+)$', output, re.MULTILINE)
    notes = reason_lines[:5]

    return {
        "attack_successful": attack_successful,
        "symbol": symbol,
        "reason": reason,
        "notes": notes,
    }


def result_to_latex(result, tool, vuln):
    """
    Map a parsed result to a LaTeX cell string.

    Mapping:
      ✓ (native APIs)          -> \verified{}
      ✓ (KMS analogue)         -> \verified{}
      - (manual MAC, confirmed) -> \verified{}
      * (no quantum layer)     -> $*$
      * (no EB protocol)       -> $-$
      not successful           -> \falsified{}
    """
    sym = result["symbol"]
    reason = result["reason"]
    successful = result["attack_successful"]

    if not successful:
        # Symbol-based: * = missing quantum, - = missing auth channel
        if sym == SYM_UNSUPPORTED:
            if reason == "no_eb_protocol":
                return LATEX_NOCLASSICAL  # $-$ = Missing Auth. Channel
            # Default for * symbol: no quantum support
            return LATEX_NOQSUPPORT
        return LATEX_FALSIFIED

    # Attack successful (including manual MAC case - no extra symbol)
    return LATEX_VERIFIED


def generate_latex_table(results_matrix):
    """Generate the full LaTeX table string."""
    lines = []
    lines.append(r"\renewcommand{\arraystretch}{1.05}")
    lines.append(r"\begin{table}[t]")
    lines.append(r"\centering")
    lines.append(r"\caption{Evaluation results for reproducing vulnerabilities in QKD network simulators. \\")
    lines.append(r"  {\footnotesize \verified{}=Validated,}")
    lines.append(r"  {\footnotesize $*$= Missing Quantum Operations, $-$=Missing Auth. Channel}}")
    lines.append(r"\label{tab:eval}")
    lines.append(r"\vspace{-8pt}")
    lines.append(r"\resizebox{\linewidth}{!}{%")
    lines.append(r"\begin{tabular}{@{}lcccc@{}}")
    lines.append(r"\toprule")
    lines.append(r"\textbf{Simulator} & \textbf{V1} & \textbf{V2}")
    lines.append(r"  & \textbf{V3} & \textbf{V4} \\")
    lines.append(r" & \footnotesize{Ent.\ Injection}")
    lines.append(r" & \footnotesize{Identity Misbinding}")
    lines.append(r" & \footnotesize{Basis-Deferred}")
    lines.append(r" & \footnotesize{Msg.\ Reflection} \\")
    lines.append(r"\midrule")

    for tool in TOOLS:
        cells = []
        for vuln in VULNS:
            result = results_matrix[tool][vuln]
            cells.append(result_to_latex(result, tool, vuln))

        tool_display = tool
        # Escape special chars for LaTeX
        if tool == "SeQUeNCe":
            tool_display = "SeQUeNCe"

        row = f"{tool_display} & {cells[0]} & {cells[1]} & {cells[2]} & {cells[3]} \\\\"
        lines.append(row)

    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}}")
    lines.append(r"\vspace{-16pt}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate LaTeX evaluation table from QKD experiments"
    )
    parser.add_argument("--cached", action="store_true",
                        help="Use cached results from last run")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write LaTeX to file (default: stdout)")
    parser.add_argument("--json", action="store_true",
                        help="Also print raw results as JSON")
    args = parser.parse_args()

    cache_file = PROJECT_ROOT / "results" / "eval_results_cache.json"

    if args.cached and cache_file.exists():
        print("Loading cached results...", file=sys.stderr)
        with open(cache_file) as f:
            results_matrix = json.load(f)
    else:
        print("Running all experiments...", file=sys.stderr)
        results_matrix = {}

        total = len(TOOLS) * len(VULNS)
        done = 0

        for tool in TOOLS:
            results_matrix[tool] = {}
            for vuln in VULNS:
                done += 1
                print(f"  [{done}/{total}] {tool} {vuln}...",
                      end="", file=sys.stderr, flush=True)
                output = run_experiment(tool, vuln)
                result = parse_result(output)
                results_matrix[tool][vuln] = result

                status = "CONFIRMED" if result["attack_successful"] else "NOT FEASIBLE"
                print(f" {status} ({result['symbol']})", file=sys.stderr)

        # Cache results
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_file, "w") as f:
            json.dump(results_matrix, f, indent=2, ensure_ascii=False)
        print(f"\nResults cached to {cache_file}", file=sys.stderr)

    # Print summary matrix
    print("\n=== Results Matrix ===", file=sys.stderr)
    header = f"{'Tool':<12}" + "".join(f"{v:<10}" for v in VULNS)
    print(header, file=sys.stderr)
    print("-" * len(header), file=sys.stderr)
    for tool in TOOLS:
        row = f"{tool:<12}"
        for vuln in VULNS:
            r = results_matrix[tool][vuln]
            row += f"{r['symbol']:<10}"
        print(row, file=sys.stderr)

    if args.json:
        print("\n=== Raw Results (JSON) ===", file=sys.stderr)
        print(json.dumps(results_matrix, indent=2, ensure_ascii=False),
              file=sys.stderr)

    # Generate LaTeX
    latex = generate_latex_table(results_matrix)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            f.write(latex + "\n")
        print(f"\nLaTeX table written to {out_path}", file=sys.stderr)
    else:
        print(latex)


if __name__ == "__main__":
    main()
