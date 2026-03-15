#!/usr/bin/env python3
"""
Convert Tamarin .proof_trace text output to DOT and render to PDF.
Used when Tamarin batch mode produces text traces (no native .dot output).
"""
import re
import subprocess
import sys
import os

RULE_RE = re.compile(r'rule \(modulo (?:E|AC)\)\s+(\w+)\s*:', re.I)

def parse_trace(text, lemma_name):
    """Extract rule names from proof trace to build graph nodes."""
    rules = []
    seen = set()
    for m in RULE_RE.finditer(text):
        name = m.group(1)
        if name not in seen:
            seen.add(name)
            rules.append(name)
    return rules

def trace_to_dot(trace_text, lemma_name, title=None):
    """Produce DOT source from trace text."""
    rules = parse_trace(trace_text, lemma_name)
    if not rules:
        # Placeholder: single node indicating counterexample
        return f'''digraph G {{
    graph [fontname="Helvetica", fontsize=11];
    node [fontname="Helvetica", fontsize=10, shape=box];
    label="Counterexample: {lemma_name}";
    labelloc=t;
    "trace" [label="Counterexample found\\n(lemma: {lemma_name})", style=filled, fillcolor=lightyellow];
}}
'''
    # Linear chain of rules
    lines = [
        'digraph G {',
        '    graph [fontname="Helvetica", fontsize=11, rankdir=TB];',
        '    node [fontname="Helvetica", fontsize=10, shape=box];',
        f'    label="{title or lemma_name}";',
        '    labelloc=t;',
    ]
    # Sanitize node IDs (DOT doesn't like some chars)
    for i, r in enumerate(rules):
        nid = "n" + str(i)
        lines.append(f'    {nid} [label="{r}"];')
    for i in range(len(rules) - 1):
        lines.append(f'    n{i} -> n{i+1};')
    lines.append('}')
    return '\n'.join(lines)

def main():
    import argparse
    ap = argparse.ArgumentParser(description='Convert Tamarin proof trace to PDF graph')
    ap.add_argument('trace_file', nargs='?', help='Input .proof_trace file')
    ap.add_argument('-o', '--output', required=True, help='Output PDF path')
    ap.add_argument('--lemma', help='Lemma name (default: from filename)')
    args = ap.parse_args()
    trace_path = args.trace_file
    if not trace_path or not os.path.isfile(trace_path):
        ap.error('trace_file is required and must exist')
    out_pdf = args.output
    lemma = args.lemma or os.path.splitext(os.path.basename(trace_path))[0].replace('.proof_trace', '')

    with open(trace_path, 'r', errors='replace') as f:
        text = f.read()

    dot_src = trace_to_dot(text, lemma)
    dot_path = out_pdf.replace('.pdf', '.dot')
    with open(dot_path, 'w') as f:
        f.write(dot_src)

    rc = subprocess.call(['dot', '-Tpdf', '-o', out_pdf, dot_path], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if rc != 0:
        print(f"Warning: dot failed for {trace_path}", file=sys.stderr)
        sys.exit(1)
    # Optionally remove .dot to save space
    # os.remove(dot_path)

if __name__ == '__main__':
    main()
