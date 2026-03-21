"""Shared utilities for QKD vulnerability experiments."""

from .experiment_utils import (
    SYMBOL_SUCCESS,
    SYMBOL_UNSUPPORTED,
    SYMBOL_UNAUTH_CHAN,
    LEGEND_TEXT,
    compute_mac,
    verify_mac,
    compute_match_rate,
    create_result_template,
    print_experiment_header,
    print_result_verdict,
    print_legend,
    print_results_json,
    json_serializable,
)

__all__ = [
    "SYMBOL_SUCCESS",
    "SYMBOL_UNSUPPORTED",
    "SYMBOL_UNAUTH_CHAN",
    "LEGEND_TEXT",
    "compute_mac",
    "verify_mac",
    "compute_match_rate",
    "create_result_template",
    "print_experiment_header",
    "print_result_verdict",
    "print_legend",
    "print_results_json",
    "json_serializable",
]
