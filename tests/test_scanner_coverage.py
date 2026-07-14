"""Tests for src/scanner/coverage.py — high-value-target detection + checklist."""

from __future__ import annotations

from gradientql.scanner import coverage
from gradientql.scanner.memory import blank_entry


def _sm(query=None, mutation=None):
    return {"_query_type": "Query", "_mutation_type": "Mutation",
            "Query": query or {}, "Mutation": mutation or {}}


def test_high_value_targets_detects_the_classes():
    sm = _sm(query={"guestOrder": {}, "products": {}},
             mutation={"generateCustomerTokenAsAdmin": {}, "resetPassword": {}, "deletePaymentToken": {},
                       "cancelOrder": {}, "mergeCarts": {}, "applyCouponToCart": {}})
    labels = " ".join(coverage.high_value_targets(sm))
    assert "token-mint" in labels and "password" in labels and "guest-order" in labels
    assert "vault" in labels and "order-state" in labels and "cart takeover" in labels and "coupon" in labels
    # a plain storefront field is NOT high-value (precision)
    assert "products" not in coverage.high_value_fields(sm)


def test_critical_untested_and_render_marks():
    sm = _sm(mutation={"generateCustomerTokenAsAdmin": {}, "resetPassword": {}})
    assert set(coverage.critical_untested(sm, {})) == {"generateCustomerTokenAsAdmin", "resetPassword"}
    # a single ping (attempts=1) is NOT enough — a critical field must be actually attacked
    pinged = {"generateCustomerTokenAsAdmin": {**blank_entry("generateCustomerTokenAsAdmin", "anon", 0),
                                               "attempts": 1},
              "resetPassword": {**blank_entry("resetPassword", "anon", 0), "attempts": 1}}
    assert set(coverage.critical_untested(sm, pinged)) == {"generateCustomerTokenAsAdmin", "resetPassword"}
    # a depth signal (auth_test matrix, fuzz, a finding, or repeated probing) clears the guard
    attacked = {"generateCustomerTokenAsAdmin": {**blank_entry("generateCustomerTokenAsAdmin", "anon", 0),
                                                 "authmatrix": ["anon", "current"]},
                "resetPassword": {**blank_entry("resetPassword", "anon", 0), "attempts": 3}}
    assert coverage.critical_untested(sm, attacked) == []
    # a verdict-only phantom entry (no request sent) does NOT clear the guard
    phantom = {"generateCustomerTokenAsAdmin": blank_entry("generateCustomerTokenAsAdmin", "anon", 0),
               "resetPassword": blank_entry("resetPassword", "anon", 0)}
    assert set(coverage.critical_untested(sm, phantom)) == {"generateCustomerTokenAsAdmin", "resetPassword"}
    # render marks: ✓ auth-matrixed, ★ never probed
    ledger = {"generateCustomerTokenAsAdmin": {**blank_entry("generateCustomerTokenAsAdmin", "anon", 0),
                                               "authmatrix": ["anon", "current"]}}
    r = coverage.render_high_value(sm, ledger)
    assert "✓generateCustomerTokenAsAdmin" in r    # ✓ matrixed
    assert "★resetPassword" in r                    # ★ untested


def test_render_mark_partial_for_probed_not_matrixed():
    sm = _sm(mutation={"resetPassword": {}})
    probed = {"resetPassword": {**blank_entry("resetPassword", "anon", 0), "attempts": 1}}
    r = coverage.render_high_value(sm, probed)
    assert "◐resetPassword" in r                    # ◐ probed once, not auth-matrixed


def test_render_mark_verdict_only_phantom_reads_untested():
    sm = _sm(mutation={"resetPassword": {}})
    r = coverage.render_high_value(sm, {"resetPassword": blank_entry("resetPassword", "anon", 0)})
    assert "★resetPassword" in r                    # no request sent -> still untested


def test_no_high_value_on_benign_schema():
    sm = _sm(query={"products": {}, "categories": {}}, mutation={"subscribeEmailToNewsletter": {}})
    assert coverage.high_value_targets(sm) == {}
    assert coverage.render_high_value(sm, {}) == ""


def test_keywords_do_not_overmatch_kanban_reorder_mutations():
    # GitLab-shaped *Reorder*/*OrderedTask* mutations must NOT register as order-IDOR/order-state
    # (regression: bare "reorder"/"createorder"/"updateorder" substrings tagged them)
    sm = _sm(mutation={"issueReorder": {}, "epicTreeReorder": {}, "boardListReorder": {},
                       "workItemReorder": {}, "createOrderedTask": {}, "updateOrderingPriority": {}})
    assert coverage.high_value_targets(sm) == {}


def test_self_service_password_change_is_not_critical():
    # changePassword/setPassword are session-gated, not anon-exploitable -> rank 1, never hold `done`
    sm = _sm(mutation={"changeCustomerPassword": {}, "setPassword": {}})
    assert coverage.critical_untested(sm, {}) == []      # not rank-0, done-gate won't hold
    assert coverage.high_value_targets(sm)               # still surfaced (nudged) though


def test_self_service_password_change_not_bfla_autorecord():
    # the password-CHANGE class is excluded from BFLA auto-record (only reset/mint/destruct/vault)
    sm = _sm(mutation={"changeCustomerPassword": {}})
    assert coverage.bfla_sensitive_fields(sm) == set()


def test_bfla_sensitive_fields_covers_mint_reset_destruct_vault():
    sm = _sm(mutation={"generateCustomerTokenAsAdmin": {}, "resetPassword": {}, "deactivateAccount": {},
                       "deletePaymentToken": {}, "cancelOrder": {}})
    bfla = coverage.bfla_sensitive_fields(sm)
    assert {"generateCustomerTokenAsAdmin", "resetPassword", "deactivateAccount", "deletePaymentToken"} <= bfla
    assert "cancelOrder" not in bfla                      # order-state is ambiguous -> not auto-recorded
