"""Tests for the detection engine.

Every card and identity number below is a synthetic value that passes its
checksum. None of them belongs to a real person or account.
"""

import json

import pytest

from pii_guard import (
    AuditLog,
    Policy,
    evaluate,
    is_valid_iban,
    is_valid_luhn,
    is_valid_tckn,
    card_brand,
    mask,
    redact,
    scan,
)

VISA = "4111111111111111"
MASTERCARD = "5555555555554444"
AMEX = "378282246310005"
# Synthetic TCKN values that satisfy both check digits.
TCKN = "10000000146"
TCKN_2 = "62601815964"
IBAN = "TR330006100519786457841326"


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------

def test_luhn_accepts_known_good_numbers():
    assert is_valid_luhn(VISA)
    assert is_valid_luhn(MASTERCARD)
    assert is_valid_luhn(AMEX)


def test_luhn_rejects_a_single_digit_change():
    assert not is_valid_luhn("4111111111111112")


def test_tckn_rejects_wrong_check_digits():
    assert is_valid_tckn(TCKN)
    assert not is_valid_tckn("10000000147")
    assert not is_valid_tckn("01000000146")  # leading zero is not allowed


def test_iban_mod97():
    assert is_valid_iban(IBAN)
    assert is_valid_iban("TR33 0006 1005 1978 6457 8413 26")
    assert not is_valid_iban("TR330006100519786457841327")


def test_card_brand_uses_prefix_and_length():
    assert card_brand(VISA) == "visa"
    assert card_brand(MASTERCARD) == "mastercard"
    assert card_brand(AMEX) == "amex"
    assert card_brand("1234567812345670") is None


# --------------------------------------------------------------------------
# Separator bypasses
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "my card is 4111111111111111 thanks",
        "my card is 4111 1111 1111 1111 thanks",
        "my card is 4111-1111-1111-1111 thanks",
        "my card is 4111 1111-1111 1111 thanks",
    ],
)
def test_separators_do_not_bypass_card_detection(text):
    findings = scan(text)
    assert [f.kind for f in findings] == ["credit_card"]


@pytest.mark.parametrize("text", [TCKN, "1 0 0 0 0 0 0 0 1 4 6".replace(" ", " ")])
def test_tckn_detected_with_and_without_spacing(text):
    assert any(f.kind == "tckn" for f in scan(text))


def test_card_is_not_also_reported_as_a_phone_number():
    kinds = [f.kind for f in scan(f"pay with {VISA}")]
    assert kinds == ["credit_card"]


def test_eleven_digits_inside_a_card_are_not_read_as_an_identity_number():
    assert [f.kind for f in scan(MASTERCARD)] == ["credit_card"]


# --------------------------------------------------------------------------
# False positives
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        "order reference 1234567812345678",
        "invoice 2024-0001 total 149.90 EUR",
        "the build finished in 1234567890123 ms",
        "ticket 12345678901 was closed yesterday",
    ],
)
def test_ordinary_numbers_are_left_alone(text):
    assert scan(text) == []


def test_version_strings_are_not_phone_numbers():
    assert scan("upgrade to 10.4.2.1 before Friday") == []


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

def test_card_redaction_keeps_the_last_four_digits():
    finding = scan(VISA)[0]
    assert mask(finding) == "************1111"


def test_identity_number_redaction_keeps_nothing():
    finding = scan(TCKN)[0]
    assert mask(finding) == "[TCKN]"


def test_redaction_preserves_surrounding_text():
    text = f"Hi, my email is ada@example.com and my card is {VISA}."
    out = redact(text, scan(text))
    assert out.startswith("Hi, my email is a")
    assert out.endswith("1111.")
    assert VISA not in out
    assert "ada@example.com" not in out


def test_multiple_findings_are_all_redacted():
    text = f"card {VISA}, iban {IBAN}, id {TCKN}, mail ada@example.com"
    out = redact(text, scan(text))
    for secret in (VISA, IBAN, TCKN, "ada@example.com"):
        assert secret not in out


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

def test_block_mode_returns_no_text():
    decision = evaluate(f"my card is {VISA}", Policy(mode="block"))
    assert decision.blocked
    assert decision.text == ""


def test_redact_mode_forwards_a_masked_prompt():
    decision = evaluate(f"my card is {VISA}", Policy(mode="redact"))
    assert decision.action == "redact"
    assert VISA not in decision.text


def test_audit_mode_forwards_the_prompt_unchanged():
    text = f"my card is {VISA}"
    decision = evaluate(text, Policy(mode="audit"))
    assert decision.text == text
    assert decision.tripped == ["credit_card"]


def test_clean_prompt_is_allowed():
    decision = evaluate("summarise this quarter's incident report")
    assert decision.action == "allow"
    assert decision.findings == []


def test_threshold_can_require_more_than_one_occurrence():
    policy = Policy(mode="block", thresholds={"tckn": 2})
    assert not evaluate(f"id {TCKN}", policy).blocked
    assert evaluate(f"ids {TCKN} and {TCKN_2}", policy).blocked


# --------------------------------------------------------------------------
# Audit log hygiene
# --------------------------------------------------------------------------

def test_log_entry_never_contains_the_prompt_or_the_values(tmp_path):
    text = f"please charge {VISA} for customer {TCKN}"
    decision = evaluate(text, Policy(mode="redact"))
    path = tmp_path / "audit.jsonl"
    AuditLog(path, salt="test-salt").write(decision, len(text), "redact")

    raw = path.read_text(encoding="utf-8")
    assert VISA not in raw
    assert TCKN not in raw
    assert "please charge" not in raw

    entry = json.loads(raw)
    assert entry["action"] == "redact"
    assert entry["prompt_chars"] == len(text)
    assert {"kind": "credit_card", "subtype": "visa", "count": 1} in entry["findings"]


def test_fingerprints_are_stable_and_keyed(tmp_path):
    decision = evaluate(f"card {VISA}", Policy(mode="audit"))
    with_salt = AuditLog(None, salt="one").build_entry(decision, 10, "audit")
    same_salt = AuditLog(None, salt="one").build_entry(decision, 10, "audit")
    other_salt = AuditLog(None, salt="two").build_entry(decision, 10, "audit")

    assert with_salt["fingerprints"] == same_salt["fingerprints"]
    assert with_salt["fingerprints"] != other_salt["fingerprints"]


def test_fingerprints_are_omitted_without_a_key(monkeypatch):
    monkeypatch.delenv("PII_GUARD_LOG_SALT", raising=False)
    decision = evaluate(f"card {VISA}", Policy(mode="audit"))
    entry = AuditLog(None).build_entry(decision, 10, "audit")
    assert "fingerprints" not in entry


def test_log_appends_rather_than_rewrites(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for _ in range(3):
        log.write(evaluate(f"card {VISA}", Policy(mode="block")), 20, "block")
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 3
