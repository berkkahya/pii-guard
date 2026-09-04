"""PII Guard: a middleware that inspects prompts before they reach an LLM.

The module is deliberately dependency-light. Only the LLM client and the demo
server need third-party packages; detection and redaction run on the standard
library alone, which keeps the engine easy to embed in other tools and easy to
unit test.

Design notes
------------
Detection is a two-stage process. A permissive pattern collects *candidates*,
then an algorithmic check decides whether a candidate is real:

    Turkish national ID (TCKN) -> Mod10/Mod11 check digits
    Payment cards             -> Luhn checksum plus issuer prefix table
    IBAN                      -> ISO 7064 mod-97 check

Regex alone produces far too many false positives on order numbers, invoice
references and tracking codes. The checksum stage removes almost all of them.

Candidate patterns tolerate separators between digits, because "4111 1111 1111
1111" and "4111-1111-1111-1111" are the same card number to a human reader and
to a payment processor, and a filter that only understands the unseparated form
is bypassed by pressing the space bar.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Callable, Iterable, Sequence

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# Candidate patterns
# --------------------------------------------------------------------------
# `[ -]?` between digits absorbs the separators people actually type. The
# lookarounds stop a pattern from matching a fragment of a longer digit run,
# so an 11-digit TCKN pattern cannot fire inside a 16-digit card number.

CARD_PATTERN = re.compile(r"(?<![\d\-])(?:\d[ \-]?){12,18}\d(?![\d\-])")
TCKN_PATTERN = re.compile(r"(?<![\d\-])[1-9](?:[ \-]?\d){10}(?![\d\-])")
IBAN_PATTERN = re.compile(
    r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+(?![\w-])",
    re.IGNORECASE,
)
# Phone detection is intentionally conservative: an international prefix or a
# Turkish mobile prefix is required. Bare 10-digit runs are left alone because
# they collide with invoice and order numbers far too often.
PHONE_PATTERN = re.compile(
    r"(?<![\w+])(?:"
    r"(?:\+|00)\d[\d \-().]{6,16}\d"
    r"|0?5\d{2}[ \-]?\d{3}[ \-]?\d{2}[ \-]?\d{2}"
    r")(?![\w])"
)

# Issuer prefixes, checked after the Luhn stage so that the brand shown in an
# audit record is accurate rather than guessed from the first digit alone.
CARD_BRANDS: tuple[tuple[str, re.Pattern[str], frozenset[int]], ...] = (
    ("visa", re.compile(r"^4\d+$"), frozenset({13, 16, 19})),
    ("mastercard", re.compile(r"^(5[1-5]\d+|2(?:2[2-9]\d|2[3-9]\d\d|[3-6]\d{3}|7[0-1]\d\d|720\d)\d+)$"), frozenset({16})),
    ("amex", re.compile(r"^3[47]\d+$"), frozenset({15})),
    ("discover", re.compile(r"^(6011\d+|65\d+|64[4-9]\d+)$"), frozenset({16, 19})),
    ("jcb", re.compile(r"^35(?:2[89]|[3-8]\d)\d+$"), frozenset({16, 17, 18, 19})),
    ("diners", re.compile(r"^3(?:0[0-5]|[68]\d)\d+$"), frozenset({14, 16, 19})),
    ("troy", re.compile(r"^9792\d+$"), frozenset({16})),
)


# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------

def digits_only(value: str) -> str:
    """Strip every non-digit character."""
    return "".join(ch for ch in value if ch.isdigit())


def is_valid_tckn(value: str) -> bool:
    """Validate a Turkish national identification number.

    The 10th digit is ((sum of digits 1,3,5,7,9) * 7 - (sum of digits
    2,4,6,8)) mod 10, and the 11th is the sum of the first ten mod 10.
    """
    digits = digits_only(value)
    if len(digits) != 11 or digits[0] == "0":
        return False
    d = [int(c) for c in digits]
    odd_sum = d[0] + d[2] + d[4] + d[6] + d[8]
    even_sum = d[1] + d[3] + d[5] + d[7]
    if d[9] != (odd_sum * 7 - even_sum) % 10:
        return False
    return d[10] == sum(d[:10]) % 10


def is_valid_luhn(value: str) -> bool:
    """Validate a number against the Luhn checksum."""
    digits = digits_only(value)
    if len(digits) < 12:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_brand(value: str) -> str | None:
    """Return the issuer name for a card number, or None if no prefix matches."""
    digits = digits_only(value)
    for name, pattern, lengths in CARD_BRANDS:
        if len(digits) in lengths and pattern.match(digits):
            return name
    return None


def is_valid_iban(value: str) -> bool:
    """Validate an IBAN with the ISO 7064 mod-97 check."""
    compact = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        str(ord(ch) - 55) if ch.isalpha() else ch for ch in rearranged
    )
    return int(numeric) % 97 == 1


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """One piece of sensitive data located in the input text.

    `value` stays in memory for redaction and is never written to the audit
    log. See `AuditLog` for what leaves the process.
    """

    kind: str
    start: int
    end: int
    value: str
    subtype: str | None = None

    @property
    def normalized(self) -> str:
        """The value with formatting removed, used for fingerprinting."""
        if self.kind in {"credit_card", "tckn", "phone"}:
            return digits_only(self.value)
        if self.kind == "iban":
            return re.sub(r"\s+", "", self.value).upper()
        return self.value.strip().lower()


DetectorFn = Callable[[str], Iterable[Finding]]


def _detect_cards(text: str) -> Iterable[Finding]:
    for match in CARD_PATTERN.finditer(text):
        raw = match.group()
        if not is_valid_luhn(raw):
            continue
        brand = card_brand(raw)
        if brand is None:
            continue
        yield Finding("credit_card", match.start(), match.end(), raw, brand)


def _detect_tckn(text: str) -> Iterable[Finding]:
    for match in TCKN_PATTERN.finditer(text):
        raw = match.group()
        if is_valid_tckn(raw):
            yield Finding("tckn", match.start(), match.end(), raw)


def _detect_iban(text: str) -> Iterable[Finding]:
    for match in IBAN_PATTERN.finditer(text):
        raw = match.group()
        if is_valid_iban(raw):
            country = re.sub(r"\s+", "", raw).upper()[:2]
            yield Finding("iban", match.start(), match.end(), raw, country)


def _detect_email(text: str) -> Iterable[Finding]:
    for match in EMAIL_PATTERN.finditer(text):
        yield Finding("email", match.start(), match.end(), match.group())


def _detect_phone(text: str) -> Iterable[Finding]:
    for match in PHONE_PATTERN.finditer(text):
        raw = match.group()
        if 8 <= len(digits_only(raw)) <= 15:
            yield Finding("phone", match.start(), match.end(), raw)


# Order matters. Earlier detectors win an overlap, so a card number is never
# reported as a phone number.
DETECTORS: tuple[tuple[str, DetectorFn], ...] = (
    ("credit_card", _detect_cards),
    ("iban", _detect_iban),
    ("tckn", _detect_tckn),
    ("email", _detect_email),
    ("phone", _detect_phone),
)

KINDS: tuple[str, ...] = tuple(kind for kind, _ in DETECTORS)


def scan(text: str, kinds: Sequence[str] | None = None) -> list[Finding]:
    """Return every validated finding in `text`, sorted by position.

    Overlapping findings are resolved by detector priority: whichever detector
    runs first keeps the span.
    """
    enabled = set(kinds) if kinds is not None else set(KINDS)
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []
    for kind, detector in DETECTORS:
        if kind not in enabled:
            continue
        for finding in detector(text):
            if any(finding.start < end and start < finding.end for start, end in claimed):
                continue
            claimed.append((finding.start, finding.end))
            findings.append(finding)
    findings.sort(key=lambda f: f.start)
    return findings


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

def _mask_tail(value: str, keep: int) -> str:
    """Mask every character except the last `keep` digits or letters."""
    kept = 0
    out: list[str] = []
    for char in reversed(value):
        if char.isalnum() and kept < keep:
            out.append(char)
            kept += 1
        elif char.isalnum():
            out.append("*")
        else:
            out.append(char)
    return "".join(reversed(out))


def mask(finding: Finding) -> str:
    """Return the replacement text for a finding.

    Cards and IBANs keep their last four characters so that a support agent can
    still tell two accounts apart. National identity numbers keep nothing:
    there is no partial view of a TCKN that is useful and safe at the same
    time, since the check digits let an attacker rebuild the rest.
    """
    if finding.kind == "credit_card":
        return _mask_tail(finding.value, 4)
    if finding.kind == "iban":
        compact = re.sub(r"\s+", "", finding.value).upper()
        return f"{compact[:2]}{'*' * (len(compact) - 6)}{compact[-4:]}"
    if finding.kind == "tckn":
        return "[TCKN]"
    if finding.kind == "email":
        local, _, domain = finding.value.partition("@")
        return f"{local[0]}{'*' * max(len(local) - 1, 1)}@{domain}"
    if finding.kind == "phone":
        return _mask_tail(finding.value, 2)
    return "[REDACTED]"


def redact(text: str, findings: Sequence[Finding]) -> str:
    """Replace every finding in `text` with its mask."""
    result = text
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        result = result[: finding.start] + mask(finding) + result[finding.end :]
    return result


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

BLOCK = "block"
REDACT = "redact"
AUDIT = "audit"


@dataclass
class Policy:
    """How the guard reacts to what it finds.

    `thresholds` is the number of occurrences of a kind that trips the policy.
    Every threshold defaults to 1. An earlier revision of this project only
    blocked on three or more national identity numbers, on the theory that a
    single number was likelier to be a false positive. The checksum stage made
    that trade-off unnecessary, and a leak of one identity number is still a
    leak, so the default is now 1. Raise it per deployment if a team has a
    documented reason to.
    """

    mode: str = REDACT
    thresholds: dict[str, int] = field(default_factory=dict)
    enabled_kinds: tuple[str, ...] = KINDS

    def threshold(self, kind: str) -> int:
        return max(1, self.thresholds.get(kind, 1))


@dataclass
class Decision:
    """The result of applying a policy to a prompt."""

    action: str  # "allow", "redact" or "block"
    text: str  # what should be forwarded to the LLM
    findings: list[Finding]
    tripped: list[str]

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    def summary(self) -> list[dict[str, object]]:
        """Counts per kind and subtype. Contains no sensitive values."""
        buckets: dict[tuple[str, str | None], int] = {}
        for finding in self.findings:
            key = (finding.kind, finding.subtype)
            buckets[key] = buckets.get(key, 0) + 1
        return [
            {"kind": kind, "subtype": subtype, "count": count}
            for (kind, subtype), count in sorted(buckets.items())
        ]


def evaluate(text: str, policy: Policy | None = None) -> Decision:
    """Scan `text` and apply `policy` to the result."""
    policy = policy or Policy()
    findings = scan(text, policy.enabled_kinds)

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.kind] = counts.get(finding.kind, 0) + 1
    tripped = sorted(
        kind for kind, count in counts.items() if count >= policy.threshold(kind)
    )

    if not tripped:
        return Decision("allow", text, findings, [])
    if policy.mode == BLOCK:
        return Decision("block", "", findings, tripped)
    if policy.mode == REDACT:
        return Decision("redact", redact(text, findings), findings, tripped)
    return Decision("allow", text, findings, tripped)


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------

class AuditLog:
    """Append-only JSON Lines record of guard decisions.

    The prompt body and the detected values never reach this file. A DLP tool
    that copies card numbers into a plaintext log has moved the leak rather
    than stopped it, and that log is rarely protected as carefully as the
    system it was meant to defend.

    Set PII_GUARD_LOG_SALT to record a keyed fingerprint of each value, which
    makes it possible to tell "the same card, forty times" apart from "forty
    different cards" without storing either. The fingerprint is an HMAC rather
    than a plain hash on purpose: the search space of card numbers and identity
    numbers is small enough to brute force a bare SHA-256 digest, so the secret
    key is what carries the protection. Fingerprinting is off when the variable
    is unset.
    """

    def __init__(self, path: str | os.PathLike[str] | None, salt: str | None = None):
        self.path = str(path) if path else None
        self.salt = (salt or os.environ.get("PII_GUARD_LOG_SALT") or "").encode()

    def fingerprint(self, value: str) -> str | None:
        if not self.salt:
            return None
        return hmac.new(self.salt, value.encode("utf-8"), sha256).hexdigest()[:16]

    def build_entry(self, decision: Decision, prompt_length: int, mode: str) -> dict:
        entry: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": mode,
            "action": decision.action,
            "tripped": decision.tripped,
            "prompt_chars": prompt_length,
            "findings": decision.summary(),
        }
        fingerprints = [
            fp for fp in (self.fingerprint(f.normalized) for f in decision.findings) if fp
        ]
        if fingerprints:
            entry["fingerprints"] = fingerprints
        return entry

    def write(self, decision: Decision, prompt_length: int, mode: str) -> dict:
        entry = self.build_entry(decision, prompt_length, mode)
        if self.path:
            # Append rather than read-modify-write. The earlier version of this
            # project read the whole log into memory to prepend each new line,
            # which is quadratic and loses entries if two processes write at
            # once.
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry


# --------------------------------------------------------------------------
# LLM client
# --------------------------------------------------------------------------

DEFAULT_OLLAMA_URL = os.environ.get(
    "PII_GUARD_LLM_URL", "http://localhost:11434/api/generate"
)
DEFAULT_MODEL = os.environ.get("PII_GUARD_LLM_MODEL", "deepseek-r1:1.5b")


class LLMError(RuntimeError):
    """Raised when the upstream model cannot be reached or replies unusably."""


class OllamaClient:
    """Minimal client for an Ollama-compatible generate endpoint."""

    def __init__(
        self,
        url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = 60.0,
    ):
        self.url = url
        self.model = model
        self.timeout = timeout

    def generate(self, prompt: str) -> str:
        try:
            import requests
        except ImportError as exc:  # pragma: no cover - import guard
            raise LLMError(
                "requests is not installed. Run: pip install -r requirements.txt"
            ) from exc

        payload = {"model": self.model, "prompt": prompt, "stream": False}
        try:
            response = requests.post(self.url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
        except requests.Timeout as exc:
            raise LLMError(f"The model did not respond within {self.timeout:g}s.") from exc
        except requests.RequestException as exc:
            raise LLMError(f"Could not reach the model at {self.url}: {exc}") from exc
        except ValueError as exc:
            raise LLMError("The model returned a response that is not JSON.") from exc

        text = data.get("response")
        if not text:
            raise LLMError("The model returned an empty response.")
        return text


# --------------------------------------------------------------------------
# Command line interface
# --------------------------------------------------------------------------

FRIENDLY_NAMES = {
    "credit_card": "payment card",
    "tckn": "Turkish national ID",
    "iban": "IBAN",
    "email": "email address",
    "phone": "phone number",
}


def describe(decision: Decision) -> str:
    """One line naming what was found, without repeating any of it."""
    parts = []
    for item in decision.summary():
        name = FRIENDLY_NAMES.get(str(item["kind"]), str(item["kind"]))
        subtype = item["subtype"]
        label = f"{name} ({subtype})" if subtype else name
        parts.append(f"{item['count']} x {label}")
    return ", ".join(parts) if parts else "nothing sensitive"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii_guard",
        description="Inspect a prompt for sensitive data before sending it to an LLM.",
    )
    parser.add_argument(
        "--mode",
        choices=[BLOCK, REDACT, AUDIT],
        default=REDACT,
        help="block: refuse the prompt. redact: mask and send. audit: record and send unchanged.",
    )
    parser.add_argument("--text", help="Inspect one string and exit.")
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Report findings without calling the model.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Model name to call.")
    parser.add_argument("--url", default=DEFAULT_OLLAMA_URL, help="Model endpoint.")
    parser.add_argument(
        "--log",
        default=os.environ.get("PII_GUARD_LOG", "audit.jsonl"),
        help="Audit log path. Pass an empty string to disable.",
    )
    parser.add_argument(
        "--threshold",
        action="append",
        default=[],
        metavar="KIND=N",
        help="Occurrences of KIND needed to trip the policy, e.g. tckn=2.",
    )
    parser.add_argument("--version", action="version", version=f"pii_guard {__version__}")
    return parser


def parse_thresholds(values: Sequence[str]) -> dict[str, int]:
    thresholds: dict[str, int] = {}
    for item in values:
        kind, _, raw = item.partition("=")
        if kind not in KINDS or not raw.isdigit():
            raise SystemExit(
                f"Invalid threshold {item!r}. Use KIND=N with KIND in {', '.join(KINDS)}."
            )
        thresholds[kind] = int(raw)
    return thresholds


def handle(text: str, policy: Policy, log: AuditLog, client: OllamaClient | None) -> int:
    decision = evaluate(text, policy)
    log.write(decision, len(text), policy.mode)

    if decision.findings:
        print(f"Found: {describe(decision)}")

    if decision.blocked:
        print("Blocked. The prompt was not sent.")
        return 1

    if decision.action == "redact" and decision.findings:
        print("Sending this instead:")
        print(f"  {decision.text}")

    if client is None:
        return 0

    try:
        print(client.generate(decision.text))
    except LLMError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = Policy(mode=args.mode, thresholds=parse_thresholds(args.threshold))
    log = AuditLog(args.log or None)
    client = None if args.scan_only else OllamaClient(url=args.url, model=args.model)

    if args.text is not None:
        return handle(args.text, policy, log, client)

    print("Type a prompt. Enter 'exit' to quit.")
    while True:
        try:
            text = input("> ")
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if text.strip().lower() in {"exit", "quit"}:
            return 0
        if not text.strip():
            continue
        handle(text, policy, log, client)


if __name__ == "__main__":
    raise SystemExit(main())
