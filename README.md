# PII Guard

Middleware that inspects a prompt before it reaches a large language model. It
finds payment card numbers, IBANs, Turkish national identity numbers, email
addresses and phone numbers, then blocks the prompt, masks the values, or
records the event and lets it through.

Employees paste customer data into chat assistants. Once that text leaves the
network it is outside the organisation's control and, for regulated data, often
outside its legal basis for processing. This project sits between the two.

```
user input ──▶ scan ──▶ policy ──┬─ block ──▶ nothing leaves
                                 ├─ redact ─▶ masked prompt ──▶ LLM
                                 └─ audit ──▶ prompt unchanged ──▶ LLM
                                       │
                                       └─▶ append-only JSONL audit record
```

## What it detects

| Data | Candidate pattern | Validation |
| --- | --- | --- |
| Payment cards | 13 to 19 digits, separators allowed | Luhn checksum, then issuer prefix and length (Visa, Mastercard, Amex, Discover, JCB, Diners, Troy) |
| Turkish national ID | 11 digits, separators allowed | Both check digits (Mod10 / Mod11) |
| IBAN | Country code, check digits, 11 to 30 alphanumerics | ISO 7064 mod-97 |
| Email | Local part, domain, TLD | Structural only |
| Phone | International prefix or Turkish mobile prefix | Digit count between 8 and 15 |

### Why validation and not regex alone

A pattern that accepts any 16-digit run flags order numbers, tracking codes and
invoice references. Users then learn to ignore the alerts, which is the failure
mode that matters. Each numeric type here carries its own checksum, so a second
stage cuts the false positive rate to near zero at negligible cost. The tests in
`test_pii_guard.py` cover exactly these cases.

### Why separators are part of the pattern

`4111111111111111` and `4111 1111 1111 1111` are the same card number. A filter
that only understands the first form is defeated by pressing the space bar, and
that is how people type card numbers anyway. Candidate patterns therefore
tolerate spaces and hyphens between digits, and validation runs on the
normalised value. Lookarounds prevent a shorter pattern from matching inside a
longer digit run, so an identity number is never reported inside a card number.

## The audit log

A DLP tool that writes the values it catches into a plaintext file has moved the
leak, not stopped it, and that file is rarely protected as carefully as the
system it was meant to defend. This one records the decision and nothing else:

```json
{"ts":"2026-09-04T09:12:44+00:00","mode":"redact","action":"redact",
 "tripped":["credit_card","tckn"],"prompt_chars":214,
 "findings":[{"kind":"credit_card","subtype":"visa","count":1},
             {"kind":"tckn","subtype":null,"count":1}]}
```

No prompt body. No detected values. Writes are appends, so concurrent processes
do not overwrite each other.

Set `PII_GUARD_LOG_SALT` to add a keyed fingerprint per value. That makes it
possible to tell one card leaking forty times apart from forty different cards
leaking once, without storing either. The fingerprint is an HMAC rather than a
bare hash on purpose: the search space of card numbers and identity numbers is
small enough to brute force a plain SHA-256 digest offline, so the secret key is
what carries the protection. Fingerprinting is disabled when the variable is
unset.

## Quick start

```bash
pip install -r requirements.txt

# Inspect a single prompt, no model needed
python pii_guard.py --scan-only --text "card 4111 1111 1111 1111"

# Interactive session, masking anything sensitive before the model sees it
python pii_guard.py --mode redact

# Browser demo at http://127.0.0.1:5000
python server.py
```

The model calls expect an [Ollama](https://ollama.com) endpoint. Point
`PII_GUARD_LLM_URL` and `PII_GUARD_LLM_MODEL` elsewhere for a different backend,
or stay in `--scan-only` mode, which needs no model at all.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PII_GUARD_LLM_URL` | `http://localhost:11434/api/generate` | Model endpoint |
| `PII_GUARD_LLM_MODEL` | `deepseek-r1:1.5b` | Model name |
| `PII_GUARD_LOG` | `audit.jsonl` | Audit log path |
| `PII_GUARD_LOG_SALT` | unset | HMAC key for fingerprints |
| `PII_GUARD_MAX_CHARS` | `8000` | Server prompt size limit |
| `PII_GUARD_HOST` / `PII_GUARD_PORT` | `127.0.0.1` / `5000` | Server bind address |

Thresholds are per data type and default to one occurrence. Raise them where a
team has a documented reason:

```bash
python pii_guard.py --mode block --threshold tckn=2
```

An earlier revision only blocked on three or more identity numbers, on the
theory that a single one was probably a false positive. The checksum stage made
that trade-off unnecessary, and one leaked identity number is still a leak.

## Using it as a library

```python
from pii_guard import Policy, evaluate

decision = evaluate("card 4111 1111 1111 1111", Policy(mode="redact"))
decision.action    # "redact"
decision.text      # "card ************1111"
decision.summary() # [{"kind": "credit_card", "subtype": "visa", "count": 1}]
```

## Tests

```bash
python -m pytest -q
```

The suite covers checksum validation, separator bypasses, the false positives
that a naive regex produces, redaction correctness, each policy mode, and the
guarantee that no prompt text or detected value reaches the log.

## Limitations

Worth stating plainly, because a control whose blind spots are undocumented
gets trusted further than it should be.

- **Detection is deterministic.** Names, addresses, dates of birth, account
  numbers without checksums and free-text health details all pass through. A
  named-entity model would extend the coverage at the cost of latency and
  false positives.
- **Encoding evasion is not handled.** Base64, spelled-out digits, homoglyphs
  and text embedded in an uploaded image defeat the patterns. This tool is
  built for accidental disclosure by cooperative users, not for a motivated
  insider.
- **Non-Turkish national identifiers are out of scope.** Adding a country means
  adding its validation rule.
- **The server is a demo harness.** No authentication, no rate limiting, no
  TLS. Fronting real traffic means adding all three.
- **Only the prompt is inspected.** A model that echoes sensitive data back in
  its reply is not covered. Response scanning is the obvious next step.

## Layout

```
pii_guard.py        detection, redaction, policy, audit log, CLI
server.py           Flask API and demo host
demo.html           browser demo
test_pii_guard.py   test suite
```

## License

MIT. See `LICENSE`.
