"""HTTP front end for PII Guard.

Two endpoints:

    POST /api/scan   inspect a prompt and return the decision, no model call
    POST /api/chat   inspect a prompt, then forward the allowed text to the LLM

The server is a demonstration harness. It has no authentication and no rate
limiting, so run it on localhost. Putting it in front of real traffic means
adding both, plus TLS termination.
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request, send_from_directory

from pii_guard import (
    AUDIT,
    BLOCK,
    REDACT,
    AuditLog,
    LLMError,
    OllamaClient,
    Policy,
    describe,
    evaluate,
)

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_PROMPT_CHARS = int(os.environ.get("PII_GUARD_MAX_CHARS", "8000"))

app = Flask(__name__, static_folder=None)
audit_log = AuditLog(os.environ.get("PII_GUARD_LOG", "audit.jsonl"))
llm = OllamaClient()


def _read_request() -> tuple[str, Policy]:
    """Pull the prompt and policy out of the request body."""
    payload = request.get_json(silent=True) or {}
    text = payload.get("text")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Send a JSON body with a non-empty 'text' field.")
    if len(text) > MAX_PROMPT_CHARS:
        raise ValueError(f"Prompts are limited to {MAX_PROMPT_CHARS} characters.")

    mode = payload.get("mode", REDACT)
    if mode not in {BLOCK, REDACT, AUDIT}:
        raise ValueError(f"Unknown mode '{mode}'. Use block, redact or audit.")
    return text, Policy(mode=mode)


def _serialize(decision, policy: Policy) -> dict:
    return {
        "action": decision.action,
        "mode": policy.mode,
        "tripped": decision.tripped,
        "findings": decision.summary(),
        "summary": describe(decision),
        "spans": [
            {"kind": f.kind, "subtype": f.subtype, "start": f.start, "end": f.end}
            for f in decision.findings
        ],
        "forwarded": decision.text,
    }


@app.route("/")
def index():
    return send_from_directory(HERE, "demo.html")


@app.post("/api/scan")
def api_scan():
    try:
        text, policy = _read_request()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    decision = evaluate(text, policy)
    audit_log.write(decision, len(text), policy.mode)
    return jsonify(_serialize(decision, policy))


@app.post("/api/chat")
def api_chat():
    try:
        text, policy = _read_request()
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    decision = evaluate(text, policy)
    audit_log.write(decision, len(text), policy.mode)
    body = _serialize(decision, policy)

    if decision.blocked:
        body["reply"] = None
        return jsonify(body)

    try:
        body["reply"] = llm.generate(decision.text)
    except LLMError as exc:
        body["reply"] = None
        body["error"] = str(exc)
        return jsonify(body), 502
    return jsonify(body)


if __name__ == "__main__":
    app.run(
        host=os.environ.get("PII_GUARD_HOST", "127.0.0.1"),
        port=int(os.environ.get("PII_GUARD_PORT", "5000")),
        debug=False,
    )
