# Copyright (C) 2026  JWCrypto Project Contributors - see LICENSE file

"""Batch auditing of serialized JWT tokens.

This module provides :func:`audit_tokens`, a non-throwing entry point for
screening large batches of compact-serialized JWTs. Each token is classified
with a stable reason code so that a single bad token never interrupts the
batch and results can be aggregated by cause:

* ``ok``           - signature valid, every applicable check passed
* ``expired``      - the ``exp`` claim is at or before the audit time
* ``bad_signature``- the token failed cryptographic verification
* ``alg_rejected`` - the header algorithm is not in the allow list
  (this includes the unsigned ``none`` algorithm)
* ``wrong_iss``    - the ``iss`` claim does not match the expected issuer
* ``wrong_aud``    - none of the token's audiences matches the expectation
* ``malformed``    - the serialization cannot be parsed as a JWT

The module is intentionally self-contained: it only builds on
:mod:`jwcrypto.jws` and :mod:`jwcrypto.common` and never performs network
access (no JWKS fetching).
"""

import time

from jwcrypto.common import base64url_decode, json_decode
from jwcrypto.common import JWKeyNotFound
from jwcrypto.jws import JWS, InvalidJWSObject, InvalidJWSSignature


DEFAULT_ALLOWED_ALGS = ["HS256", "HS384", "HS512"]
"""Algorithms accepted by :func:`audit_tokens` when no allow list is given."""


class _Malformed(Exception):
    """Internal signal: the token serialization is not a parseable JWT."""


class _BadSignature(Exception):
    """Internal signal: the token parsed but failed verification."""


class AuditResult:
    """Outcome of a batch audit.

    :ivar items: one result dict per input token, in input order. Each item
      carries ``index`` / ``ok`` / ``reason`` / ``alg`` / ``iss`` / ``aud``
      / ``exp`` / ``issues``.
    :ivar stats: aggregate counters with ``ok``, ``bad`` and ``by_reason``.
    """

    def __init__(self, items, stats):
        self.items = items
        self.stats = stats

    def __repr__(self):
        return "AuditResult(stats=%r, items=%d)" % (self.stats,
                                                    len(self.items))


def _decode_segment(segment):
    """Decode one compact-serialization segment; raise _Malformed on error."""
    try:
        return base64url_decode(str(segment))
    except (ValueError, TypeError) as e:
        raise _Malformed("invalid base64url segment") from e


def _parse_structure(token):
    """Split a compact JWT into (header, payload_bytes, raw_token).

    Only the three-part compact JWS serialization is accepted.
    """
    if not isinstance(token, str):
        raise _Malformed("token is not a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise _Malformed("token must have three compact segments")

    header_bytes = _decode_segment(parts[0])
    payload_bytes = _decode_segment(parts[1])
    # The signature segment must be valid base64url as well; an unsigned or
    # empty signature is structurally legal and handled later by the alg /
    # signature checks, not here.
    _decode_segment(parts[2])

    try:
        header = json_decode(header_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise _Malformed("header is not valid JSON") from e
    if not isinstance(header, dict):
        raise _Malformed("header is not a JSON object")

    return header, payload_bytes, token


def _verify_signature(raw_token, key, allowed_algs):
    """Verify the JWS signature, restricting algorithms first.

    :raises _Malformed: if the token cannot be deserialized as a JWS.
    :raises _BadSignature: if deserialization works but verification fails.
    """
    jws = JWS()
    # Restrict the algorithms before any cryptographic operation so that a
    # rejected algorithm (including "none") is reported as alg_rejected
    # rather than failing later inside signature verification.
    jws.allowed_algs = allowed_algs
    try:
        jws.deserialize(raw_token, None)
    except InvalidJWSObject as e:
        raise _Malformed("invalid JWS object") from e
    try:
        jws.verify(key)
    except InvalidJWSSignature as e:
        raise _BadSignature("signature verification failed") from e
    except JWKeyNotFound as e:
        raise _BadSignature("no matching key") from e


def _aud_matches(token_aud, expected_aud):
    """Check the expected audience against a string or array ``aud``."""
    if isinstance(token_aud, list):
        audiences = token_aud
    else:
        audiences = [token_aud]
    if isinstance(expected_aud, list):
        expected = expected_aud
    else:
        expected = [expected_aud]
    return any(value in audiences for value in expected)


def _check_claims(claims, now, expected_iss, expected_aud):
    """Run the claim-level gates; return (reason, issues) or (None, [])."""
    issues = []

    exp = claims.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool) \
            and exp <= now:
        issues.append("expired: exp=%s <= now=%s" % (exp, now))
        return "expired", issues

    if expected_iss is not None:
        if claims.get("iss") != expected_iss:
            issues.append("wrong_iss: expected %r, got %r"
                          % (expected_iss, claims.get("iss")))
            return "wrong_iss", issues

    if expected_aud is not None:
        token_aud = claims.get("aud")
        if token_aud is None or not _aud_matches(token_aud, expected_aud):
            issues.append("wrong_aud: expected %r, got %r"
                          % (expected_aud, token_aud))
            return "wrong_aud", issues

    return None, issues


def audit_tokens(tokens, key, allowed_algs=None, expected_iss=None,
                 expected_aud=None, now=None):
    """Audit a batch of serialized JWT tokens without raising.

    :param tokens: list of compact-serialized JWT strings.
    :param key: a :class:`jwcrypto.jwk.JWK` (or :class:`jwcrypto.jwk.JWKSet`)
      used to verify signatures.
    :param allowed_algs: optional allow list of header ``alg`` values;
      defaults to :data:`DEFAULT_ALLOWED_ALGS`. The unsigned ``none``
      algorithm is never accepted unless explicitly listed, and listing it
      still cannot produce a valid signature against a real key.
    :param expected_iss: if set, tokens whose ``iss`` differs are classified
      ``wrong_iss``.
    :param expected_aud: if set, tokens whose ``aud`` (string or array) does
      not contain the expected audience are classified ``wrong_aud``.
    :param now: integer epoch seconds used for expiry checks; defaults to the
      current time. A token with ``exp <= now`` is ``expired``.
    :returns: :class:`AuditResult` with ``items`` and ``stats``. Bad tokens
      are recorded with a reason code instead of interrupting the batch.
    """
    if allowed_algs is None:
        allowed_algs = list(DEFAULT_ALLOWED_ALGS)
    if now is None:
        now = int(time.time())

    items = []
    by_reason = {}
    ok_count = 0

    for index, token in enumerate(tokens):
        item = {
            "index": index,
            "ok": False,
            "reason": "malformed",
            "alg": None,
            "iss": None,
            "aud": None,
            "exp": None,
            "issues": [],
        }

        try:
            header, payload_bytes, raw_token = _parse_structure(token)
            alg = header.get("alg")
            if not isinstance(alg, str):
                raise _Malformed("header 'alg' missing or not a string")
            item["alg"] = alg

            if alg not in allowed_algs:
                item["reason"] = "alg_rejected"
                item["issues"].append(
                    "alg_rejected: %r not in allowed list" % alg)
            else:
                _verify_signature(raw_token, key, allowed_algs)

                try:
                    claims = json_decode(payload_bytes.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as e:
                    raise _Malformed("payload is not valid JSON") from e
                if not isinstance(claims, dict):
                    raise _Malformed("payload is not a JSON object")

                item["iss"] = claims.get("iss")
                item["aud"] = claims.get("aud")
                item["exp"] = claims.get("exp")

                reason, claim_issues = _check_claims(
                    claims, now, expected_iss, expected_aud)
                item["issues"].extend(claim_issues)
                if reason is None:
                    item["reason"] = "ok"
                    item["ok"] = True
                else:
                    item["reason"] = reason

        except _Malformed as e:
            item["reason"] = "malformed"
            item["issues"].append("malformed: %s" % e)
        except _BadSignature as e:
            item["reason"] = "bad_signature"
            item["issues"].append("bad_signature: %s" % e)
        except Exception as e:  # last-resort guard: one token must not kill
            item["reason"] = "malformed"  # the whole batch
            item["issues"].append("malformed: %s: %s"
                                  % (type(e).__name__, e))

        items.append(item)
        if item["ok"]:
            ok_count += 1
        by_reason[item["reason"]] = by_reason.get(item["reason"], 0) + 1

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_reason": by_reason,
    }
    return AuditResult(items, stats)


__all__ = ["audit_tokens", "AuditResult", "DEFAULT_ALLOWED_ALGS"]
