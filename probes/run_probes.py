#!/usr/bin/env python3
"""验收探针：JWT 声明批量审计（6 条契约）。token 现场签发，离线校验。"""
import sys, time, json, base64
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from jwcrypto.audit import audit_tokens
    return audit_tokens

NOW = 1794960000  # 2026-11-18T00:00:00Z

def tok(claims=None, key=None, alg="HS256"):
    from jwcrypto.jwk import JWK
    from jwcrypto.jwt import JWT
    k = key or JWK(kty="oct", k=base64.urlsafe_b64encode(b"0" * 32).decode().rstrip("="))
    body = dict(claims or {})
    body.setdefault("iss", "https://idp.example.com")
    body.setdefault("aud", "gateway")
    body.setdefault("iat", NOW - 60)
    body.setdefault("exp", NOW + 3600)
    return JWT(header={"alg": alg, "typ": "JWT"}, claims=json.dumps(body)).make_signed_token(k) \
        if False else _tok(k, body, alg)

def _tok(k, body, alg):
    from jwcrypto.jwt import JWT
    t = JWT(header={"alg": alg, "typ": "JWT"}, claims=json.dumps(body))
    t.make_signed_token(k)
    return t.serialize()

def key():
    from jwcrypto.jwk import JWK
    return JWK(kty="oct", k=base64.urlsafe_b64encode(b"1" * 32).decode().rstrip("="))

@probe("P01 批量入口与合规 token")
def p01():
    fn = api(); k = key(); out = fn([tok(key=k)], key=k, expected_iss="https://idp.example.com",
                                    expected_aud="gateway", now=NOW)
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "alg", "iss", "aud", "exp", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合规 token 应 ok，实际 {item['reason']}"
    assert item["alg"] == "HS256" and item["exp"] == NOW + 3600

@probe("P02 过期")
def p02():
    fn = api(); k = key(); item = fn([tok({"exp": NOW - 10}, key=k)], key=k, now=NOW).items[0]
    assert item["reason"] == "expired", f"应为 expired，实际 {item['reason']}"

@probe("P03 算法白名单与 none")
def p03():
    fn = api(); k = key()
    out = fn([tok(key=k), "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0."], key=k,
             allowed_algs=["HS256"], now=NOW)
    assert out.items[1]["reason"] == "alg_rejected", f"none 应被拒，实际 {out.items[1]['reason']}"
    assert out.items[1]["alg"] == "none"

@probe("P04 iss / aud 不匹配")
def p04():
    fn = api(); k = key()
    out = fn([tok({"iss": "https://evil.example.com"}, key=k),
              tok({"aud": "other"}, key=k)], key=k, expected_iss="https://idp.example.com",
             expected_aud="gateway", now=NOW)
    assert out.items[0]["reason"] == "wrong_iss", f"应为 wrong_iss，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "wrong_aud", f"应为 wrong_aud，实际 {out.items[1]['reason']}"

@probe("P05 签名无效与结构损坏")
def p05():
    fn = api(); k = key(); good = tok(key=k)
    parts = good.split("."); forged = ".".join(parts[:2] + ["AAAA" + parts[2][4:]])
    out = fn([forged, "not-a-jwt"], key=k, now=NOW)
    assert out.items[0]["reason"] == "bad_signature", f"应为 bad_signature，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "malformed", f"应为 malformed，实际 {out.items[1]['reason']}"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api(); k = key()
    out = fn([tok(key=k), tok({"exp": NOW - 1}, key=k), "garbage"], key=k, now=NOW)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("expired") == 1, f"by_reason 不对：{st['by_reason']}"
    empty = fn([], key=k); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    t = tok(key=k); recs = [t] * 300
    t0 = time.perf_counter(); out2 = fn(recs, key=k, now=NOW); cost = time.perf_counter() - t0
    assert len(out2.items) == 300 and cost < 3.0, f"300 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：JWT 声明批量审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
