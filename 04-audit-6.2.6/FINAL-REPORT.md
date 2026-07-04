# ActiveMQ Classic 6.2.6 — Auto-Research Security Audit

**Date:** 2026-06-21
**Target:** Apache ActiveMQ Classic **6.2.6** (tag `activemq-6.2.6`, commit `bb9523b98`, released 2026-05-27), clean checkout at `targets/activemq-6.2.6`, 32 modules / ~220k SLOC Java.
**Method:** RAPTOR auto-research loop — 5 rounds, generate→judge→verify→completeness-critic, isolated parallel agents (Sonnet generate / Opus judge+verify), persistent ledger. ~50 agents, ~10M agent-tokens.
**Scope (standing):** RCE / auth-bypass / access-granting are the headline; DoS catalogued but not headline.
**Ledger:** `ledger/EXISTING-FINDINGS.md` (exclusion set), `ledger/TRIED.md` (every attempt), `ledger/FINDINGS.md` (running findings), `rounds/R*.json` (raw).

---

## 1. The question you asked — "can we find similar to past issues, or are we better?"

**Both, and the split is the headline result.**

- **The past *RCE/deserialization* doors are CLOSED in 6.2.6, and our verifiers confirmed the closures hold** — including refuting tempting re-discoveries. We did **not** find a clean unauthenticated RCE on par with CVE-2026-34197 / 42588. That is the product getting better.
- **The same past *bug families* recur as net-new, lower-severity instances.** The CVE-2026-42253 console-injection family is now **systemic** (one attacker-controlled identifier reaching ~7 unescaped sinks), and the broker carries a **cluster of authorization-model gaps** (the broken-object-level-authz family that dominates our prior web audits). We also found a genuine **sink variant past the 34197/42588 denylist** (`static:` scheme).
- **Our methodology is materially better than our last ActiveMQ pass.** The April-30 2026 run completed only 5 of 60 dispatched analyses (egress-proxy cap) and concluded "no novel primitive beyond 34197." This run swept all four altitudes with adversarial verification and produced **10+ verified net-new findings** plus a completeness-critic sign-off.

**Bottom line:** 6.2.6 is meaningfully hardened against the memory-safety/RCE/deser classes we (and the CVEs) hit before. The residual risk has shifted to **(a) output-encoding/injection in the web console and (b) the authorization model** — exactly the classes our memory flags as recurring (`map-then-trace-all-classes`, `anonymous-read-authz-object-hunt`, `post-cve-sink-variant-reaudit`).

---

## 2. Past issues vs. 6.2.6 ground truth (verified by direct read)

| Past issue | Class | State in 6.2.6 (verified) |
|---|---|---|
| CVE-2026-34197 / 42588 (Jolokia→`vm://?brokerConfig=xbean:`→Spring RCE) | RCE | **Closed twice by default.** `BrokerView.validateAllowedUri` (BrokerView.java:615) now parses composites directly with `URISupport.parseComposite` + recurses (kills the 42588 no-paren `isCompositeURI` bypass); sink layer `VMTransportFactory` enforces `DEFAULT_ALLOWED_SCHEMES="broker,properties"` (VMTransportFactory.java:52) → `xbean` rejected. Bypass needs self-inflicted `...SCHEMES_ENABLED=*`. |
| CVE-2026-42253 (MessageServlet header-injection/XSS) | Injection | Mitigated — `MessageServlet` `@Deprecated`+disabled (MessageServlet.java:55-57), undeployed in default `web.xml`. **Sink code unchanged** + the *class* recurs elsewhere (see §3 Theme A). |
| CVE-2023-46604 (OpenWire `createThrowable`) | RCE | Patched — `validateIsThrowable` across all v1-v12 + legacy. |
| CVE-2015-5254 (ObjectMessage deser) | RCE | Mitigated — no unfiltered `ObjectInputStream` in the tree; `ClassLoadingAwareObjectInputStream` + XStream allow-list factory everywhere. |
| CVE-2024-32114 (Jolokia unauth on 6.0-6.1.1) | Auth | Fixed; 6.2.6 requires auth for the console/Jolokia. |
| AMQ-9810 (MQTT/AMQP length DoS) | DoS | Patched (additional wireformat validation). |

Supply chain is current and clean: Spring 6.2.18, Jetty 11.0.26, Jackson 2.21.1, log4j 2.25.4, commons-collections **3.2.2** (post-gadget safe), qpid-proton 0.34.1, netty 4.2.10. XXE hardened by default (`FEATURE_SECURE_PROCESSING` + disallow-doctype). Log4J config-reload lead from 2026-04 is closed by the log4j2 migration (reflective `reconfigure()`, no attacker input).

---

## 3. Confirmed net-new findings (6.2.6)

All independently generated, adversarially judged, and verified from raw source; the headline ones re-read by the orchestrator. Severity is realistic-deployment.

### Theme A — Console / output-encoding injection  *(CVE-2026-42253 family — "map then trace ALL classes")*
**Root cause (systemic):** attacker-controlled identifier strings — OpenWire `ConnectionInfo.connectionId`, `clientId`, and the `MessageId.textView` wire field (OpenWire v10+ **and** AMQP `AmqpReceiver:188` ingress) — flow through `MessageId.toString()` = `"ID:"+textView` and are rendered **unescaped** in multiple web-console/REST sinks.

| ID | Sink | Severity | Reachability |
|----|------|----------|--------------|
| A1 (F2) | `browse.jsp:51` `${row.JMSMessageID}` raw (every sibling uses `<c:out>`) | Low→Med | producer→admin console; full JS-exec gated by default CSP → HTML/content-injection by default |
| A2 (F8) | `scheduled.jsp:56` jobId in `href` (attribute breakout via `"`) | Low | conditional (schedulerSupport=true) |
| A3 (F12) | `queueConsumers.jsp` `${row.clientId}` raw | Low | write-side pre-auth on default-no-auth broker; CSP-gated exec |
| A4 | `graph.jsp` JMSMessageID in `href` (uncertain — CSP-blocked default) | Low | admin |
| A7 (F3) | `FileSystemBlobStrategy.java:134` `new File(root, getJMSMessageID())` (only `:`→`_`, `../` survives) → arbitrary client-side file read/write | Med | client-side; hostile/MITM broker + BLOB feature + `file://` baseline |

Refuted in this family (verifier killed): `MessageServlet` `setHeader("id",...)` (undeployed by default + Jetty 11 rejects CRLF), `RssMessageRenderer` link (not exploitable).

### Theme B — Authorization model  *(broken-object-level-authz family — our recurring web-audit class)*

| ID | Finding | Severity | Reachability | Status |
|----|---------|----------|--------------|--------|
| **B1 (F10)** | **Durable-subscription cross-clientId deletion IDOR** — `TopicRegion.removeSubscription:212` keys on the **wire-supplied** `RemoveSubscriptionInfo.clientId` (not `context.getClientId()`, contrast lines 125/195), and `AuthorizationBroker` overrides `addConsumer/addProducer/send/...` but **NOT `removeSubscription`** → any user deletes any client's durable sub. | **Medium** | post-auth-user (pre-auth if no auth) | **Confirmed (cleanest net-new)** |
| **B2 (F9)** | **Shiro colon-injection verb-escalation** — destination physically named `ACCOUNTING:read` + grant `queue:ACCOUNTING:read` makes the required `queue:ACCOUNTING:read:write` (4-part) `.implies()`-true by the 3-part grant (`:` is both dest-name char and WildcardPermission separator). | Low-Med | post-auth-user | Confirmed (Shiro non-default) |
| B3 (F1) | **LDAP empty-password → unauthenticated/anonymous bind** — `LDAPLoginModule` (login:127-134) passes empty password into `bindUser` (433-438) with no emptiness guard; only the service-account bind is guarded. | Med (conditional) | pre-auth | Real; conditional on LDAPLoginModule + directory accepting anon/unauth binds |
| B4 | Temp-destination authz **fail-OPEN** (null temp-ACL passes) vs non-temp **fail-CLOSED** asymmetry → cross-connection temp-queue hijack. | Low | post-auth-user | Real-but-by-design (AMQ-4721, 2012) + documented mitigation `tempDestinationAuthorizationEntry` → **hardening** |
| B5 | `StatisticsBroker.sendStats()` `next.send()` skips the write-ACL on the attacker `replyTo` **iff** `statisticsBrokerPlugin` is listed before `authorizationPlugin`. | Low | post-auth-user | Real, config-order-dependent → hardening |
| B6 | Cert-login DN matched via deprecated **non-canonical** `getSubjectDN().getName()` (CertificateLoginModule.java:193) → identity-collision among same-CA certs; + regex-map HashMap race / null-cache policy bypass. | Low | pre-auth (TLS-trust-validated first) | Real code smell; conditional (cert module non-default); "any self-signed cert" does NOT work (JSSE validates trust at handshake) |
| B7 | `JMSXUserID` spoof when `populateJMSXUserID=false` (the default) — client sets `userID` verbatim, no `UserIDBroker`. | Low | post-auth-user | Noted |

Refuted in this theme: **scheduler BROWSE/REMOVE/REMOVEALL "IDOR"** — the scheduler is single-tenant **by design**; the management queue is a documented API gated by its write-ACL; disabled by default → **hardening note, not a defect** (verifier correctly overruled the earlier IDOR framing).

### Theme C — Sink variant past the 34197/42588 fix  *(post-cve-sink-variant-reaudit)*

| ID | Finding | Severity | Reachability |
|----|---------|----------|--------------|
| **C1 (F11)** | **`static:` denylist gap** — `static` is absent from `BrokerView.DENIED_TRANSPORT_SCHEMES`, so `addNetworkConnector("static:(tcp://attacker:port)")` reaches `DiscoveryNetworkConnector` → outbound broker TCP = **SSRF**. The denylist guards the trigger; this scheme slips it. (Not RCE — `static→tcp`, not `vm→xbean`.) | Medium | admin / JMX |

### Cross-protocol
- **F5** STOMP outbound header **NAME** never escaped (`StompWireFormat.java:83`; only VALUE is) → a JMS property name with `\n` (set by an OpenWire/AMQP producer) splits the frame to a co-tenant STOMP subscriber. Low, conditional (STOMP enabled), client-side.

---

## 4. Out of headline scope — catalogued

**Pre-auth protocol-parser DoS cluster** (DoS = out of scope per standing rule, but genuine):
- OpenWire signed-`short` `NegativeArraySizeException` (tightUnmarshalString, StackTraceElement arrays); unbounded alloc / recursion in `MarshallingSupport.unmarshalPrimitive`; cache-index AIOOBE; **`OpenWireFormat.DEFAULT_MAX_FRAME_SIZE = Long.MAX_VALUE`** (cap effectively unbounded unless operator sets `wireFormat.maxFrameSize`).
- STOMP negative content-length unbounded alloc.
- **MQTT `ActiveMQ.MQTT.QoS` int property → `QoS.values()[ordinal]` AIOOBE** (F4) — *exploitable, no special config, cross-protocol* (any OpenWire/STOMP/AMQP producer force-disconnects an MQTT subscriber). Cleanest of the DoS set.
- AMQP dead `maxFrameSize` guard (int vs `Long.MAX_VALUE`); scheduler **negative `AMQ_SCHEDULED_REPEAT`** → immortal job.

**Default-config posture (deployment reality, mostly long-known by-design):** broker auth **disabled by default** (plugins block commented out in `activemq.xml`) → pre-auth full queue access; default `admin/admin` console creds; `PBEWithMD5AndDES` + documented default key `activemq` for `credentials-enc`; missing cookie `Secure`/`SameSite`; non-constant-time password compare.

---

## 5. What the verifiers *refuted* (the discipline working)

The generate→judge→verify→reconcile pipeline killed ~24 of ~38 distinct candidates, including several plausible-but-wrong ones — this is why the surviving set is trustworthy:
- **scheduler "IDOR"** → by-design single-tenant management API (overruled my own initial confirmation).
- **stomp-3** "ACK-without-removal/duplication" → disproven by tracing `acknowledge()`+`dropMessage()` run *before* the networkSubscription-gated `messages.rollback()`, which only clears the cursor audit.
- **runtime-config reload RCE** → requires `activemq.xml` write (= already-owned) or admin Jolokia; no boundary crossed.
- **AMQP SASL ANONYMOUS bypass** → a real auth plugin rejects null-username; only the explicit `GuestLoginModule` accepts it (by-design).
- **XPath selector XXE** → XXE hardened by default; sysprop-reenable needs JVM-arg control.
- **MessageServlet header injection, transport-3, network-bridge-1, client-core-1, http-transport-2/3, console-jolokia-2, broker-plugins-1/3** → undeployed-by-default / theoretical / by-design / admin-only-read.
- **StatisticsBroker ACL bypass** → reconciled to *config-order-dependent* (resolved an R2a-vs-R2b disagreement).

---

## 6. Residual cells deliberately deprioritized (honesty — grid not claimed exhausted)

The completeness-critic returned `comprehensive=true` for the realistic threat model. Remaining lower-priority cells, none of which yielded an in-scope exploitable bug in R4:
- OpenWire `Long.MAX_VALUE` frame-cap pre-auth allocation DoS (operator-mitigable, DoS-class).
- RuntimeConfigurationBroker reload **if** an attacker already has a file-write/symlink TOCTOU primitive on `activemq.xml` (compound precondition).
- AMQP ANONYMOUS **with** `GuestLoginModule` wired (guest-access-as-configured).
- XPath-selector shared `DocumentBuilder` thread-safety race (robustness, not security).
- Deep fuzzing of the OpenWire/AMQP binary parsers (static review only; would need AFL/libFuzzer for the DoS-corner tail).

---

## 7. Are *we* better? (methodology delta vs. 2026-04-30)

| | April-30 run | This run (6.2.6) |
|---|---|---|
| Engine | `/agentic` (egress-proxy capped) | RAPTOR auto-research loop via Workflow (no egress path) |
| Analyses completed | 5 / 60 (egress cap) | ~50 agents, all completed |
| Altitude coverage | one band, RCE-only lens | all four altitudes × all bug classes × 5 rounds |
| Verification | none converged | adversarial judge + per-finding verifier + cross-function reconcile + completeness critic |
| Result | "no novel primitive beyond 34197" | 10+ verified net-new findings; 2 systemic root causes; 1 denylist variant; ~24 candidates correctly refuted |
| Lessons applied | — | `post-cve-sink-variant-reaudit` (→ C1), `map-then-trace-all-classes` (→ Theme A), `anonymous-read/authz-object-hunt` (→ Theme B), `enumerate-all-pre-auth-subsystems` (per-protocol tuples) |

We are better at *coverage and verification*. We are not "better" at finding a 6.2.6 unauth-RCE — because there is no easy one to find; the vendor closed them.

---

## 8. Recommendations (defensive)

1. **Output-encode identifiers in the web console** — wrap `${row.JMSMessageID}`/`${row.clientId}`/jobId in `<c:out>` (browse.jsp:51, queueConsumers.jsp, scheduled.jsp, graph.jsp). Keep the strict default CSP. *(Theme A root cause.)*
2. **Gate `removeSubscription` in `AuthorizationBroker` and key it on `context.getClientId()`** (or verify `info.getClientId()` == connection clientId). *(B1.)*
3. **Add `static` (and audit `nop`/`auto`/`ssl`/`tcp`-wrapping discovery schemes) to `DENIED_TRANSPORT_SCHEMES`**, or allow-list at the network-connector sink as VMTransportFactory does. *(C1.)*
4. **Canonicalize cert DNs** — migrate `getSubjectDN().getName()` → `getSubjectX500Principal().getName(RFC2253)`. *(B6.)*
5. **Reject empty-password user binds in `LDAPLoginModule`** before `bindUser`. *(B3.)*
6. **Bound parser inputs** — set a sane `wireFormat.maxFrameSize`; validate `QoS`/`AMQ_SCHEDULED_*` ranges; treat signed-`short` length fields as unsigned. *(Theme D.)*
7. **Harden the shipped sample config** — restrict write on `ActiveMQ.Statistics.*`/`ActiveMQ.Scheduler.Management`, add a restrictive `tempDestinationAuthorizationEntry`, ship auth on. *(B4/B5/B6, default posture.)*

---

## 9. Confidence & limitations

Static source review only (no live broker / PoC detonation this engagement). Confirmations are code-trace-level; the headline access-control findings (B1, C1) and the cert-trust ground truth (B6) were re-read by the orchestrator. Exploitability ratings state their config preconditions explicitly. The DoS cluster would benefit from an AFL/libFuzzer pass on the OpenWire/AMQP parsers to map the corner tail. PoC build + version-matrix validation is the recommended next step for B1 (durable-sub IDOR) and the Theme-A console injections, both of which are the most directly demonstrable.
