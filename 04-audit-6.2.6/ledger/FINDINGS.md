# FINDINGS — confirmed/surviving findings, ActiveMQ 6.2.6 hunt

A finding lands here only after: independent generator proposed it → separate judge (from raw) failed to
refute it → live-verified against 6.2.6 source. Each entry is the dedup key for future rounds.

Status enum (RAPTOR): exploitable | confirmed | suspicious | ruled_out | needs-verify.

### Live-verified by orchestrator (harness-level read, pending R1a corroboration)

**F1 — jaas-1 — LDAPLoginModule empty-password → unauthenticated/anonymous LDAP bind = auth bypass.**
`activemq-jaas/.../LDAPLoginModule.java`. login() (127-134): null/empty PasswordCallback → `password=""`, passed to `authenticate()` with NO emptiness guard. authenticate() (307) → bindUser() (428): sets `SECURITY_AUTHENTICATION=simple`, `SECURITY_CREDENTIALS=""`, then `context.getAttributes("",null)` (437) → on a directory that accepts unauthenticated simple binds (RFC 4513 §5.1.2; JNDI sends an *anonymous* bind for empty creds), `isValid=true` (438) → authenticated as the victim DN with no password. The only `"Empty password is not allowed"` guard (≈line 498) is in openContext() for the SERVICE-account bind, not the user path. Class: CWE-287 auth-bypass. Reachable: pre-auth (any OpenWire/STOMP/MQTT/AMQP ConnectionInfo with username + empty password). **Exploitability: conditional** — requires (a) LDAPLoginModule configured (NON-default; ships PropertiesLoginModule, JAAS plugin commented out in default activemq.xml), and (b) directory allowing anonymous bind / anon-readable attrs. Confirmed present by orchestrator read 2026-06-21.

**F2 — web-console-1 — stored XSS via unescaped JMSMessageID in browse.jsp.**
`activemq-web-console/src/main/webapp/browse.jsp:51`: `...>${row.JMSMessageID}</a>` rendered RAW (EL), while every sibling cell uses escaping `<c:out>` (lines 52-58). JMSMessageID is client-influenceable: an OpenWire producer chooses `connectionId` (ConnectionInfo) and ProducerId components that compose `MessageId.toString()`. A malicious producer with queue-write can embed markup → executes in the admin's browser when they Browse that queue in the web console. Class: stored XSS (CWE-79). Reachable: post-auth producer → admin-viewing-console. Net-new vs CVE-2026-42253 (that was MessageServlet, now disabled). Sink confirmed by orchestrator read 2026-06-21; attacker-control of JMSMessageID to be PoC-confirmed.

**F1 update (R1a):** verifier concurs the mechanism is present; downgrades exploitability to **uncertain/conditional** — doubly config-gated (non-default LDAPLoginModule + directory accepting empty-password/anonymous simple binds). Real missing-guard defect; exploitability conditional.

**F2 update (R1a):** confirmed unescaped sink + a cleaner attacker-control path than connectionId — **`MessageId.textView`** (OpenWire v10+ wire field) round-trips & persists, and `MessageId.toString()` returns `"ID:"+textView`. **CSP caveat:** default `jetty.xml` ships `Content-Security-Policy: default-src 'none'; script-src-elem 'self'` (no unsafe-inline) which **blocks inline `<script>`/event-handler execution by default** → under stock config this is **HTML/content injection** (defacement, phishing link in admin console), NOT full JS XSS. Full script-XSS is conditional on the operator weakening CSP. net-new vs 42253.

### F3 — client-core-2 — path traversal in FileSystemBlobStrategy via MessageId.textView (CONFIRMED, client-side)
`activemq-client/.../blob/FileSystemBlobStrategy.java:134` — `new File(rootFile, message.getJMSMessageID().replaceAll(":","_"))`; only colons stripped, `../` survives (no canonicalize). A hostile/MITM broker sets `MessageId.textView="../../../../etc/passwd"` (v10+ wire field) → arbitrary file **read** (getInputStream→FileInputStream) and **write** (uploadStream→FileOutputStream) on the CLIENT. **Conditional**: requires hostile/MITM broker + client uses BLOB feature + `file://` upload baseline (default is http). CWE-22. net-new. Same root cause as F2 (attacker-controlled `MessageId.textView`).

### F4 — mqtt-3 — cross-protocol force-disconnect via ActiveMQ.MQTT.QoS (CONFIRMED, DoS)
`activemq-mqtt/.../MQTTProtocolConverter.java:586` — `qoS = QoS.values()[ordinal]` with no bounds check; `ordinal` from JMS int property `ActiveMQ.MQTT.QoS` settable by any OpenWire/STOMP/AMQP producer. ordinal 3/-1/MAX → AIOOBE → IOException → MQTT subscriber force-disconnected; repeat = persistent DoS. MQTT enabled by default; no special config. **DoS-class (out of headline scope; catalogued).** net-new. Cross-protocol-only (MQTT→MQTT safe).

### F5 — stomp-5 — STOMP header-NAME injection / frame splitting (CONFIRMED, conditional, low)
`activemq-stomp/.../StompWireFormat.java:83` — outbound header KEY `buffer.append(entry.getKey())` is NEVER escaped (only the VALUE gets version-aware escaping). A JMS property NAME containing `\n` (set by an OpenWire/AMQP producer; `setObjectProperty` rejects only null/empty names, no control-char check) splits the MESSAGE frame delivered to a co-tenant STOMP subscriber → spoofed headers in that client. **Conditional**: STOMP connector enabled (non-default) + shared destination. Client-side impact, not broker compromise. Low.

### F6 — transport-1 — MulticastDiscoveryAgent SSRF (CONFIRMED, conditional)
`activemq-broker/.../transport/discovery/multicast/MulticastDiscoveryAgent.java:420` → `DiscoveryNetworkConnector.onServiceAdd:132 TransportFactory.connect(attacker_uri)` with no scheme/host validation (connectionFilter null by default). A UDP datagram to the multicast group with `default.ActiveMQ-4.alive.%name%tcp://attacker:port` makes the broker dial arbitrary TCP. **Conditional**: requires non-default `<networkConnector uri="multicast://...">`. SSRF (broker-side); RCE escalation not demonstrated. Borderline scope.

### Uncertain — kept for Round 2 verification
- **shiro-1** — authz verb-escalation via colon-injection of destination name into Shiro WildcardPermission string (conditional; needs Shiro plugin). Re-verify R2.
- **stomp-4** — STOMP 1.0 header-VALUE injection (by-design, STOMP 1.0 has no escaping). Low/by-design.
- **web-console-5** — `test/systemProperties.jsp` renders all JVM sysprops (admin-only). Info-disclosure, low.

## Rejected set (judge-refuted or live-verify-failed) — do not resurface

- **stomp-3** — networkSubscription property injection: claimed "ACK without removal/duplication/priv-esc" DISPROVEN — `acknowledge()`+`dropMessage()` run BEFORE the networkSubscription-gated `messages.rollback()`, and rollback only clears the cursor duplicate-audit (not re-queue). By-design `activemq.*` header reflection. Not net-new.
- **transport-3** — BrokerInfo networkProperties injection: refuted (not attacker-reachable as claimed pre-auth in default/standard setup).
- **http-transport-2** — maxFrameSize chunked-encoding bypass: refuted.
- **http-transport-3** — DiscoveryRegistryServlet SSRF: not-reachable (servlet not wired in default).
- **web-console-3** — reflected XSS in test/index.jsp: refuted (not reachable / not as claimed).
- **console-jolokia-2** — NetworkConnectorView UserName via Jolokia: refuted (admin-only, by-design read).
- **client-core-1** — SSRF via BrokerInfo.brokerUploadUrl: refuted (not an SSRF as claimed).

### F7 — scheduler-idor — cross-tenant scheduled-job IDOR (orchestrator-confirmed, pending R2 corroboration)
`activemq-broker/.../broker/scheduler/SchedulerBroker.java:251-285`. `send()` dispatches management actions from attacker message properties on `ActiveMQ.Scheduler.Management`: BROWSE → `scheduler.getAllJobs()` (no per-user filter; job payloads written to attacker replyTo → cross-tenant disclosure); REMOVE → `scheduler.remove(jobId)` (attacker-chosen id, no ownership check); REMOVEALL → `scheduler.removeAllJobs()` (destroys all tenants' jobs). The scheduler store is a SINGLE shared "JMS" namespace with NO owner concept — only gate is send-ACL to the management queue. Class: broken-object-level-authz / IDOR (CWE-639) + destructive. **Conditional**: requires `schedulerSupport=true` (NOT broker default) + user has send access to ActiveMQ.Scheduler.Management. Confirmed mechanism by orchestrator read 2026-06-21.

## R1b survivor catalogue (pending R2a verify) — see rounds/R1b-survivors.json
- **authz-idor-1** (HIGH, verifying R2a) — temp-destination authz fail-open → cross-connection temp-queue hijack. Strongest access-control lead.
- **broker-plugins-1/2/3** (StatisticsBroker, conditional on plugin) — reset-stats without role check; cross-subscriber clientId/connectionId/selector disclosure; datadir-path + connector-URI leak.
- **cross-protocol-injection-2** — STOMP→AMQP JMS_AMQP_* metadata spoofing on AMQP consumers.
- **network-bridge-1** — BrokerInfo.networkProperties syncDurableSubs injection → durable-sub topology disclosure.
- **web-jsp-sweep-1** — stored XSS in scheduled.jsp via jobId (same injected-identifier family as F2).
- **config-default-secrets-1** (HIGH, known by-design) — default activemq.xml ships auth commented out → pre-auth full queue access; **-2** default web-console creds; **-4** weak PBEWithMD5AndDES + default key 'activemq'; **-3** non-constant-time pw compare; **-5** missing cookie Secure/SameSite.
- **management-rmi-jmx-1** — JMX RMI connector without auth/TLS when createConnector=true (conditional).
- DoS-class (catalogued): scheduler-2 (cron */0 div-by-zero), scheduler-3 (negative-repeat immortal job), broker-plugins-4 (log injection).

### F8 — web-jsp-sweep-1 — stored XSS in scheduled.jsp via injected identifier (CONFIRMED, R2a)
`activemq-web-console/src/main/webapp/scheduled.jsp:56` emits `href="deleteJob.action?jobId=${row.jobId}..."` where jobId = `MessageId.toString()`. An attacker sets OpenWire `ConnectionInfo.connectionId` to a string with a `"` (e.g. `ID:x" data-x="y`) — propagates into MessageId → jobId → breaks out of the href attribute → stored XSS when an admin opens scheduled.jsp. Conditional (schedulerSupport=true). **Second confirmed sink of the same root cause as F2** (attacker-controlled identifier strings — connectionId/MessageId.textView — reflected unescaped in console JSPs). net-new. CWE-79.

### F9 — shiro-1 — authz verb-escalation via colon-injection in destination name (CONFIRMED, R2a)
`activemq-shiro` DestinationActionPermissionResolver builds a Shiro `WildcardPermission` string `queue:<name>:<action>` using the destination physical name, where `:` is ALSO the WildcardPermission part separator. A user granted `queue:ACCOUNTING:read` (3 parts) sending to a queue physically named `ACCOUNTING:read` produces required perm `queue:ACCOUNTING:read:write` (4 parts); Shiro `.implies()` returns true at part index 3 → **write granted despite a read-only grant**. Authz bypass (CWE-863). Conditional (activemq-shiro wired — non-default). net-new. Clean logic bug.

### Catalogued (R2a-confirmed, lower/DoS or by-design-hardening)
- **scheduler-3** (CONFIRMED, DoS) — negative `AMQ_SCHEDULED_REPEAT` via raw OpenWire → repeat counter never decrements → job fires forever. Conditional (schedulerSupport=true). Out of headline scope (DoS).
- **authz-idor-1** (UNCERTAIN→hardening) — temp-destination authz fail-OPEN (null ACL passes) vs non-temp fail-CLOSED — a real asymmetry, but documented intended ownership-transfer (AMQ-4721, 2012) with documented mitigation `tempDestinationAuthorizationEntry`. Report as hardening/defense-in-depth, not net-new code defect.
- **broker-plugins-2** (UNCERTAIN) — StatisticsBroker subscriber-info disclosure; conditional on plugin+write-ACL; by-design plugin output.

### Rejected in R2a (do not resurface)
- broker-plugins-1 (reset-stats is by-design + write-ACL gated, telemetry-only), broker-plugins-3 (not reachable, plugin absent by default), cross-protocol-injection-2 (refuted), network-bridge-1 (theoretical), scheduler-2 (cron */0 — refuted), management-rmi-jmx-1 (createConnector OFF by default).

### F10 — authz-idor-deep-1 — cross-clientId durable-subscription deletion IDOR (orchestrator-confirmed, R3 corroborating)
`activemq-broker/.../broker/region/TopicRegion.java:212` — `removeSubscription()` builds `new SubscriptionKey(info.getClientId(), info.getSubscriptionName())` from the **wire-supplied** `RemoveSubscriptionInfo.clientId`, NOT the authenticated `context.getClientId()` (contrast lines 125/195/338 which correctly use context). AND `AuthorizationBroker` overrides `addConsumer/addProducer/send/removeDestination/...` but **NOT `removeSubscription`** — so there is no ACL gate. Any authenticated user (or any user if auth disabled) can delete another tenant's durable subscription by supplying the victim clientId+subscriptionName → victim loses durable message delivery. Class: broken-object-level-authz / IDOR (CWE-639), destructive. net-new. Reachable post-auth-user (pre-auth if no auth). Matches the classic gate-context-then-act-on-attacker-key pattern. Confirmed by orchestrator read 2026-06-21.

## R2b survivor catalogue (R3 verifying)
- **scheduler-idor-1** (= F7) confirmed by R3 hunt + orchestrator read.
- **Identifier-injection root cause — additional sinks** (all consume attacker-controlled JMSMessageID/connectionId/clientId): messageid-textview-sinks-2 `graph.jsp` href attribute-breakout XSS; messageid-textview-sinks-1 `MessageServlet` `setHeader("id", JMSMessageID)` HTTP header injection (servlet disabled by default); messageid-textview-sinks-3 `RssMessageRenderer` link corruption; default-config-confirm-1 `queueConsumers.jsp` `${row.clientId}` stored XSS. Theme A now spans browse.jsp/scheduled.jsp/graph.jsp/queueConsumers.jsp + MessageServlet header + Rss/blob.
- **jmx-direct-sink-1** — `static:` scheme NOT in `DENIED_TRANSPORT_SCHEMES` → `addNetworkConnector("static:(tcp://attacker)")` → broker SSRF. Variant past the 34197/42588 denylist; admin/JMX-reachable.
- **plugin-authz-chain-1** — StatisticsBroker `next.send()` may bypass write-ACL (R3 reconciling vs R2a's refutation).
- **plugin-authz-chain-2** — DestinationsPlugin newline → unintended destination on restart (low).

### R3 verification outcomes
- **F10 — durable-sub IDOR — CONFIRMED (medium, net-new).** R3 + orchestrator agree.
- **F11 — jmx-direct-sink-1 — `static:` denylist gap → broker SSRF — CONFIRMED (medium, net-new, admin/JMX-reachable).** `static` is absent from `BrokerView.DENIED_TRANSPORT_SCHEMES`, so `addNetworkConnector("static:(tcp://attacker:port)")` reaches DiscoveryNetworkConnector → outbound TCP. Variant past the 34197/42588 fix (the denylist guards the trigger, this scheme slips it). Not RCE (static→tcp, not vm→xbean), SSRF only.
- **F12 — default-config-confirm-1 — `queueConsumers.jsp` stored XSS via `${row.clientId}` — CONFIRMED (low, net-new).** Another Theme-A sink (attacker-controlled clientId, write-side pre-auth on default-no-auth broker; full JS-exec gated by default CSP).
- **F13 — plugin-authz-chain-2 — DestinationsPlugin newline → unintended destination on restart — CONFIRMED (low, net-new, config-gated).**
- **F7 DOWNGRADED:** scheduler "IDOR" REFUTED as a vuln — ActiveMQ scheduler is single-tenant **by design**; the management API is documented and access is gated by the write-ACL on `ActiveMQ.Scheduler.Management`; disabled by default. Keep as a **hardening note** (restrict write to the scheduler management topic), not a net-new defect.
- **StatisticsBroker write-ACL bypass (plugin-authz-chain-1):** CONDITIONAL — bypass exists **iff** `statisticsBrokerPlugin` is listed before `authorizationPlugin` in `<plugins>` (so it sits below it in the filter chain). Real but config-order-dependent + plugin non-default. Hardening note.
- Refuted: MessageServlet "id" header (undeployed by default + Jetty 11 CRLF rejection), RssMessageRenderer link (not-exploitable), graph.jsp (uncertain, CSP-blocked default).

### Completeness critic — comprehensive=TRUE; residual never-sliced cells → Round 4
1. **CertificateLoginModule / TextFileCertificateLoginModule DN-matching** — `getSubjectDN().getName()` (deprecated, non-canonical) matched exact/regex → cert identity confusion / auth bypass. PRE-AUTH, in-scope, never sliced. **Top R4 lead.**
2. **AMQP SASL ANONYMOUS** — does it slip a null-user past an installed JaasAuthenticationBroker? (auth-bypass tuple).
3. **RuntimeConfigurationBroker hot-reload** — second-order connector/bean creation bypassing BrokerView denylist (34197-analog reach-path). RCE-class lead.
4. **XPath/XQuery selector → broker-side XML parse of attacker body** — sysprop-reenable XXE + entity-expansion DoS.
5. OpenWire `DEFAULT_MAX_FRAME_SIZE=Long.MAX_VALUE` pre-auth alloc DoS (catalogue).

Supply-chain CLEAN (Spring 6.2.18, Jetty 11.0.26, Jackson 2.21.1, log4j 2.25.4, commons-collections 3.2.2-safe, qpid-proton 0.34.1); XXE hardened by default; deser hardened (R0-gt2).

### R4 outcome + CONVERGENCE
R4 (critic residual cells) = thinning round: 16 cand → 3 survivors, all `cert-login-dn` (DN non-canonical collision High-but-conditional [TLS validates trust first → no self-signed bypass]; regex HashMap race; regex null-cache policy bypass — all cert-module-non-default). The three RCE/auth-bypass-class leads ALL REFUTED: amqp-sasl-anon (real auth plugin rejects null-user), runtimeconfig-reload (needs activemq.xml write=already-owned / admin Jolokia), xpath-XXE (hardened default; sysprop-reenable=privileged).

**CONVERGED after 5 rounds** (R0-R4): critic comprehensive=TRUE + thinning round + all in-scope RCE/auth-bypass leads refuted. No clean unauth-RCE on par with 34197/42588 (6.2.6 closed them). 10+ verified net-new lower-severity findings in the SAME families (console-injection / authz-model) + 1 denylist variant (static: SSRF). ~24 candidates refuted by the pipeline.

**→ Full writeup: `FINAL-REPORT.md`.** Headline confirmed net-new: B1 durable-sub IDOR (Med), C1 static: SSRF (Med, admin), Theme-A console injection cluster (Low, identifier root cause), F3 blob path-traversal (Med client-side), B2 Shiro colon-bypass, B3 LDAP empty-password, F4 cross-proto MQTT-QoS DoS.

---

## Ground-truth on 6.2.6 (verified by direct read, 2026-06-21)

- **34197/42588 chain closed by default (two layers):** `BrokerView.validateAllowedUri` (BrokerView.java:615) parses composites with `URISupport.parseComposite` and recurses components (kills the 42588 no-paren `isCompositeURI` bypass); `DENIED_TRANSPORT_SCHEMES`={vm,http,multicast,zeroconf,discovery,fanout,mock,peer,failover,proxy,reliable,simple,udp,masterslave}. Sink layer: `VMTransportFactory` allow-list `DEFAULT_ALLOWED_SCHEMES="broker,properties"` (VMTransportFactory.java:52) rejects `xbean` brokerConfig. Bypass requires operator misconfig `org.apache.activemq.transport.VM_TRANSPORT_FACTORY_SCHEMES_ENABLED=*` → hardening note, not a new bug.
- **42253:** `MessageServlet` `@Deprecated`, "keep it disabled" (MessageServlet.java:55-57); `setResponseHeaders` sink (line 379) UNCHANGED → re-enabling reintroduces it.
- **Lead#1 closed:** `Log4JConfigView.reloadLog4jProperties` (line 204) → `doReloadLog4jProperties` just reflectively calls log4j2 `LogManager.getContext(false).reconfigure()` — no attacker-supplied URL/property. Closed by log4j2 migration.

## Rejected set (judge-refuted or live-verify-failed) — do not resurface

_None yet._
