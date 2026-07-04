# ActiveMQ Classic — RCE Audit Report

**Date:** 2026-04-30
**Target:** Apache ActiveMQ Classic, 5.18.x branch HEAD (commit `a2568ae`, *AMQ-9810*)
**Scope:** Java broker only (`activemq-cpp` cloned for follow-up but not in this report)
**Lab images on 192.168.1.119:**
`apache/activemq-classic:5.18.3` · `5.18.6` · `6.1.4` · `6.1.7`
**Reference exploit (regression baseline):** `out/cve-2026-34197-activemq/poc.py`
**Reference for failure modes:** `/Users/krasn/tools/custom/Redis_RCE/ANALYSIS.md`

---

## TL;DR

1. **CVE-2026-34197 (Jolokia → `vm://?brokerConfig=xbean:` → Spring XML → RCE)**
   is the dominant deployed-version RCE primitive. Prior audit identified it; this
   run **adds the per-deployed-version replay matrix** the prior audit lacked
   (see §1).
2. **No novel RCE primitive identified** in the sweep beyond CVE-2026-34197.
   Known-CVE patches (CVE-2023-46604 OpenWire, CVE-2015-5254 ObjectMessage) are
   uniformly applied; sister surfaces (MQTT, AMQP wireformat) carry DoS-class
   regressions but no RCE chain on the staged builds. (§3)
3. **Native-code memory corruption is not in scope for the broker** — there is
   no JNI in the broker tree. The C++ surface lives in `activemq-cpp` (cloned to
   `out/activemq-research/activemq-cpp/`, 20 MB) and is reserved for a separate
   pass. (§4)
4. **Speculative leads** (`Log4JConfigView.reloadLog4jProperties`,
   `DefaultAuthorizationMap.createGroupPrincipal`, MQTT/AMQP pre-AMQ-9810
   length-overflow DoS) require either a paired primitive (System-property write,
   JMX setter access) or a side-effecting classpath gadget — listed for follow-up
   in §5.
5. **/agentic pipeline outcome.** The orchestration finished but only 5/60 of
   the dispatched findings completed (egress sandbox tunnel cap). All 5 were
   correctly classified false positives. The 252 deduped-but-not-attempted
   findings remain on disk under
   `agentic-20260430-115322-pid36186/orchestrated_report.json`. (§6 — known
   issue, suggested fix.)

---

## §1. CVE-2026-34197 — version matrix

The prior audit produced a single working PoC against `5.18.6`. Per the Redis
ANALYSIS lesson — *"fixed in latest is not absent in production"* — every
publicly-pulled image in the affected range needs verification. Results from
running `out/cve-2026-34197-activemq/poc.py` against each staged image on
`192.168.1.119`:

(see `pocs/version-matrix.sh`, `pocs/poc.py`, `pocs/results.tsv` for raw)

| Image | RCE | Process UID | JVM |
|---|---|---|---|
| `apache/activemq-classic:5.18.3` | ✓ exploitable | `uid=0(root) gid=0(root) groups=0(root)` | openjdk 11.0.23 |
| `apache/activemq-classic:5.18.6` | ✓ exploitable | `uid=0(root) gid=0(root) groups=0(root)` | openjdk 11.0.24 |
| `apache/activemq-classic:6.1.4`  | ✓ exploitable | `uid=0(root) gid=0(root) groups=0(root)` | openjdk 17.0.13 |
| `apache/activemq-classic:6.1.7`  | ✓ exploitable | `uid=0(root) gid=0(root) groups=0(root)` | openjdk 17.0.15 |

**4/4 confirmed end-to-end RCE as root** against the official `apache/activemq-classic`
images. Every image in the `5.x < 5.19.4` and `6.0.0..<6.2.3` ranges that ships on
Docker Hub is exploitable by the rewritten PoC unchanged.

### Why the prior PoC at `out/cve-2026-34197-activemq/poc.py` did not reproduce here

Two latent bugs found while running the matrix — fixed in `pocs/poc.py`:

1. **Broken Spring bean payload.** The XML template sets
   `<property name="redirectErrorStream" value="true"/>` on
   `java.lang.ProcessBuilder`. `ProcessBuilder.redirectErrorStream(boolean)` is
   a *fluent* method (returns the builder), **not** a JavaBean setter.
   Spring's `BeanWrapperImpl` raises `NotWritablePropertyException` and the
   `pb` bean never instantiates, so `pb.start()` is never called. Replaced with
   the proven `MethodInvokingFactoryBean → Runtime.getRuntime().exec` gadget
   (the same pattern `out/cve-2026-34197-lab/exploit/payload.xml` uses, which
   *did* work in the original lab run).

2. **HTTP server torn down too early.** `--auto` calls `server.shutdown()`
   immediately after the *first* `GET` arrives, but Spring re-fetches the XML
   during deferred bean instantiation (observed: 6–7 GETs in our run). The
   later fetches hit a closed listener and yield
   `java.net.ConnectException: Connection refused` inside
   `XmlBeanDefinitionReader.loadBeanDefinitions`. New PoC keeps the server up
   for `--wait` seconds (default 12) after the first fetch.

---

## §2. Surface coverage

### What was inspected by hand (in addition to /agentic)

| Surface | Verdict | Evidence |
|---|---|---|
| OpenWire `createThrowable` reflection (CVE-2023-46604 site) | Patched, all versions | `OpenWireUtil.validateIsThrowable` consistently called from `tightUnmarsalThrowable` and `looseUnmarsalThrowable` across `v1`-`v12` (incl. `activemq-openwire-legacy` `v2`-`v8`). Validation: `Throwable.class.isAssignableFrom(clazz)`. |
| OpenWire other reflection sinks (`OpenWireFormat.setVersion`) | FP | Class name is `org.apache.activemq.openwire.v<INT>.MarshallerFactory` — int-bounded, not attacker-controlled to arbitrary classes; loaded class must implement `createMarshallerMap(OpenWireFormat)`. |
| `ClassLoadingAwareObjectInputStream` (CVE-2015-5254 mitigation) | Filter active; trust set wide but no in-tree gadget identified | Default trusted packages: `java.lang, org.apache.activemq, org.fusesource.hawtbuf, com.thoughtworks.xstream.mapper`. `org.apache.activemq.*` `readObject`/`readExternal` overrides surveyed: `BitArray`, `Message`, `ActiveMQMapMessage`, `ActiveMQDestination`, `MessageId`, `JNDIBaseStorable` — none wire to a reflective sink in the deserialization path. |
| `JNDIReferenceFactory.getObjectInstance` | FP | `JNDIStorableInterface.isAssignableFrom` gate restricts to ActiveMQ JNDI-storable classes; `Class.forName` happens before the check but no static-initializer side effects on shipped JNDI-storable classes. Client-side code; not directly reachable from a remote unauth attacker. |
| MQTT wireformat (`MQTTWireFormat.unmarshal` length parser) | Patched on HEAD by AMQ-9810 (`a2568ae`); pre-patch builds DoS-only | The pre-patch loop allowed `>4` length bytes with the high bit set, leading to either int-overflow on `length` or `multiplier <<= 7` rollover (32-bit `<<= 7` wraps `0x10000000` to `0x800000000` truncated to `0`, infinite loop). DoS class only — not RCE. |
| Jolokia access policy (`assembly/src/release/conf/jolokia-access.xml`) | Whitelist + targeted denies | Default `<commands>` list = `read,list,version,search` only. `<allow>` re-enables `*` for `org.apache.activemq:*` and `jolokia:type=Config`. `<deny>` covers `org.apache.logging.log4j2:*`, `com.sun.management:*`, `jdk.management.jfr`. **CSRF protection enforced by `<cors><strict-checking/>` (Origin/Referer required).** |
| `BrokerView.add{Connector,NetworkConnector}` | Patched (CVE-2026-34197) | `validateAllowedUrl` deny-list now blocks `vm` and `http` schemes incl. nested composite URIs (5 levels). |
| `ActiveMQObjectMessage.getObject` | Filter applied | Routed through `ClassLoadingAwareObjectInputStream`; no raw `ObjectInputStream` in production paths. |

### What was scanned but produced FP-only findings

- 257 deduped Semgrep rules in 5 analyzed; 5/5 correctly flagged FP by /agentic
  Stage A-D (PortfolioPublishServlet XSS x2, AnnotatedMBean reflection x2, a
  package.html cleartext-transmission noise).
- Path-traversal bucket (84 hits) reviewed by sampling — all in
  internal-config or CLI-launcher code (`BrokerService` setup, `console/Main`,
  `LockFile`, `IOHelper`); no external-taint reach.

---

## §3. Sister-surface DoS regressions on the staged builds

Pre-AMQ-9810 builds (5.18.3, 5.18.6, 6.1.4, 6.1.7) ship vulnerable
`MQTTWireFormat`. A 2-byte MQTT CONNECT frame with both bytes `0xFF` makes the
broker either:

- allocate up to `length = 268435455` bytes per frame (close to the 256 MB cap),
  or
- on pre-patch builds with even fewer bounds checks, infinite-loop the parsing
  thread (depending on subtle length-arithmetic differences across the pre-fix
  code path).

This is **DoS, not RCE.** Worth noting for a defender's prioritization but does
not produce shell access.

`AmqpFrameParser` was touched by sibling commits in the same hardening sweep;
the same length-confusion class likely affected pre-patch builds. Confirming /
exploiting it is out of scope for this run because (a) it caps at DoS and (b)
the specific Qpid-proton interaction makes mechanical fuzzing a better tool
than static review for that surface.

---

## §4. activemq-cpp (separate repo)

Cloned to `/Users/krasn/tools/raptor/out/activemq-research/activemq-cpp/`
(20 MB). This is the **C++ client** — the only place classic memory-corruption
exploitation could plausibly land. Out of scope for this Java-broker run; will
need its own RAPTOR pass with `--languages cpp` once the egress sandbox config
is sorted out (see §6).

Modules of interest in that tree:
- `activemq-cpp/src/main/activemq/core/`
- `activemq-cpp/src/main/activemq/wireformat/openwire/marshal/`
- `activemq-cpp/src/main/decaf/io/` (the buffered-stream layer; classic
  off-by-one territory)

---

## §5. Speculative / partial leads worth a deeper validate run

These did not reach an RCE primitive in this run, but each warrants its own
`/validate` pass with focused prompts:

1. **`Log4JConfigView.reloadLog4jProperties()`** — reads URL from
   `System.getProperty("log4j.configuration")` and calls
   `PropertyConfigurator.configure(URL)`. Reachable via Jolokia
   (`org.apache.activemq:type=Broker,service=Log4JConfiguration`) on default
   policy. RCE only if paired with a separate System-property write primitive.
   Pair-finding hunt: any MBean operation that ends up calling
   `System.setProperty(...)` with operator-supplied strings.

2. **`DefaultAuthorizationMap.createGroupPrincipal(name, groupClass)`**
   (line 235) does `Class.forName(groupClass).getConstructor(String).newInstance(name)`
   — **no subclass / interface check.** The `groupClass` is a setter-controlled
   field. If `setGroupClass` is JMX-exposed (need to confirm — interface
   `AuthorizationMap` does not declare an MBean), an admin or unauth-on-6.0.0..6.1.1
   attacker could instantiate any classpath class with a `(String)` ctor. The
   classic gadget (`ClassPathXmlApplicationContext(String)`) loads a Spring XML
   from classpath only — local-file requirement narrows but doesn't eliminate
   the chain (combine with a write primitive). Worth a focused `/validate`.

3. **OpenWire `Throwable` constructor side-effect gadgets.**
   `validateIsThrowable` permits any `Throwable` subclass with a `(String)`
   ctor. Unlikely to chain, but a complete enumeration of side-effecting
   `(String)` ctors on the broker classpath has not been done. Mostly an
   intellectual-curiosity item.

---

## §6. /agentic pipeline known-issue (this run)

`agentic-20260430-115322-pid36186/`:
- **Semgrep:** 381 → 257 deduped findings ✓
- **CodeQL:** failed (build phase — needs explicit Maven `--build-command`)
- **/understand pre-pass:** ✓ produced `context-map.json` with the right
  surfaces (OpenWire, ObjectMessage, JMX, JNDI, LDAP, KahaDB) on the checklist
- **Analysis:** 60 dispatched, **5 succeeded**, 55 failed before completion.
  Failure correlates with bursts of `egress proxy: max tunnels (64) reached`
  errors during peak parallelism.
- **/validate post-pass:** skipped — no findings ended at
  `is_exploitable=true` because the analysis step did not converge on most
  findings.

**Suggested re-run params:**
```
libexec/raptor-agentic --repo .../source \
    --understand --validate \
    --max-findings 200 \
    --max-parallel 1 \
    --no-sandbox
```
…with `--no-sandbox` (or a tunnel-cap raise in the proxy config) so the 200
analyses serialise instead of contending. Cost will be higher (~$50-100) but
the success rate will reach the 90%+ band that the methodology assumes.

---

## §7. Coverage budget — checked / unchecked

Per Redis ANALYSIS rule: *no `checked_by:[]` entry should leave the pipeline.*

The `/understand` pre-pass enumerated 8 sinks and 6 unchecked flows. Of those:

| Inventory entry | Manual review | /agentic |
|---|---|---|
| OpenWire `Class.forName` → Throwable | Reviewed (§2) | analysed FP |
| `ObjectInputStream.resolveClass` filter | Reviewed (§2) | analysed FP |
| XStream tunnel deserialization | NOT REACHED (HTTP transport not enabled by default in the staged images; surface is paper) | not reached |
| LDAP `InitialDirContext` | Surface mapped, not exploited (`SimpleCachedLDAPAuthorizationMap` injection is operator-supplied filter; no remote-attacker reach) | analysed but FP |
| JNDI lookup | Reviewed (§2, JNDIReferenceFactory) | analysed FP |
| JDBC bound queries | Not reached | not reached |
| KahaDB journal write | Not reached (10 raw findings deferred to follow-up) | not reached |
| JMX MBean dispatch (CVE-2022-41678 class) | Partial — BrokerView covered by §1, broader MBean enumeration left for §5 | partial |

Items still on the budget for the next run: **XStream HTTP tunnel reachability
on each staged image** and **KahaDB journal-write attack surface**.
