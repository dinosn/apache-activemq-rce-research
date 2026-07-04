# EXISTING FINDINGS — exclusion set for the 6.2.6 hunt

Target: Apache ActiveMQ Classic **6.2.6** (tag `activemq-6.2.6`, commit `bb9523b98`, released 2026-05-27).
Source: `/Users/krasn/tools/raptor/targets/activemq-6.2.6`.

This file is the dedup/exclusion set. A new candidate that matches one of these is **NOT net-new** —
it must be filed as "variant of X" with a concrete reason it differs, or dropped. The goal of this
hunt is net-new bugs and *variants past the patches below*, plus surface the prior runs never reached.

## Confirmed prior CVEs (already found by us or public; do not re-report as new)

| ID | Class | Sink / mechanism | Status in 6.2.6 |
|----|-------|------------------|------------------|
| CVE-2023-46604 | RCE | OpenWire `createThrowable` reflection (`tight/looseUnmarsalThrowable`) | Patched — `OpenWireUtil.validateIsThrowable` (`Throwable.isAssignableFrom`) |
| CVE-2015-5254 | Deser RCE | `ActiveMQObjectMessage.getObject` ObjectInputStream | Mitigated — `ClassLoadingAwareObjectInputStream` trusted-package filter |
| CVE-2022-41678 | JMX RCE | MBean dispatch (Log4J/JMX config) | class noted; see leads below |
| CVE-2024-32114 | Auth bypass | Jolokia/web console unauthenticated on 6.0.0–6.1.1 | Fixed in 6.1.2+ (6.2.6 requires auth) |
| CVE-2026-34197 | RCE | Jolokia `addNetworkConnector` → `vm://?brokerConfig=xbean:` → `ResourceXmlApplicationContext` Spring-bean RCE | Trigger guarded by `BrokerView.DENIED_TRANSPORT_SCHEMES` denylist |
| CVE-2026-42588 | RCE (patch-bypass of 34197) | no-paren `static:vm://EVIL?brokerConfig=xbean:...` — `URISupport.isCompositeURI` (needs `(`) disagrees with `parseComposite`, so inner `vm` never validated | **Patched in 5.19.7/6.x**: `VMTransportFactory.validateBrokerCreationSchema` allow-list (`broker,properties`) blocks `xbean` at the SINK |
| CVE-2026-42253 | Header injection / stored XSS | `MessageServlet.setResponseHeaders` copies attacker JMS property names/values into `response.setHeader` unsanitized; POST `appendParametersToMessage` sets the props | **Mitigated in 5.19.7/6.2.6**: `MessageServlet` `@Deprecated` + **disabled by default**. Sink code UNCHANGED — re-enabling reintroduces the bug |
| AMQ-9810 | DoS | MQTT/AMQP wireformat length parser overflow/infinite-loop | Patched (additional validation for MQTT wireformat + control packets) |

## Patched sinks worth VARIANT-HUNTING in 6.2.6 (per memory: variant-hunt the proven sink)

- **`ResourceXmlApplicationContext` / Spring-XML-from-URI** sink (34197/42588 endpoint). The 42588 fix
  is the `VMTransportFactory` allow-list at the sink. Hunt: any OTHER reach-path to
  `XBeanBrokerFactory.createBroker` / `ResourceXmlApplicationContext` / `spring/Utils.resourceFromString`
  that bypasses the allow-list — different transport factory, different scheme parser, config reload path.
- **`BrokerView.validateAllowedUri` denylist** — `isCompositeURI` vs `parseComposite` disagreement was the
  42588 root. Hunt: other places that parse composite/wrapper URIs with the same two-function mismatch,
  or new scheme wrappers (`failover:`, `fanout:`, `discovery:`, `masterslave:`, `static:`) reaching a
  broker-creating factory.
- **`response.setHeader(name, value)` from message properties** (42253). Hunt: every other servlet/REST
  path that echoes attacker-controlled JMS properties / destination names / selectors into headers, body
  (XSS), or logs (log injection) — `activemq-web`, `activemq-http`, web-console.
- **Deserialization filter** — `ClassLoadingAwareObjectInputStream` trusted packages. Hunt: any raw
  `ObjectInputStream` / `readObject` NOT routed through the filter; gadgets reachable inside trusted pkgs.

## Speculative leads from the April-30 run — RE-CHECK against 6.2.6 (were not exploited)

1. `Log4JConfigView.reloadLog4jProperties()` — `System.getProperty("log4j.configuration")` →
   `PropertyConfigurator.configure(URL)`; reachable via Jolokia. RCE only if paired with a
   System-property write primitive. Re-check: is the MBean still present/reachable; any setter primitive.
2. `DefaultAuthorizationMap.createGroupPrincipal(name, groupClass)` —
   `Class.forName(groupClass).getConstructor(String).newInstance(name)`, **no subclass/interface check**.
   `groupClass` is setter-controlled. Re-check: is `setGroupClass` JMX/remote-reachable.
3. OpenWire `Throwable` ctor side-effect gadgets — `validateIsThrowable` permits any `Throwable` subclass
   with a `(String)` ctor; full enumeration of side-effecting ctors on classpath not done.
4. **XStream HTTP tunnel** deserialization reachability (`activemq-http` `XStreamMessageBodyReader` /
   transport) — flagged "paper surface", never reached. Re-check default config in 6.2.6.
5. **KahaDB journal-write** attack surface — never reached.

## Surface the prior runs NEVER deeply analyzed (egress cap killed 55/60 analyses on 4/30)

The April-30 `/agentic` completed only 5/60 findings. Treat ALL of these as fresh ground:
STOMP, MQTT, AMQP frame parsers; JAAS/Shiro auth; LDAP authorization maps; JDBC store SQL;
scheduler (KahaDB JobSchedulerStore); runtime-config; web-console servlets/JSP; management/JMX;
network bridge/discovery; failover transport.

## Methodology gaps to apply this run (from memory)

- Variant-hunt every proven sink for alternate reach-paths (schemes / composite-URI / encodings).
- Trace EVERY mapped entry point for ALL bug classes (XSS / CRLF / SSRF / traversal / deser / SQLi /
  auth-bypass), not just the RCE headline.
- Map-then-trace: a mapped-but-untraced entry point is uncovered.
- Don't scope-lock after the first hit; broad re-audit is a separate pass.
- Enumerate full pre-auth surface: versions × auth mechanisms × transports × ancillary parsers.
- Hunt lifecycle/state-machine bugs, not just parser bugs.
