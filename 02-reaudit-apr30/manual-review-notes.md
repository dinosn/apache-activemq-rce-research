# ActiveMQ Classic — Manual Review Notes (parallel to /agentic run)

Run: `agentic-20260430-115322-pid36186` on `activemq-5.18.x` HEAD (`a2568ae` AMQ-9810)

## Reference / failure-mode prophylaxis (from out/redis-research analysis)

- The prior Redis audit dropped HLL functions with `checked_by:[]` from validate.
- Single-version "fixed in latest" framing → false comfort for deployed versions.
- Coverage budget enforcement is mandatory.
- For protocol-parsing / wireformat targets, manually inject memory-corruption /
  encoding / allocator prompts at validate.

## What's NOT in scope (ruled out by inspection)

| Class | Why ruled out |
|---|---|
| Native heap/stack overflow in broker | No JNI in tree. `wrapper.so/.dll` is Tanuki Java Service Wrapper, not broker logic. C++ only in `assembly/src/release/examples/` (client examples). |
| Original CVE-2023-46604 OpenWire reflection | `OpenWireUtil.validateIsThrowable` is uniformly applied across v1–v12 marshallers (incl. `activemq-openwire-legacy` v2-v8). Both `tightUnmarsalThrowable` and `looseUnmarsalThrowable` route through the gated `createThrowable` helper. |
| MQTT "remaining length" int-overflow infinite loop | Patched on `activemq-5.18.x` HEAD by AMQ-9810 (commit `a2568ae`, 2025-11-21): `MQTTWireFormat.unmarshal` now throws if `multiplier == MAX_MULTIPLIER && (digit & 0x80) != 0`. **All releases prior to that commit are still affected — `5.18.6` and `6.1.7` images we staged ship the vulnerable code.** Affects DoS only (memory/CPU exhaustion); not RCE. |
| `ActiveMQObjectMessage` deserialization (CVE-2015-5254 baseline) | Always reads via `ClassLoadingAwareObjectInputStream`. Raw `ObjectInputStream` only appears in test code. |

## Open / partially-checked surfaces (priority for /agentic + /validate)

### 1. Jolokia exec on ActiveMQ MBeans beyond `BrokerView`

CVE-2026-34197 patch added `validateAllowedUrl` only to
`BrokerView.addNetworkConnector` and `BrokerView.addConnector`. The Jolokia
policy `assembly/src/release/conf/jolokia-access.xml` allows `*` operations on
`org.apache.activemq:*` (only log4j2 / sun-management MBeans are denied). So 29
MBean classes in `activemq-broker/src/main/java/org/apache/activemq/broker/jmx/`
remain reachable.

**Of immediate interest** (need closer review):

- `Log4JConfigView.reloadLog4jProperties()` — calls `PropertyConfigurator.configure(URL)` with URL from `System.getProperty("log4j.configuration")`. Direct attacker control requires a separate System-property write primitive, but this is exactly the kind of "second-stage gadget" that pairs with any other prop-set bug.
- `Log4JConfigView.setLogLevel(String, String)` — uses reflection (`Configurator.setLevel`); unlikely RCE on its own but loads classes by reflection.
- `BrokerView.addQueue/addTopic/createDurableSubscriber` — destination-name strings; check whether any sub-URI parsing is reachable (composite destinations `composite:queue1,queue2`?).

### 2. Deserialization trust scope

`ClassLoadingAwareObjectInputStream` default trust set:
```
java.lang, org.apache.activemq, org.fusesource.hawtbuf,
com.thoughtworks.xstream.mapper
```

`org.apache.activemq` is trusted *in full*. Custom `readObject` /
`readExternal` exists in:

| Class | Behavior on deserialization |
|---|---|
| `org.apache.activemq.util.BitArray` | calls `readFromStream(in)` — read-only deserialize, no reflection |
| `org.apache.activemq.command.Message` | needs review |
| `org.apache.activemq.command.ActiveMQMapMessage` | needs review |
| `org.apache.activemq.command.ActiveMQDestination` | needs review |
| `org.apache.activemq.command.MessageId` | needs review |
| `org.apache.activemq.jndi.JNDIBaseStorable` | reads a `Properties` from stream and calls `setProperties` → abstract `buildFromProperties`. Subclasses include `ActiveMQConnectionFactory`. Cast-gated by `(Properties)` so generic gadgets blocked, but worth checking the `Properties` `defaults` chain and whether any subclass `buildFromProperties` does anything with a class-name-shaped value. |

### 3. XStream HTTP tunnel

`activemq-http` exposes `/api/message`-style servlets that historically
deserialize via XStream. `com.thoughtworks.xstream.mapper` is in the trust
list. Need to verify:
- whether the HTTP transport is enabled by default in the docker images we
  staged (5.18.3, 5.18.6, 6.1.4, 6.1.7),
- which `XStream` security framework version is used and whether the default
  blocklist covers known gadget chains.

### 4. AMQP frame parser

`AmqpFrameParser` was touched by AMQ-9810 sibling commits. Same length-confusion
class as MQTT — needs comparable bound-check audit on the AMQP performative
size fields. Lower priority because AMQP parsing on ActiveMQ depends on Qpid
proton library quality, but the frame-size dispatch in `AmqpFrameParser` is
ActiveMQ's own code.

### 5. `activemq-cpp` (separate repo, cloned to `out/activemq-research/activemq-cpp/`)

The C++ client. ~20MB of native code — actual heap/stack bug surface. Out of
scope for the Java broker pipeline run. Will be scanned separately in a
follow-up Semgrep + manual sweep targeting the OpenWire C++ marshallers.

## Per-version test matrix (from staged docker images on 192.168.1.119)

| Version | Pre/post CVE-2026-34197 fix (5.19.4 / 6.2.3) | Pre/post AMQ-9810 |
|---|---|---|
| 5.18.3 | pre — vulnerable to Jolokia `vm://` chain | pre — vulnerable to MQTT len overflow |
| 5.18.6 | pre — vulnerable to Jolokia `vm://` chain | pre — vulnerable to MQTT len overflow |
| 6.1.4  | pre — vulnerable to Jolokia `vm://` chain | pre — vulnerable to MQTT len overflow |
| 6.1.7  | pre — vulnerable to Jolokia `vm://` chain | pre — vulnerable to MQTT len overflow |

(Per Redis-audit lesson: validate must run against each deployed image, not
just `master`.)
