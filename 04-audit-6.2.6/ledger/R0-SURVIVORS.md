# Round 0 survivors (pending adversarial verification) — ActiveMQ 6.2.6

34 survivors from 71 candidates across 18 slices. DoS-class catalogued but not headline (standing scope: RCE/auth-bypass/access-granting).

| id | class | sev | preauth | judge | file:line |
|----|-------|-----|---------|-------|-----------|
| openwire-marshalling-1 | Unbounded Allocation / Integer Overflow (DoS) | medium | true | real/0.85 | activemq-client/src/main/java/org/apache/activemq/util/MarshallingSupport.java:192-208 |
| openwire-marshalling-2 | Unbounded Recursion / Stack Overflow (DoS) | medium | true | real/0.8 | activemq-client/src/main/java/org/apache/activemq/util/MarshallingSupport.java:211-215 |
| openwire-marshalling-3 | Integer Sign Extension / NegativeArraySizeException (DoS) | low | true | real/0.8 | activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:293-295 |
| openwire-marshalling-4 | Unbounded Recursion / Stack Overflow (DoS) | low | true | real/0.78 | activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:547 |
| openwire-marshalling-5 | Missing Bounds Check / ArrayIndexOutOfBoundsException (DoS) | low | true | real/0.78 | activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:562 |
| openwire-marshalling-6 | NullPointerException in marshalling path (DoS — broken ExceptionResponse dispatch) | low | true | real/0.65 | activemq-client/src/main/java/org/apache/activemq/openwire/v1/BaseDataStreamMarshaller.java:656 |
| openwire-legacy-1 | Integer/Length Overflow (signed-short misuse) | low | true | real/0.9 | activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java:292-294 |
| openwire-legacy-2 | Integer/Length Overflow (signed-short misuse) | low | true | real/0.9 | activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java:197 |
| openwire-legacy-3 | Unbounded Allocation / Infinite Loop | low | true | real/0.82 | activemq-openwire-legacy/src/main/java/org/apache/activemq/openwire/v2/BaseDataStreamMarshaller.java:220 |
| openwire-legacy-4 | Integer/Length Overflow (signed-short array index) | low | true | real/0.85 | activemq-client/src/main/java/org/apache/activemq/openwire/OpenWireFormat.java:565 |
| openwire-legacy-5 | Auth/Authz Bypass (informational / attack surface widening) | informational | true | uncertain/0.8 | activemq-client/src/main/java/org/apache/activemq/transport/WireFormatNegotiator.java:141-145 |
| stomp-1 | Integer parsing / length confusion leading to unbounded heap allocation (DoS) | High | true | real/0.85 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/StompCodec.java:97-124 |
| stomp-2 | Missing input validation — negative integer passed to array allocation | Medium | true | real/0.85 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/StompWireFormat.java:284-300, 143-146 |
| stomp-3 | Privilege escalation via reflection-based property injection — attacker-controlled ConsumerInfo flag alters ACK semantics | Medium | ? | uncertain/0.6 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/ProtocolConverter.java:624 |
| stomp-4 | STOMP protocol response splitting / header injection (cross-client) | Low | ? | real/0.7 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/StompWireFormat.java:303-333, 77-93 |
| stomp-5 | Header injection / STOMP frame splitting — unencoded key in outbound marshal | Medium | ? | real/0.7 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/StompWireFormat.java:82-87 |
| stomp-7 | Information disclosure — internal stack traces sent to remote clients | Low | ? | real/0.7 | activemq-stomp/src/main/java/org/apache/activemq/transport/stomp/ProtocolConverter.java:312-316 |
| mqtt-1 | Integer truncation / authentication bypass (resource exhaustion) | Medium | true | real/0.82 | activemq-mqtt/src/main/java/org/apache/activemq/transport/mqtt/MQTTProtocolConverter.java:687-723 |
| mqtt-3 | Unchecked array index / cross-protocol DoS | Medium | ? | real/0.83 | activemq-mqtt/src/main/java/org/apache/activemq/transport/mqtt/MQTTProtocolConverter.java:584-586 |
| amqp-1 | Unbounded allocation / integer type mismatch | High | true | real/0.85 | activemq-amqp/src/main/java/org/apache/activemq/transport/amqp/AmqpFrameParser.java:81-88, 217-225 |
| amqp-2 | Unbounded allocation / integer type mismatch | Medium | ? | real/0.8 | activemq-amqp/src/main/java/org/apache/activemq/transport/amqp/protocol/AmqpAbstractReceiver.java:108-115 |
| transport-1 | Server-Side Request Forgery (SSRF) | medium | true | uncertain/0.6 | activemq-client/src/main/java/org/apache/activemq/transport/discovery/multicast/MulticastDiscoveryAgent.java:468 |
| transport-3 | Improper Input Validation / Property Injection (CWE-20) | low | true | uncertain/0.55 | activemq-broker/src/main/java/org/apache/activemq/broker/TransportConnection.java:1386-1391 |
| http-transport-2 | Incorrect Comparison / Security Check Bypass (CWE-697) | medium | true | uncertain/0.7 | activemq-http/src/main/java/org/apache/activemq/transport/http/HttpTunnelServlet.java:127 |
| http-transport-3 | SSRF via Stored Injection (CWE-918 / CWE-20) | high | true | uncertain/0.68 | activemq-http/src/main/java/org/apache/activemq/transport/discovery/http/DiscoveryRegistryServlet.java:44 |
| web-console-1 | Stored Cross-Site Scripting | High | ? | real/0.8 | activemq-web-console/src/main/webapp/browse.jsp:51 |
| web-console-3 | Reflected Cross-Site Scripting | Low | ? | uncertain/0.6 | activemq-web-console/src/main/webapp/test/index.jsp:44 |
| web-console-5 | Sensitive Information Disclosure | Low | ? | real/0.75 | activemq-web-console/src/main/webapp/test/systemProperties.jsp:41-42 |
| console-jolokia-2 | Sensitive data exposure via JMX read (CWE-200) | low | ? | real/0.6 | assembly/src/release/conf/jolokia-access.xml:134-152 |
| jaas-1 | Authentication Bypass (CWE-287 / CWE-521) | high | true | real/0.7 | activemq-jaas/src/main/java/org/apache/activemq/jaas/LDAPLoginModule.java:127-130, 307, 428-460 |
| shiro-1 | Authorization Bypass (Permission Escalation) | Medium | ? | uncertain/0.6 | activemq-shiro/src/main/java/org/apache/activemq/shiro/authz/DestinationActionPermissionResolver.java:261 |
| authz-maps-2 | Authorization Bypass / Stale Cache | Medium | ? | uncertain/0.6 | activemq-broker/src/main/java/org/apache/activemq/security/AuthorizationBroker.java:66-67 |
| client-core-1 | SSRF | high | ? | uncertain/0.6 | activemq-client/src/main/java/org/apache/activemq/blob/DefaultBlobDownloadStrategy.java:43-59 |
| client-core-2 | Path Traversal | medium | ? | real/0.72 | activemq-client/src/main/java/org/apache/activemq/blob/FileSystemBlobStrategy.java:134-135 |
