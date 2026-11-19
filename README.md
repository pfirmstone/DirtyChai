# Dirty Chai

**A community fork of OpenJDK that retains and advances Authorization (SecurityManager) functionality.**
**Last Reviewed:** 2026-04-22

> ⚠️ **Security Notice**: Dirty Chai is a specialized implementation targeting enterprise, regulated-industry, and high-security deployments. It is not a drop-in replacement recommended for all use cases. Evaluate carefully for your specific requirements before adopting in production.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Building](#building)
- [Key Features](#key-features)
- [JGDMS Compatibility](#jgdms-compatibility)
- [Principle of Least Privilege Policy Writer](#principle-of-least-privilege-policy-writer)
- [Deploying with SecurityManager](#deploying-with-securitymanager)
- [Development](#development)
- [Enterprise Use Cases](#enterprise-use-cases)
- [Vulnerabilities Addressed](#vulnerabilities-addressed)
- [Security Hardening Roadmap](#security-hardening-roadmap)
- [Relevant Presentations](#relevant-presentations)
- [Security Tooling](#security-tooling)
- [Complexity and Maintenance](#complexity-and-maintenance)
- [Simplification](#simplification)
- [Performance](#performance)
- [Ultimate Goal](#ultimate-goal)
- [Why OpenJDK Removed Authorization](#why-openjdk-removed-authorization)

---

## Overview

Dirty Chai is a community fork of [OpenJDK](https://openjdk.org/) that retains and actively improves Java's Authorization infrastructure. No attempt is made to sandbox untrusted code; instead, the project goals are:

- **Prevent loading of untrusted code** — whitelist trusted code sources via policy.
- **Break gadget attack chains** — deny the permissions attackers need to complete an exploit.
- **Block injection attacks** — whitelist allowed URLs and serialization targets.
- **Maintain and extend guard hooks** — preserve permission-check points throughout OpenJDK and add new ones where needed.
- **Research Authorization improvements** — drive best practices and new APIs.
- **High performance and scalability** — `ConcurrentPolicyFile` is designed for modern, high-throughput deployments.
- **Practical tooling, not vaporware** — improve Java security against injection-style attacks using Principle of Least Privilege (POLP) whitelisting.

> Developers interested in **sandboxing untrusted code** should investigate [GraalVM Espresso](https://www.graalvm.org/latest/reference-manual/espresso/) or Graal process isolation instead.

Dirty Chai ships two related sub-tools with their own READMEs:
- [`src/utils/IdealGraphVisualizer`](src/utils/IdealGraphVisualizer/README.md) — graph visualization for compiler IR
- [`src/utils/hsdis`](src/utils/hsdis/README.md) — HotSpot disassembler plugin

---

## Quick Start

### 1. Audit your application (staging environment)

Run your application with the PolicyWriter audit agent to auto-generate a least-privilege policy file:

```sh
java -Djava.security.manager=polpAudit \
     -DpolpAudit.path.properties=/path/to/audit.properties \
     -jar your-app.jar
```

### 2. Review and audit the generated policy file

Inspect the generated policy for over-broad permissions (e.g., `FilePermission` for temp files, `SocketPermission`). Re-run the audit agent multiple times — permissions added in later runs indicate areas requiring wider scope — and use [SpotBugs](https://github.com/spotbugs/spotbugs) (< 4.9.0) for static analysis.

### 3. Deploy with SecurityManager enabled

```sh
java -Djava.security.manager=default \
     -Djava.security.policy==/path/to/security.policy \
     -jar your-app.jar
```

> **Note:** The double equals (`==`) in `-Djava.security.policy==` instructs `ConcurrentPolicyFile` to use *only* your policy file, excluding `<JAVA_HOME>/lib/security/default.policy`, which contains broad `AllPermission` grants that are undesirable in production.

---

## Building

For full build instructions, see:

- [doc/building.md](doc/building.md) — Markdown version
- [doc/building.html](doc/building.html) — HTML version
- [Online documentation](https://git.openjdk.org/jdk/blob/master/doc/building.md) — upstream OpenJDK build guide

**Minimal build example (Linux/macOS):**

```sh
# Configure the build
bash configure

# Build the JDK images
make images

# Verify the build
./build/*/images/jdk/bin/java -version
```

See <https://openjdk.org/> for more information about the OpenJDK Community and the JDK, and see <https://bugs.openjdk.org> for JDK issue tracking.

---

## Key Features

1. **Enterprise Security Gap Addressed**
   - Modern Java lacks fine-grained authorization (SecurityManager is deprecated upstream).
   - Dirty Chai uses an RFC 3986-compliant, defense-in-depth approach to restore and improve fine-grained authorization.
   - Target: Enterprises requiring strict access control (financial, healthcare, government).

2. **Zero-Trust Architecture Ready**
   - Multi-layer validation (caller, stack, CodeSource, policy).
   - Perfect for high-security deployments.
   - Target: Organizations implementing zero-trust security models.
   - Ambient Authority: doPrivileged methods only grant permissions recorded by polpAudit.

3. **Compliance & Audit Requirements**
   - Fine-grained permission controls enable compliance tracking and audit trails.
   - Target: Regulated industries (fintech, healthcare, critical infrastructure).

4. **Performance-Conscious**
   - `ConcurrentPolicyFile` is designed for high-throughput with no DNS-lookup overhead.
   - Authorization overhead is less than 1% in benchmarks.
   - Target: High-performance systems requiring authorization.

5. **JGDMS Binary Compatibility**
   - Dirty Chai re-exports `org.apache.river.api.security.ScalableNestedPolicy`, `PermissionGrant`, and `PermissionGrantBuilder` from `java.base`.
   - Existing JGDMS applications run without recompilation; ClassLoader delegation resolves the compatibility APIs from the platform automatically.
   - `SecurityPolicyWriter` (`polpAudit`) auto-discovers required grants, including `defineClassInPackage.org.apache.river.api.security`.

---

## JGDMS Compatibility

Dirty Chai includes JGDMS core authorization contracts in `java.base` under `org.apache.river.api.security` to preserve binary compatibility for existing deployments:

- `ScalableNestedPolicy`
- `PermissionGrant`
- `PermissionGrantBuilder`

This allows JGDMS applications to run on Dirty Chai without recompilation. Platform ClassLoader precedence ensures these API contracts are resolved from Dirty Chai, while JGDMS implementation classes loaded by the application ClassLoader continue to interoperate through the same public types.

For deployment details, ClassLoader behavior, and policy guidance, see [JGDMS_COMPATIBILITY.md](JGDMS_COMPATIBILITY.md).

---

## Principle of Least Privilege Policy Writer

The PolicyWriter tool (ported from [JGDMS](https://github.com/pfirmstone/JGDMS)) automates the creation of policy files using the Principle of Least Privilege (POLP). It creates a minefield of `SecurityException`s for attackers navigating inside your perimeter defenses.

- Permissions are **not** granted to load transitive dependencies or modules your application does not use.
- Serialization is limited to only the classes observed in your deployment staging environment.

### System properties to configure

| Property | Purpose |
|----------|---------|
| `java.security.policy` | Path to your policy file |
| `javax.net.ssl.trustStore` | Path to your trust store |
| `javax.net.ssl.trustStoreType` | Trust store type (e.g., `JKS`, `PKCS12`) |
| `javax.net.ssl.trustStorePassword` | Trust store password |

### Auditing workflow

1. Run PolicyWriter in your staging environment to generate an initial policy file.
2. Audit the generated policy for permissions with overly broad scope (e.g., `FilePermission` covering temp dirs, `SocketPermission` wildcards).
3. Run the auditing cycle multiple times, marking where the policy was last updated after each run. Permissions that re-appear across runs indicate areas needing a wider scope in the final policy.
4. Once satisfied, deploy the audited policy in production with `ConcurrentPolicyFile`.

---

## Deploying with SecurityManager

### Audit phase (staging)

```sh
java -Djava.security.manager=polpAudit \
     -DpolpAudit.path.properties=${your.path}audit.properties \
     -jar your-app.jar
```

### Production deployment

```sh
java -Djava.security.manager=default \
     -Djava.security.policy==/path/to/security.policy \
     -jar your-app.jar
```

> Unlike the standard `PolicyFile`, `ConcurrentPolicyFile` does **not** automatically include `<JAVA_HOME>/lib/security/default.policy` when `==` is used. That default policy contains many broad `AllPermission` grants that are undesirable in a hardened deployment. They remain in the distribution for testing purposes only.

---

## Development

- The `trunk` branch is where all development occurs. Development branches are created from `trunk` and rebased to `trunk`.

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines. Issues are tracked at <https://bugs.openjdk.org> for upstream items and in this repository's [issue tracker](https://github.com/pfirmstone/DirtyChai/issues) for Dirty Chai-specific changes.

---

## Enterprise Use Cases

| Segment | Use Case | Pain Point Addressed |
|---------|----------|---------------------|
| **Financial Services** | Microservices security | No fine-grained Java authorization upstream |
| **Healthcare (HIPAA)** | Access control compliance | Audit trail requirements |
| **Government (Federal)** | FedRAMP/DoD compliance | Defense-in-depth mandates |
| **Critical Infrastructure** | Nuclear, power, water systems | Zero-trust requirements |
| **Cloud Platforms** | Container orchestration | Tenant isolation |
| **Defense Contractors** | Security-critical systems | TS/SCI requirements |

---

## Vulnerabilities Addressed

- **Log4Shell (Log4j) root cause**: JNDI LDAP dynamic code downloading and object deserialization are secured without disabling or removing functionality. By removing static permission grants in `ClassLoader`s (e.g., `URLClassLoader`), the policy can instead whitelist allowed URLs via `URLPermission`, restrict dynamic code loading to signed JAR files using `LoadClassPermission`, and limit object deserialization to a whitelist using `SerialObjectPermission`.

---

## Security Hardening Roadmap

| Item | Status |
|------|--------|
| Replace default policy provider with `ConcurrentPolicyFile` from JGDMS | ✔ Done |
| Reduce the size of the trusted platform | ✔ Done |
| Add PolicyWriter tool from JGDMS for least-privilege deployment | ✔ Done |
| `System.setSecurityManager(null)` throws `IllegalArgumentException`, preventing privileged-context injection attacks from disabling the SecurityManager | ✔ Done |
| Add strict RFC 3986, RFC 6874, and RFC 5952 URI support; remove DNS lookups from `CodeSource` | ✔ Done |
| Add support for Virtual threads when SecurityManager is enabled | ✔ Done |
| Make `AccessControlContext` immutable; add static builder methods for reuse; update VM call sites | ✔ Done |
| Simplify `AccessControlContext` to align with its original design intent | ✔ Done |
| Update `AccessControlContext` `equals` and `hashCode` implementations | ✔ Done |
| Create `DomainIdentity` subclass of `ProtectionDomain` implementing `equals` and `hashCode` | ✔ Done |
| Reimplement `AccessController::doPrivileged` methods with `Permission` arguments to strictly limit permissions rather than granting full caller privileges; capture caller as `jrt:/module/class` domain | ✔ Done |
| Allow Policy to grant additional permissions beyond those hard-coded in `AccessController::doPrivileged` with `Permission` arguments | ✔ Done |
| Cache `AccessControlContext` instances to avoid duplication; instantiate only when SecurityManager is enabled (required for Virtual thread support) | ✔ Done |
| Remove `ProtectionDomain` cache from `SubjectDomainCombiner`; replace with non-blocking `AccessControlContext` cache and `DomainIdentity` | ✔ Done |
| Update `CombinerSecurityManager` to hand off permission checks to Virtual threads | ✔ Done |
| Add `LoadClassPermission` to `SecureClassLoader` so HTTP sources and JAR signers can control which code is loaded via policy | ✔ Done |
| Add `SerialObjectPermission` for Java Serialization, automating class whitelisting | ✔ Done |
| Add `NativeInvocationPermission` for JNI/FFM native symbol-resolution control (`ClassLoader.findNative`, `SymbolLookup`, `SystemLookup`) | ✔ Done |
| Add `NativeMemoryPermission` for FFM off-heap memory access control (`Arena.global()` and `MemorySegment.reinterpret*()`) | ✔ Done |
| Remove XML parsing from trusted code to allow authorization decisions based on authenticated users. XML modules are no longer part of the trusted codebase and can be assigned appropriate permissions, or loading can be prevented via `LoadClassPermission` | ✔ Done |
| Add policy tests from JGDMS | Planned |
| Add netmask wildcards to `SocketPermission` | Planned |
| Reimplement `AccessController::getContext` using `StackWalker` | 🪓 Attempted — not stable; caused test failures |
| Reimplement `AccessController::doPrivileged` using `ScopedValue` for context | 🪓 Attempted — not stable; caused test failures |
| Follow and review upstream OpenJDK changes | Ongoing |
| Maintain Authorization and Authentication APIs | Ongoing |
| Research improvements to Authorization and Authentication APIs | Ongoing |
| Remove native ProtectionDomainCache | ✔ Done |

> **Non-goal**: Sandboxing untrusted code. Dirty Chai focuses on user authorization — ensuring users have access only when using approved, policy-controlled code — and provides tooling to audit and limit the privileges requested by third-party code prior to deployment. Developers needing untrusted code sandboxing should consider Graal process isolation.

---

## Relevant Presentations

- [Presentation 1](https://www.youtube.com/watch?v=uVob-4aXbxY)
- [Presentation 2](https://www.youtube.com/watch?v=sIuVbVbjZcw)
- [Presentation 3](https://www.youtube.com/watch?v=8Qyghv00vEQ)
- [Presentation 4](https://www.youtube.com/watch?v=Y8a5nB-vy78)
- [Presentation 5](https://www.youtube.com/watch?v=0h8DWiOWGGA)

---

## Security Tooling

It is not recommended to run unaudited, untrusted code in a deployed environment — but how many programs today download code that their developers haven't audited? Is it even practical for small development teams to audit hundreds of thousands or millions of lines of code? The PolicyWriter tool from JGDMS allows administrators to test untrusted code (after static analysis) in a safe staging environment to determine exactly which privileges that code will request at runtime.

Following auditing with static analysis ([SpotBugs](https://github.com/spotbugs/spotbugs) < 4.9.0, since `doPrivileged` bugs are no longer reported in later versions) and PolicyWriter, code that is deemed safe to run should be executed using the Principle of Least Privilege, using policy files generated by PolicyWriter to minimize the attack surface available to any exploit that leverages flaws in that code.

PolicyWriter generates policy files that are easy to edit and straightforward to understand. While the existing SecurityManager authorization infrastructure is not perfect, it is the best available tool for auditing third-party code and establishing a level of trust in that code prior to deployment. It also enables administrators to disable unused or unwanted features that require privileges — such as network communication, file system access, agents, XML parsing, or access to secret keys — so that an attacker is unlikely to be able to leverage those features even if a vulnerability exists in the code.

---

## Complexity and Maintenance

Concurrency is a complex topic — yet programmers are motivated to learn it because of the significant performance benefits. Much investment has gone into the Java memory model and concurrency libraries. Security, by contrast, has received comparatively little tooling investment; security budgets tend to go toward addressing zero-day vulnerabilities rather than building foundational infrastructure. No new tools were written for Java Authorization from its introduction in the late 1990s until recently; the only tool available was Policy Tool, a small hand-editor for adding permissions. That approach required discovering required permissions through trial and error, leading to widespread overuse of `AllPermission`. In 2004, the Jini project created a Debug Policy Tool that wrote out each required permission; administrators then had to manually add each one to their policy files. PolicyWriter was inspired by that tool — instead of requiring manual editing, it appends missing permissions directly to policy files.

One of the problems with the existing `PrivilegedAction` model is that many developers call methods requiring privileges without encapsulating those calls in a `PrivilegedAction`. Programmers also often forget to preserve the security context across threads; by default, `Executor`s do not inherit the calling thread's context unless a `PrivilegedThreadFactory` is used. PolicyWriter makes it easy to read policy files and identify where permissions are leaking into code that should not have them — it provides visibility, and visibility reduces complexity. In hindsight, it would have been better if Java API methods requiring privileges also required a `PrivilegedAction` parameter, warning the programmer not to leak privileged information. `Executor`s could use `ThreadFactory`s that inherit the calling thread's context by default; opting out of that behavior could require an explicit permission, since bypassing context inheritance is effectively a privileged operation.

An alternative to the privileged action model would have been explicit privileged calls, where no privileges are granted unless a privileged call has been made — so that outside a privileged call, code operates with no permissions at all.

JGDMS contains interesting Authorization APIs — such as `ScalableNestedPolicy` and `PermissionGrant` — that leverage immutability and safe publication.

One root cause of the SecurityManager's adoption problems is that it was never enabled by default. The practical reason was simple: there were no adequate tools for managing policy. Policy may also have been too complex; it was designed prior to annotations, and a more declarative approach might allow an annotation processor to assist with policy generation during development.

Another issue is that every protection domain ends up with some permissions, so programs typically operate with a minimum permission set. If everything has a minimum permission set, why regulate it? Missing `PrivilegedAction` wrappers are the cause, but the effect is that user permissions are always in force and can be leveraged for privilege escalation if an attacker exploits a data-parsing vulnerability, since the attacker operates without a domain of its own. A different model — privileged calls — would mean that outside a privileged call, there are no permissions at all. The code developer and the user would need to be trustworthy enough not to leak privileged information; in the real world, if someone is untrustworthy, their permissions are revoked.

Authorization complexity for developers could be significantly reduced with tooling and compile-time static analysis to identify missing `PrivilegedAction` wrappers. The greatest complexity falls on the OpenJDK development team — implementing guards, preserving context across threads, and avoiding privilege escalation. Reducing the size of Java's trusted codebase and centralizing access to external resources would reduce this risk.

Experience from JGDMS, Jini, and Apache River demonstrates that combining Authorization best practices with policy tooling made SecurityManager relatively simple to use once understood. The largest maintenance component was maintaining policy files — but that became manageable and useful once tooling was provided, since it also brought auditing benefits. Jini introduced dynamic policy (changing policy after deployment). River introduced revocation (removing policy grants via garbage collection when no longer needed). JGDMS adopted OSGi's approach of bundling required permissions in a service proxy's JAR file following authentication. The administrator gives users the ability to dynamically grant a restricted set of permissions to authenticated services using `GrantPermission`, making the process largely automatic while still constrained by the administrator. Since most users grant whatever permission is requested in order to complete a task, these permissions are granted automatically following authentication.

OpenJDK is reluctant to provide hooks for an authorization framework to place guards due to the maintenance burden. Without those guards, an authorization framework that controls network access, file system access, system properties, and so on is not possible. It is our hope that OpenJDK will eventually allow these hooks to remain in the codebase if the Dirty Chai community maintains them.

---

## Simplification

In Java 1.2, permissions were static: defined by Policy but stored as immutable within a `ProtectionDomain`. `ClassLoader`s assigned permissions to `ProtectionDomain`s under the assumption that a caller holding `RuntimePermission "createClassLoader"` would scrutinize URL data. `ClassLoader`s assigned permissions not listed in policy files, removing the possibility of administrator control. Vulnerabilities such as JNDI and the more recent Log4Shell have shown that URL data cannot be assumed safe. Static permissions were useful for applet `ClassLoader`s — assuming that an applet could connect to the URL it originated from — but that assumption is not relevant to modern code and only adds complexity and attack surface.

Later, in Java 1.4, Policy began being consulted during `implies` calls. This decision was made for the Jini 2.0 release to support `DynamicPolicy`. It has become clear that static permissions are a mistake that adds unnecessary complexity.

In Java 1.8, new `doPrivileged` methods were added to `AccessController` that accept a `Permission` array, allowing a caller to reduce its permissions to the specified set. That implementation added significant complexity to `AccessControlContext`, making it impractical to support Virtual threads. However, by pushing a new `ProtectionDomain` onto the stack with the restricting permissions, the same semantics can be achieved without the complexity — and with better debuggability, since the caller's module and class can be captured in `jrt:/module/classname` URL syntax.

Removing static permissions and eliminating direct `ClassLoader` permission assignment at construction time gives full control to Policy and policy administrators. Administrators can whitelist safe domains without requiring code changes. What was previously a developer concern becomes an administrative concern.

Removing static permissions also helps developers reason about what belongs inside a `PrivilegedAction` — and what the difference is between a user concern and a code concern.

`PrivilegedThreadFactory`s should be used by default when SecurityManager is active, so programmers do not need to manually preserve context when creating threads.

A cache of immutable `AccessControlContext` instances would significantly reduce the number of context objects needed to support Virtual threads — stay tuned.

---

## Performance

Standard OpenJDK `Policy` and `PermissionCollection` implementations are heavily synchronized and contended. DNS calls are made during `CodeSource.implies` evaluations. Those implementations were created in the late 1990s, when most Java-capable machines were single-threaded.

The JGDMS policy implementation, now used in Dirty Chai via `ConcurrentPolicyFile`, is modern concurrent code that takes advantage of mutability and thread confinement. RFC 3986 URIs replace DNS calls; all performance hotspots have been analyzed and removed — even string case conversion uses bit-shift operations (string case conversion was identified as a hotspot in RFC 3986 URI normalization). The performance overhead of Authorization with `ConcurrentPolicyFile` is less than 1%.

---

## Ultimate Goal

Community-based redesign of the Authorization API for Java as a preview feature, with the goal of eventual integration into the OpenJDK mainline.

---

## Why OpenJDK Removed Authorization

Not enough developers used SecurityManager, and the work required to maintain it served only a small fraction of the Java ecosystem. Dirty Chai exists to serve that fraction — and to make the case that, with the right tooling, Authorization can be practical and accessible to a much wider audience.
