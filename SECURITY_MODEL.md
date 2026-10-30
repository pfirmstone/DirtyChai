# Dirty Chai Security Model

- **Version:** 2.4
- **Date:** 2026-05-26
- **Last Reviewed:** 2026-10-19
- **Project:** Dirty Chai
- **Repository:** https://github.com/pfirmstone/DirtyChai

---

## 1) Purpose and Scope

Dirty Chai extends OpenJDK authorization behavior to enforce policy-based least privilege with stronger controls around class loading, caller validation, and privilege boundaries.
It also re-exports JGDMS compatibility contracts in `org.apache.river.api.security` (`ScalableNestedPolicy`, `PermissionGrant`, `PermissionGrantBuilder`) from `java.base` so existing JGDMS applications can run without recompilation.

This document covers the active model implemented in:

- `java.lang.System`
- `java.security.AccessController`
- `java.security.DigestCodeSource`
- `java.security.SecureClassLoader`
- `org.apache.river.api.security.*` (JGDMS compatibility contracts)
- `au.zeus.jdk.authorization.policy.ConcurrentPolicyFile`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.guards.*`
- `au.zeus.jdk.authorization.spire.*`

---

## 2) Quick Start (Developer Workflow)

Use this path first, then return to the deeper sections below.

1. **Audit in staging by setting `-Djava.security.manager=polpAudit`** to generate policy grants from real permission checks:

   ```bash
   java -Djava.security.manager=polpAudit \
        -DpolpAudit.path.properties=/path/to/audit.properties \
        -jar your-app.jar
   ```

2. **Review generated policy** and narrow broad grants (`AllPermission`, wide file/socket wildcards).
3. **Deploy in production** with strict policy:

   ```bash
   java -Djava.security.manager=default \
        -Djava.security.policy==/path/to/app.policy \
        -jar your-app.jar
   ```

4. **Use Subject-aware execution where policy requires principals**:
   - Wrap entrypoints in `Subject.callAs(...)`. `Subject.doAs(...)` is retained for backward compatibility only; new code should prefer `Subject.callAs(...)`.
   - Use `Thread.Builder` / `ThreadFactory` inside that scope for consistent Subject-aware context inheritance.
   - Create executors using those factories within the same scope so worker threads inherit the intended context baseline.

### Why `polpAudit` first?

Manual policy authoring is error-prone in real systems. `polpAudit` activates `SecurityPolicyWriter` audit mode, observes actual runtime checks, and incrementally writes required grants, giving a practical least-privilege baseline before human tightening. For the full audit-review-deploy cycle, see section 14 ("Recommended Deployment Pattern").

---

## 3) Simple Mental Model

1. **Who is calling?** (active `Subject` scope from `Subject.callAs(...)`, plus caller context)
2. **What code is running?** (`CodeSource`, signer, module/path)
3. **What does policy grant?** (`ConcurrentPolicyFile` matching + permission implication)
4. **Does execution stay bounded?** (`AccessController` context boundaries, fail-secure on mismatch)

If any required condition does not match, the operation is denied.

---

## 4) Core Security Guarantees

1. **Fail-secure defaults**: validation failures deny access (exception or unprivileged state).
2. **Least privilege**: permissions must be explicitly granted by policy.
3. **No trust transfer**: dependencies are evaluated independently.
4. **Policy-driven principal enforcement**: principal checks apply when grants include `principal` clauses.
5. **Caller-sensitive privilege boundaries**: privileged APIs retain caller-sensitive behavior.
6. **URI-validated code source matching**: policy matching relies on RFC 3986 URI handling.
7. **Content-hash code source integrity**: when a `SecurityManager` is active, `SecureClassLoader` promotes every network-loaded `CodeSource` to a `DigestCodeSource` (SHA-256 by default) before computing the `ProtectionDomain`.  Policy grants that use a `digest` clause are only matched by `DigestCodeSource`-backed domains, enforcing content-addressed trust.
8. **SPIFFE workload identity binding**: when a `SecurityManager` is active, `SecureClassLoader` stamps `ProtectionDomain`s for code with a non-null codebase, including network-loaded code, with SPIFFE workload principals from the SPIRE-managed `SpiffeSubject`. Those stamped principals come from the current SVID's `X500Principal` set. This lets policy `principal` clauses match both code identity and verified infrastructure identity. Injection is deferred until `VM.isBooted()`. If the SPIFFE Verifiable Identity Document (SVID) is not yet available, principal stamping is skipped and SPIFFE-constrained `principal` grants do not match (fail-secure: under-privilege rather than over-privilege).

---

## 5) High-Level Architecture

1. Application invokes security-sensitive operation.
2. `SecurityManager.checkPermission(...)` delegates to policy evaluation.
3. `AccessController` computes effective context (stack + inherited + explicit context, plus active scoped user subjects when present).
4. `ConcurrentPolicyFile` resolves grants by code source, signer, principal, and permission implication.
5. Permission decision is enforced (allow/deny).

---

## 5.1) Compact Permission-Check Call-Flow Diagram

### Guard entry points → `CombinerSecurityManager`

```
ObjectInputStream.readOrdinaryObject()
  → new SerialObjectPermission(className).checkGuard(null)

ClassLoader.findNative() / SymbolLookup / SystemLookup
  → new NativeInvocationPermission(libName).checkGuard(null)

Arena.global()
  → new NativeMemoryPermission("global-arena").checkGuard(null)

AbstractMemorySegmentImpl.reinterpretInternal()
  → new NativeMemoryPermission("reinterpret-memory-segment").checkGuard(null)

SecureClassLoader.defineClass()
  → LoadClassPermission.LOAD_CLASS_ALLOW.checkGuard(pd)

ThreadBuilders.PlatformThreadBuilder.unstarted/factory
  → RuntimePermission("createPlatformThread").checkGuard(null)

ThreadBuilders.VirtualThreadBuilder.unstarted/factory
  → RuntimePermission("createVirtualThread").checkGuard(null)

Module.addExports() / Module.addOpens()
  → new RuntimePermission("mutateModuleTopology") → sm.checkPermission(...)

  all paths → Permission.checkGuard(…) → sm.checkPermission(perm)
```

### `CombinerSecurityManager.checkPermission`

```
CombinerSecurityManager.checkPermission(perm)
  │
  ├─ self-bypass: SMPrivilegedContext / SMConstructorContext? → return
  │
  ├─ checked cache hit: (executionContext, perm) already verified? → return
  │       key: ConcurrentHashMap<ACC, ConcurrentSkipListSet<Permission>>
  │       TTL: 20 s; cleared on policy.refresh()
  │
  ├─ contextCache hit: delegate ACC cached? → use cached delegate ACC
  │   miss: DelegateDomainCombiner builds optimized delegate ACC, stores it
  │       key: ConcurrentHashMap<ACC, delegate ACC>; TTL: 60 s
  │
  └─ delegateContext.checkPermission(perm)
         └─ DelegateProtectionDomain.implies(perm) for each domain
                │
                ├─ < 4 domains → sequential
                └─ ≥ 4 domains → parallel (VirtualThreadPerTaskExecutor)
```

### `AccessControlContext` / stack walk

```
AccessController.getStackAccessControlContext()  [native]
  → intersects ProtectionDomain of every frame on call stack
  → stops at doPrivileged() boundary (privilege elevation point)
  → returns effective AccessControlContext

AccessController.getContext()
  → getStackAccessControlContext()
  → optimize()
  → SubjectAccess.SCOPED.get()
      → for each scoped Subject that is not a WorkerSubject:
           SubjectDomainCombiner.combine(acc.getContext(), acc.getContext())
           also combine privilegedContext when present
  → return effective AccessControlContext

AccessControlContext.checkPermission(perm)
  → for each domain in context: policy.implies(domain, perm)
  → deny if any domain lacks the permission
```

### Limited-privilege `doPrivileged(..., perms)` / `doPrivilegedWithCombiner(..., perms)`

```
AccessController.doPrivileged(action, context, perms)
  → Reflection.getCallerClass()
  → getResource(caller)
      → named module? construct jrt:/<module>/<class> CodeSource
      → non-module code? use callerLoader.getResource(clazz.getName())
      → URI construction failure? return null CodeSource (fail-secure)
  → new DomainIdentity(codeSource, perms, null, null)
  → intersect with supplied AccessControlContext
  → execute privileged action with limited scope
```

### `ConcurrentPolicyFile.implies`

```
ConcurrentPolicyFile.implies(ProtectionDomain pd, Permission perm)
  │
  ├─ volatile read: PermissionGrant[] grantRefCopy = grantArray
  │     (single memory fence; all subsequent work is thread-local)
  │
  ├─ privileged grants first (AllPermission early-exit for infrastructure code)
  │
  ├─ static domain permissions (pd.getPermissions())
  │
  └─ for each PermissionGrant:
         ├─ CodeSource match? (RFC 3986 URI string compare, no DNS)
         │     via Uri.java — normalized at parse time
         ├─ Digest match? (DigestGrant only)
         │     pd.getCodeSource() must be DigestCodeSource
         │     algorithm and digest bytes must match exactly
         │     plain CodeSource never implies a DigestGrant (fail-secure)
         ├─ Principal match? (Subject principal class + name exact match)
         └─ grant.getPermissions().implies(perm)?
                └─ Permission.implies() per permission type
                      (SocketPermission, FilePermission, BasicPermission, …)

  no match → deny (fail-secure default)
```

### `System.setSecurityManager` validation flow

```
System.setSecurityManager(sm)
  │
  ├─ sm == null → IllegalArgumentException (always)
  │
  ├─ trustedSMClass(sm)?    [exact Class.equals(), not instanceof]
  │     SecurityManager.class
  │     CombinerSecurityManager.class
  │     PolicyOnlySecurityManager.class
  │
  │  YES (trusted) ──────────────────────────────────────────────►
  │    → install SM (no stack inspection; policy governs it)
  │
  └─ NO (custom/untrusted) ──────────────────────────────────────►
       Layer 1 (@CallerSensitive)
         Reflection.getCallerClass() → null caller → SecurityException
        Layer 2 (StackWalker, limit 50 frames)
          rejects: java.lang.reflect.* / sun.reflect.* frames,
                   including java.lang.reflect.AccessibleObject.setAccessible
                   sun.misc.Unsafe, jdk.internal.misc.Unsafe
                   non-whitelisted java.lang.invoke.* runtime frames
                   $$Lambda$, $Proxy, GeneratedMethodAccessor*
       Layer 3 (ProtectionDomain)
         caller.getProtectionDomain() == null → SecurityException
       Layer 4 (generated/synthetic caller name check)
         isGeneratedClassName(caller.getName()) → SecurityException
       → install SM if all layers pass
```

---

## 6) SecurityManager Installation Model (`System.setSecurityManager`)

Dirty Chai uses **conditional validation** when installing a SecurityManager.

### Trusted implementations (exact class match)

`trustedSMClass(sm)` trusts only:

- `java.lang.SecurityManager`
- `au.zeus.jdk.authorization.sm.CombinerSecurityManager`
- `au.zeus.jdk.authorization.sm.PolicyOnlySecurityManager`

For these classes, Dirty Chai applies the trusted path and avoids full custom-stack hardening.

### Custom implementations (all other classes)

For non-trusted classes, Dirty Chai applies layered checks before installation:

1. Direct caller check (`@CallerSensitive` + caller lookup)
2. Stack inspection via `StackWalker` (reflection/method-handle/generated-frame detection, including `AccessibleObject.setAccessible`)
3. Caller `ProtectionDomain` validation
4. Generated/synthetic caller rejection

If any layer fails, installation is blocked with `SecurityException`.

### Important operational note

`SecurityPolicyWriter` is intentionally **not** in the trusted whitelist and is for audit/staging workflows, not production enforcement.

---

## 7) AccessController and Privilege Boundaries

Dirty Chai keeps `AccessController` and `doPrivileged` semantics active for authorization use.

- `doPrivileged(...)` establishes bounded privilege elevation.
- `doPrivilegedWithCombiner(...)` preserves combiner/domain behavior.
- Effective permissions are constrained by the active `AccessControlContext` and policy grants.

Security depends on minimizing privileged blocks and scoping them to the smallest operation necessary.

### `AccessController.getContext()` scoped-subject injection

`AccessController.getContext()` no longer returns only a stack/intersection snapshot. After optimizing the current stack context, it reads the active scoped subject array from `SubjectAccess.SCOPED.get()` and injects each non-`WorkerSubject` into the returned `AccessControlContext` with a `SubjectDomainCombiner`.

This means `Subject.callAs(...)` participates in authorization through `ScopedValue`-backed subject injection at every `getContext()` call, not only at a `doPrivileged` boundary. If a privileged context is present, the same injection is applied to that nested privileged context before the final `AccessControlContext` is returned.

### Limited-privilege `doPrivileged(..., context, Permission...)`

For the limited-privilege overloads of `doPrivileged(...)` and `doPrivilegedWithCombiner(...)`, Dirty Chai does not reuse the caller's existing `ProtectionDomain` directly. Instead it builds a `DomainIdentity` from the caller class and the requested permissions.

For named-module callers, `AccessController.getResource(Class<?>)` constructs a module-aware `CodeSource` URI of the form `jrt:/<module>/<class>`. For non-module code, it falls back to the caller class loader's resource URL. Policy grants that are meant to match these limited-privilege blocks therefore need to match the `jrt:/...` `CodeSource` for named-module callers; grants written only against the caller's original `file:` or `http:` location will not match this `DomainIdentity`.

If `getResource(Class<?>)` cannot construct the URI because of `MalformedURLException` or `URISyntaxException`, it returns `null` so the synthetic `DomainIdentity` cannot match any grant.

---

## 8) Policy Model (`ConcurrentPolicyFile`)

Policy decisions are computed from:

- **CodeSource** (location/signer)
- **Content digest** (when grant clauses use a `digest` selector — see §8.1)
- **Principals** (when grant clauses require them)
- **Permission implication rules**

### Default posture

- No matching grant => denied.
- Invalid or unmatched inputs do not gain privileges.

### Grant clause selectors

A policy `grant` block may combine any of:

| Selector | Syntax | Effect |
|---|---|---|
| `codebase` | `codebase "https://example.com/lib.jar"` | URI prefix/wildcard match against the `CodeSource` location |
| `signedby` | `signedby "alice,bob"` | Certificate signer aliases must all be present |
| `digest` | `digest "SHA-256:a1b2c3..."` | Content-hash match; only `DigestCodeSource`-backed domains qualify |
| `principal` | `principal com.example.MyPrincipal "name"` | Subject principal class + name exact match |

Selectors are ANDed: all present selectors must match for the grant to apply.

### Principal semantics

- Grants **without** principal clauses can apply without authenticated Subject identity.
- Grants **with** principal clauses require matching Subject principals.

This makes principal enforcement configurable by policy rather than globally forced.

---

## 8.1) Content-Addressed Trust (`DigestCodeSource` and `DigestGrant`)

### Overview

`DigestCodeSource` extends `CodeSource` with a cryptographic content digest of the artifact at the code location. When a `SecurityManager` is active, `SecureClassLoader.getProtectionDomain(CodeSource)` automatically promotes every network-`CodeSource` to a `DigestCodeSource` before assigning a `ProtectionDomain`, so the loaded class is always bound to the artifact's hash rather than merely to its URL.

### `SecureClassLoader` promotion flow

```
SecureClassLoader.defineClass(name, bytes, cs)
  │
  ├─ cs already a DigestCodeSource? → use pdcache directly (skip re-download)
  │
  ├─ Compute CodeSourceKey(cs) [URI + certs + digest]
  │
  ├─ pdcache hit? → return cached ProtectionDomain
  │
  ├─ SecurityManager active and codebase != null?
  │   ├─ VM.isBooted()?
  │   │   ├─ no → pals = null
  │   │   └─ yes → sub = SpiffeCredentialManager.getInstance().getSubject()
  │   │       ├─ sub != null and sub.isReadOnly()? → pals[] = X500Principal[] from SpiffeSubject
  │   │       └─ otherwise → pals = null (SPIRE not yet connected)
  │   ├─ new ProtectionDomain(cs, perms, loader, principals[])   ← SPIFFE principals embedded (`pals` in code)
  │   ├─ check URLPermission("GET:") — must be granted to the new domain
  │   ├─ download artifact; compute SHA-256 digest
  │   │     (served via JarResponseCache on subsequent loads)
  │   ├─ promote cs → DigestCodeSource(uri, certs, "SHA-256")
  │   └─ recompute permissions from DigestCodeSource
  │
  ├─ check LoadClassPermission.LOAD_CLASS_ALLOW
  └─ pdcache.putIfAbsent(key, pd) → return ProtectionDomain
```

### `DigestCodeSource` equality and hashing

Equality uses RFC 3986 URI form (no DNS lookup), certificates, digest algorithm name, and digest bytes. A plain `CodeSource` and a `DigestCodeSource` for the same URL are **never equal**, preventing cached plain-CS lookups from bypassing the digest check.

### Allowed digest algorithms

`DigestCodeSource` accepts only the following algorithms; all others throw `IllegalArgumentException`:

```
SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256, SHA3-384, SHA3-512
```

### `DigestGrant` implication rules

A `DigestGrant` (produced by a policy `digest` clause) implies a `ProtectionDomain` only when **all** of the following hold:

1. Principal match.
2. `pd.getCodeSource()` is a `DigestCodeSource` instance whose digest was computed when the domain was created (`unverified()` is false). A `DigestCodeSource` constructed with a supplied digest, or deserialised, is never implied: otherwise code allowed to create a class loader could define its own bytes in a domain carrying a trusted jar's digest. *(Agreed 2026-10-18; being implemented.)*
3. The algorithm name matches exactly (case-sensitive).
4. The digest bytes match exactly (`Arrays.equals`).
5. Every signer named by the grant is present on the code source (`CertificateGrant.impliesSigners`). Unsigned code is not implied by a grant that names signers.

The location is **not** compared: content, not location, is the identity a digest grant is made to, so the same artifact is matched wherever it is loaded from. A `codeBase` written in a `digest` grant has no effect on matching.

A `DigestGrant` always returns `false` for a plain `ClassLoader` argument (digest is indeterminate without a `CodeSource`).

### Dynamic grants to proxies

*Design agreed 2026-10-18, being implemented in both trees; see JGDMS `docs/SOW-PermissionGrant-Mirror-and-ProtectionDomain-Grants.md`, section 7.*

JGDMS makes dynamic grants to proxies after verifying them. Where the codebase was verified with a digest per jar, the grant is a `DigestDomainGrant` (`PermissionGrantBuilder.DIGEST_DOMAIN`). It applies to a `ProtectionDomain` only when the domain was defined by the proxy's loader (held weakly, so the grant goes with the proxy), the grant's principals are satisfied, the domain's code source is a computed (not `unverified()`) `DigestCodeSource`, and its `CodeSourceKey` (location, signers and digest) is one of the identities the verifier supplied. Jars added to the loader later, jars whose content differs from what was verified, and domains carrying a supplied digest receive nothing from it.

Where the codebase could not be verified that way, the grant is the loader-wide `ClassLoaderGrant`, as before; policy should limit what that path can confer through `GrantPermission`. Either grant is only as narrow as the loader it is attached to, so loader isolation per remote object, and planned per-SPIFFE-ID process isolation, matter as much as the grant rules. The isolating process is itself an entry point that runs downloaded code, so least privilege inside it still depends on these rules. See [`JGDMS_COMPATIBILITY.md`](JGDMS_COMPATIBILITY.md) for the full rules.

### Network caching (JarResponseCache)

`DigestCodeSource` installs a JVM-wide `ResponseCache` (`JarResponseCache`) during class initialization via `AccessController.doPrivileged`. This cache stores complete JAR/resource response bodies keyed by URI, avoiding repeated network downloads when the same artifact is loaded multiple times within a JVM lifetime. The `doPrivileged` call is required because `ResponseCache.setDefault()` demands `NetPermission("setResponseCache")`, which application code may not hold; `DigestCodeSource` is a `java.base` class and asserts that privilege explicitly.

### DOS defences

| Limit | Value | Purpose |
|---|---|---|
| `MAX_STREAM_BYTES` | 512 MiB | Abort digest computation on abnormally large responses |
| `MAX_CERT_COUNT` | 100 | Bound certificate array size during deserialization |
| `MAX_CERT_BYTES` | 64 KiB | Bound per-certificate DER size during deserialization |
| `MAX_DIGEST_BYTES` | 512 bytes | Bound digest field size during deserialization |

### Policy file example

```
grant codebase "https://trusted.example.com/lib.jar",
      digest "SHA-256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b"
{
    permission java.io.FilePermission "/tmp/-", "read,write";
};
```

The grant is matched **only** if the artifact at `https://trusted.example.com/lib.jar`
produces the stated SHA-256 digest. Any URL pointing to a different artifact — even if the URL is identical — will not match.

---

## 8.2) SPIFFE Workload Identity and `ProtectionDomain` Stamping

### Mechanism

When a `SecurityManager` is active, `SecureClassLoader.getProtectionDomain()` consults `SpiffeCredentialManager.getInstance().getSubject()` on the `ProtectionDomain` construction path, but only after `VM.isBooted()` is true. This lets Dirty Chai bind loaded code to the current SPIFFE-managed workload identity without risking bootstrap deadlock during `initPhase3` (the JVM bootstrap phase where the system class loader is still being initialized).

### Principal stamping

After verifying that the returned `SpiffeSubject` is non-null and read-only, `SecureClassLoader` extracts the `X500Principal` set from the current SVID leaf certificate and passes those principals as the `pals` array to the `ProtectionDomain` constructor. The read-only check matters because it ensures the principal set cannot be mutated after extraction. The resulting domain therefore carries both the code identity (`CodeSource` / `DigestCodeSource`) and the verified workload identity asserted by SPIRE.

### Policy integration

`ConcurrentPolicyFile` grants can combine `codebase`, `digest`, and `principal` selectors. In practice, SPIFFE-aware grants match on the stamped `javax.security.auth.x500.X500Principal` name derived from the current SVID leaf certificate, allowing policy to restrict permissions to code running under a specific verified workload identity as well as a specific artifact.

### Fail-secure posture

If SPIRE has not connected yet, `SpiffeCredentialManager.getSubject()` returns `null`. In that case `pals = null`, so the `ProtectionDomain` is created without SPIFFE principals. Grants that require SPIFFE `principal` clauses therefore do not match until a valid SVID is available: the failure mode is under-privilege rather than over-privilege.

### Bootstrap deferral (`VM.isBooted()` guard)

The `VM.isBooted()` guard is mandatory. `SpiffeCredentialManager` opens a `SocketChannel`, which reaches `SelectorProvider.provider()` and then `getSystemClassLoader()`. Performing that lookup before the VM is fully booted would deadlock during `initPhase3`, so SPIFFE principal injection is deferred until bootstrap is complete.

### Identity forgery prevention

`SpiffeSubject` is a sealed `WorkerSubject` subtype with a `private` constructor. Only `SpiffeCredentialManager` can construct one, so external code cannot fabricate a `SpiffeSubject` and feed forged SPIFFE principals into `SecureClassLoader`.

### SVID rotation and `pdcache`

When the SVID rotates, `SpiffeCredentialManager` atomically replaces its current subject snapshot. New `ProtectionDomain` constructions from that point onward use the rotated principals. Existing cached domains in `SecureClassLoader.pdcache` retain the principals they had at creation time; policy refresh via `SvidRotationListener` and `SpiffePolicyFile.refresh()` ensures grant evaluation is refreshed against the current policy and identity state.

---

## 8.3) SPIFFE Credential Lifecycle (`SpiffeCredentialManager` and `SpiffePolicyFile`)

### `SpiffeCredentialManager`

- JVM-wide singleton, constructed at class initialization.
- Connects to the SPIRE Workload API over a Unix domain socket. The default socket path is `/run/spire/sockets/agent.sock`, overridden by the `spiffe.workload.socket` system property.
- Stores the current X.509 SVID as an atomic snapshot containing:
  - the read-only `SpiffeSubject` (`WorkerSubject`)
  - the SPIFFE ID URI string
  - the SPIRE trust bundle (`X509Certificate[]`)
- A background watcher processes the SPIRE stream, calls `updateSubjectInternal()` for each SVID update, atomically replaces the snapshot, and notifies registered `SvidRotationListener`s.
- SPIRE unavailability at startup is tolerated gracefully. `getSubject()` returns `null` until the first successful fetch, while a background reconnect path retries with exponential backoff.

### Configuration properties

| Property | Default | Purpose |
|---|---|---|
| `spiffe.workload.socket` | `/run/spire/sockets/agent.sock` | SPIRE agent Unix socket path |
| `spiffe.policy.url` | derived from SPIFFE ID | Bootstrap policy HTTPS URL override |
| `spiffe.reconnect.max.attempts` | `10` | Maximum reconnect attempts (`0` disables reconnect) |
| `spiffe.reconnect.initial.backoff.ms` | `1000` | Initial reconnect backoff |
| `spiffe.reconnect.max.backoff.ms` | `300000` | Maximum reconnect backoff (5 minutes) |

**Debug:** `-Djava.security.debug=spiffe` enables bootstrap-safe diagnostics via `sun.security.util.Debug`.

### `SpiffeSubject`

`SpiffeSubject extends WorkerSubject` is the sealed credential carrier for the current workload identity:

- `private` constructor — only `SpiffeCredentialManager` can construct one, preventing identity forgery.
- `WorkerSubject` subtype — `Subject.callAs(...)` **and** `Subject.doAs(...)`/`doAsPrivileged(...)` reject it (see §10.1, "UserSubject, WorkerSubject, and `callAs(...)`"), and the scoped-subject injection path described there excludes it when building an `AccessControlContext`. The worker identity is ambient only; reach it via `Subject.processWorker()`.
- Read-only at construction time (`SpiffeSubject(true, ...)`) — downstream code cannot mutate its principal set.

### `SpiffePolicyFile`

`SpiffePolicyFile extends ConcurrentPolicyFile` provides SPIFFE-authenticated bootstrap policy:

- Fetches bootstrap policy from an HTTPS endpoint using the SVID for mutual TLS client authentication; `HttpsClientAuthPolicyParser` opens the connection inside a `Subject.doAs(...)` context so JSSE can locate the SVID credentials during the handshake. That `doAs` subject **must be a plain (non-`WorkerSubject`) `Subject`** carrying the SVID `CertPath` (public credential) + `X500PrivateCredential` (private credential) — `doAs` rejects a `WorkerSubject`. See the discrepancy flag below.
- Derives the default policy URL from the SPIFFE ID trust domain (`spiffe://trust-domain/...` -> `https://policy.trust-domain/bootstrap/policy`), unless overridden by `spiffe.policy.url`.
- Registers as an `SvidRotationListener`, so `refresh()` runs automatically on SVID rotation through `RefreshingParserDecorator`, which obtains fresh credentials from `SpiffeCredentialManager` on each parse.
- Fail-secure: if bootstrap policy fetch fails, the HTTPS server is unreachable, or a non-200 response / parse failure prevents initialization, `PolicyInitializationException` is thrown and startup does not proceed with an untrusted policy state.

### `SubjectDomainCombiner` principal composition

SPIFFE workload identity is **ambient**: it is stamped into every network-loaded `ProtectionDomain` at class-load time and is obtained as a fresh reference via `Subject.processWorker()`. It is **never** carried as a scoped or ACC-bound subject — the sealed `SpiffeSubject` (`WorkerSubject`) is rejected by **both** `Subject.callAs(...)` **and** `Subject.doAs(...)`/`doAsPrivileged(...)`, each of which throws `IllegalArgumentException` for a `WorkerSubject`. Human/user identity is introduced separately through `Subject.callAs(...)` and `AccessController.getContext()` scoped-subject injection. This lets policy `principal` matching evaluate the ambient workload identity (`WorkerSubject` / SPIFFE `X500Principal`, read from the stamped `ProtectionDomain`s) alongside the active user identity, without the workload identity ever becoming a `doAs` or `callAs` subject.

> **Discrepancy flag (bootstrap policy fetch — needs human source change).** As currently
> wired, `RefreshingParserDecorator` (and the direct `SpiffePolicyFile(Subject, URL)`
> constructor) pass `SpiffeCredentialManager.getSubject()` — which returns a `SpiffeSubject`
> (`WorkerSubject`, constructed at `SpiffeCredentialManager` line ~373) — into
> `HttpsClientAuthPolicyParser`, which calls `Subject.doAs(spiffeSubject, …)`. Because
> `Subject.doAs`/`doAsPrivileged` reject `WorkerSubject` (same guard as `callAs`), this
> bootstrap fetch throws `IllegalArgumentException` at runtime. The fix is to hand the
> parser a **plain `Subject`** holding the same SVID credentials (`CertPath` +
> `X500PrivateCredential`) rather than the sealed `SpiffeSubject`. Flagged for human
> implementation — DirtyChai source is advise-only here.

---

## 9) Class Loading and Authorization

Dirty Chai introduces authorization-aware class loading controls (including `LoadClassPermission`) to reduce unauthorized code execution risk.

Security posture assumes:

- class loading is policy-controlled,
- code source and signer identity can be policy-constrained,
- ungranted code paths fail closed.

---

## 10) Virtual Threads and Subject Context

Dirty Chai preserves authorization behavior with virtual threads by carrying effective context through standard Java security context mechanisms, including `ScopedValue`-backed subject injection in `AccessController.getContext()`.

`Subject.callAs(...)` and `Subject.doAs(...)` remain available and participate in principal-aware authorization flows where policy requires principals.

### 10.1) UserSubject, WorkerSubject, and `callAs(...)`

- `UserSubject` represents human/client identity and can be bound with `Subject.callAs(...)`.
- `WorkerSubject` represents service/process identity and is ambient; `Subject.callAs(Subject, Callable)` rejects a `WorkerSubject` with `IllegalArgumentException`.
- `Subject.doAs(Subject, PrivilegedAction)` and `Subject.doAs(Subject, PrivilegedExceptionAction)` also throw `IllegalArgumentException` when the `Subject` argument is a `WorkerSubject` instance — consistent with the `callAs` restriction above. `Subject.doAs` is retained for backward compatibility; new code should use `Subject.callAs(...)` instead.
- The multi-subject overload `Subject.callAs(Callable<T>, UserSubject...)` binds zero or more `UserSubject` instances simultaneously. `Subject.current()` returns `subject[0]` (the primary) when multiple subjects are bound; `Subject.currentAll()` returns the full stack.
- **Multi-party binding is conjunctive (intersection).** When several `UserSubject`s are bound at once, all of their principals are folded into a single multi-principal `ProtectionDomain` by `currentAll()` during `getContext()`, so a multi-principal policy grant fires only when **every** listed principal is co-present (`PrincipalGrant.containsAll`, a logical AND — not a union). `SecurityPolicyWriter` (polpAudit) captures this declaratively as one multi-principal grant.
- A plain `Subject` (neither `UserSubject` nor `WorkerSubject`) remains instantiable for legacy/service identity and is accepted by `Subject.callAs(Subject, Callable)` / `Subject.doAs(...)`; only the sealed `UserSubject` and `WorkerSubject` carry the special routing rules above.
- `WorkerSubject` (sealed: `permits SpiffeSubject, RemoteSubject`) is excluded from this overload by the parameter type and is also skipped by `AccessController.getContext()` when scoped subjects are injected into an `AccessControlContext` — `currentAll()`/`currentAllNoCheck()` never fold a `WorkerSubject`. The ambient worker reaches `ProtectionDomain`s only by class-load stamping (`SpiffeSubject`) or the verified TLS peer chain (`RemoteSubject`).

> **SPIFFE workload identity propagation**: SPIFFE workload identity (`SpiffeSubject` / `WorkerSubject`) is ambient — it is present in `ProtectionDomain` principals at class-load time and in subject-bearing ACC state, not through `Subject.callAs(...)`. The `WorkerSubject` exclusion in `AccessController.getContext()` (§10.1) ensures SPIFFE identity does not bleed into user-scoped `callAs` chains.

### 10.2) `callAs()` vs `doAs()` propagation model

- `Subject.callAs(...)` binds subjects in the `SCOPED_SUBJECT` `ScopedValue`. Any code path that later calls `AccessController.getContext()` inside that scope receives an `AccessControlContext` with those scoped user subjects folded in automatically (via `SubjectDomainCombiner.currentAll()`), and the binding survives an intervening `doPrivileged`.
- `Subject.doAs(...)` also binds its subject in the **same** `SCOPED_SUBJECT` `ScopedValue` — **replacing** (not accumulating with) any enclosing user subject — and it does **not** attach a `SubjectDomainCombiner` to the `AccessControlContext`. The one difference from `callAs` is the boundary it establishes: `doAs` first captures a **code-only** context by calling `AccessController.getContext()` inside a `STACK_CONTEXT` scope, which makes `currentAllNoCheck()` return no subjects so the *enclosing* user's principals are suppressed from that captured context; it then runs the action under `doPrivileged` with that code-only context, with the new subject bound on the scoped value. The new subject is folded — exactly like `callAs` — at each `getContext()` inside the action.
- The two APIs therefore differ only in the boundary, not in how the subject propagates: `callAs()` rebinds the user within the lexical scope with no `doPrivileged`; `doAs()` additionally installs a `doPrivileged` boundary over a code-only context (dropping the *enclosing* user and the caller's permissions beyond that point). In both cases the bound user rides the `ScopedValue` and is folded transiently by `currentAll()` during `getContext()` — **no `SubjectDomainCombiner` is retained on the returned ACC** (`acc.getDomainCombiner()` is `null` by design). This is a deliberate divergence from upstream OpenJDK; see §10.4.
- Both `callAs(...)` and `doAs(...)` reject a `WorkerSubject` argument with `IllegalArgumentException`. Process/workload identity (`WorkerSubject` / `SpiffeSubject`) is always ambient through `ProtectionDomain` stamping (§8.2) and is never bound via either API.

> **Deprecation note:** `Subject.doAs(...)` is retained for backward compatibility with existing code and JGDMS consumers. It is not recommended for new development. New code should use `Subject.callAs(...)`, which integrates with the `ScopedValue`-backed subject injection described above and produces more predictable propagation semantics. Formal `@Deprecated` annotation is under consideration (see tracked issue); coordination with upstream OpenJDK is required before that annotation is applied.

### 10.3) Thread builders inside `callAs(...)`

`Thread.Builder` and builder-produced `ThreadFactory` instances created inside `Subject.callAs(...)` automatically capture the active scoped user subject because the builder `unstarted()` and `factory()` paths call `AccessController.getContext()` at creation time. A separate `doAs()` wrapper is not required to carry the `callAs()` subject into the inherited `AccessControlContext` captured by those thread-building APIs.

### 10.4) Divergence from upstream: ScopedValue fold vs. `SubjectDomainCombiner` on the ACC

This is the structural difference behind §10.2, and the unification result that makes the model tractable.

**Upstream OpenJDK (pre-JEP-486, e.g. jdk23).** `Subject.doAs` / `doAsPrivileged` wrap the execution context with a `SubjectDomainCombiner` and **attach it to the `AccessControlContext`** (via `createContext`). The Subject's principals are folded into each `ProtectionDomain` only when that combiner-bearing ACC is consulted — i.e. the Subject is *carried on the ACC*, and only a combiner-aware path mixes it in.

**DirtyChai.** The bound (user) Subject rides the `SCOPED_SUBJECT` `ScopedValue`, which **survives `doPrivileged`**, and the fold happens centrally inside `AccessController.getContext()` — which `AccessController.checkPermission` now routes through. No `SubjectDomainCombiner` is attached to the `AccessControlContext`; `acc.getDomainCombiner()` is `null` by design (the combiner runs only transiently during `getContext()`).

**The unification.** Because `checkPermission` reaches `getContext()` → `currentAll()`, the **stock `SecurityManager` and `CombinerSecurityManager` fold the bound user subject identically.** Subject-aware authorization is therefore *not* a `CombinerSecurityManager`-specific behaviour, and there is no "only the combiner-aware SM sees the Subject" caveat: the bound user is mixed in at every enforcement entry point. A `ScopedValue` is also the correct carrier for an ambient, non-sheddable identity — unlike a stack-captured combiner, a privileged frame cannot drop it.

**Latent inherited defect this exposed (fixed 2026-07-01).** `AccessControlContext.optimize()` carries an old OpenJDK shortcut — *"if there is a single stack domain already in the assigned context, skip the combine"* — that dereferences `acc.context[0]`. Upstream never reached it with an **empty** assigned context, because `doAs`/`doAsPrivileged` always attached a `SubjectDomainCombiner`, so `optimize()` took the combiner branch instead. DirtyChai, having removed that combiner, falls into the non-combiner branch; and because `Subject.doAsPrivileged(subject, action, null)` builds an **empty** assigned context (`NULL_PD_ARRAY`), the first permission check inside the action (e.g. `Subject.current()` → `checkPermission` → `getContext` → `optimize`) dereferenced `[0]` on a zero-length array → `ArrayIndexOutOfBoundsException`. Fixed by guarding the shortcut with `acc.context.length > 0` (stricter than upstream's own `assigned != null` test, which would itself miss a non-null but empty array). The defect never affected stock OpenJDK — it was a consequence of the ScopedValue rework, and every JGDMS `doAsPrivileged(…, null)` call site would have hit it under the production `SecurityManager`. Regression coverage: `qa/jtreg/org/apache/river/api/security/doAsPrivNullAcc`.

> The combiner-on-the-ACC was an *implicit contract* that `optimize()` quietly relied on. Replacing it (cleaner in itself) broke the hidden coupling and lit up the latent line — the difficulty was in the contract, not the code.

---

## 11) Thread Creation Security Semantics (Detailed)

### 11.1 Runtime permissions enforced at thread-creation entry points

When a SecurityManager is installed, Dirty Chai enforces explicit runtime permissions before creating threads:

- **Platform threads:** `RuntimePermission("createPlatformThread")`
- **Virtual threads:** `RuntimePermission("createVirtualThread")`
- **JDK-internal ("innocuous") threads:** `RuntimePermission("createInnocuousThread")`
- **Asynchronous I/O provider:** `RuntimePermission("getAsynchronousChannelProvider")`, checked in `AsynchronousChannelProvider.provider()`. The JDK's default asynchronous channel group creates its completion threads inside `doPrivileged`, so a thread permission checked at the thread factory never sees the caller. The check is at `provider()` because every route to a provider that can reach the default group goes through it: `AsynchronousSocketChannel.open()`, `AsynchronousServerSocketChannel.open()`, the `AsynchronousChannelGroup.with*` methods, and a direct call to `provider().openAsynchronousSocketChannel(null)`. A group created with a same-thread executor and then used through `group.provider()` is also stopped, because creating that group needs `provider()` first. The check is not in the provider's static holder, so a denial does not poison it. A caller that holds this permission can be given a thread that runs its `CompletionHandler`s, and that thread can be used as a counter clock, so grant it only to code that needs asynchronous I/O.

The first two checks are applied in builder paths (`ThreadBuilders`) and in public platform-thread constructor paths (`Thread`), so both modern and traditional creation APIs are guarded.

`createInnocuousThread` covers a different path: the JDK creating a thread *for* the caller under `doPrivileged`, for example a `Cleaner` thread (`Cleaner.create()`) or a `ForkJoinPool` worker started by `submit()`, `CompletableFuture.runAsync()` or `parallelStream()`. `doPrivileged` truncates the stack, so the `createPlatformThread` check does not see the original caller, and the new thread's stored context is not the caller's (for `InnocuousThread` it is a fixed, privileged context set by `InnocuousThread` itself). The check is therefore placed immediately before the `doPrivileged` at each such site, not inside a shared helper and not by removing the `doPrivileged`. It is implemented at the three `InnocuousThread` factory sites and the three `ForkJoinPool` worker-factory sites. The permission is separate from `createPlatformThread` on purpose: a domain granted ordinary threads must not thereby gain privileged-context threads. Code that depends on those paths (parallel streams, `CompletableFuture` async methods, `Cleaner.create()`) needs this grant, or must run where the grant is given.

Singletons that are created lazily on these paths (`CleanerFactory`, `CleanerImpl`, `BootstrapLogger`, `VirtualThread`, `ProcessHandleImpl`, `KeepAliveCache`, `KeepAliveStream`, `Poller`, `ThreadPool`, `java.nio.BufferCleaner`, `sun.nio.fs.Cancellable`) are initialised eagerly in `System.initPhase3`, before a `SecurityManager` can be installed. A check that ran inside a static initialiser would otherwise throw `ExceptionInInitializerError` and leave the class unusable for the whole JVM, trusted code included.

The audit of other `java.base` sites that pair `doPrivileged` with thread creation is not complete. Only the six sites above are gated.

### 11.2 Builder methods vs traditional constructors

The implementation distinguishes context capture behavior:

- **`Thread.ofPlatform()` / `Thread.ofVirtual()` builders** capture an `AccessControlContext` at builder `unstarted()` / `factory()` creation points and propagate that captured context to created threads/factories.
- **Inside `Subject.callAs(...)`**, that captured context includes the active scoped `UserSubject` values because the builders call `AccessController.getContext()`.
- **Public platform-thread constructors** also default to `AccessController.getContext()` when no explicit inherited `AccessControlContext` is supplied, so constructor-created platform threads capture the active scoped subject at creation time too.
- **Inside `Subject.doAs(...)`**, propagation still depends on the older subject-bearing ACC snapshot established at the `doPrivileged` boundary.

In this codebase, the builder path remains the explicit mechanism for thread-factory workflows, but both builders and public platform-thread constructors rely on `AccessController.getContext()` capture for `callAs()`-scoped user subjects.

### 11.3 Platform thread builder behavior

For platform builders:

1. Permission check for `createPlatformThread`
2. Capture caller context with `AccessController.getContext()`
3. If inside `Subject.callAs(...)`, inject active scoped non-`WorkerSubject` identities into the captured ACC
4. Create thread/factory with captured inherited security context
5. Apply group/priority/daemon/UEH builder options

### 11.4 Virtual thread builder behavior

For virtual builders:

1. Permission check for `createVirtualThread`
2. Capture caller context with `AccessController.getContext()`
3. If inside `Subject.callAs(...)`, inject active scoped non-`WorkerSubject` identities into the captured ACC
4. Create virtual thread/factory with captured inherited security context
5. Preserve configured characteristics and exception handler

### 11.5 Security implication

For Subject-aware authorization, prefer `Thread.Builder` / builder-produced `ThreadFactory` created inside the intended Subject scope. Inside `Subject.callAs(...)`, builder capture automatically includes the active scoped user subject through `AccessController.getContext()`. `Subject.doAs(...)` remains available, but it follows the older ACC-snapshot path rather than the newer scoped-subject injection path.

### 11.6 Executors, ThreadFactory, Thread, and AccessControlContext

This section mirrors the thread-creation analysis for adjacent APIs that define runtime execution boundaries.

#### 11.6.1 `Executors`

- `Executors.newVirtualThreadPerTaskExecutor()` delegates to `Thread.ofVirtual().factory()`, so security context behavior follows the capture semantics of a virtual-thread builder-produced factory.
- `Executors.defaultThreadFactory()` returns a platform builder-based factory (`Thread.ofPlatform()...factory()`), so creation-time context capture is aligned with builder flows.
- `Executors.privilegedThreadFactory()` explicitly captures `AccessControlContext` and context class loader at factory creation, then runs work under `AccessController.doPrivileged(..., capturedContext)`.

**Operational guidance:** construct executor services in the intended Subject scope (`Subject.callAs(...)` / `Subject.doAs(...)`) when policy grants require principal-aware execution.

#### 11.6.2 `ThreadFactory`

- `Thread.Builder.factory()` checks `RuntimePermission("createPlatformThread")` or `RuntimePermission("createVirtualThread")` at factory creation.
- Builder factories store captured `AccessControlContext` and apply it to each `newThread(...)` call, yielding consistent inherited security context across produced threads.
- This is stronger and more predictable for Subject propagation than ad-hoc thread construction in mixed caller contexts.

#### 11.6.3 `Thread` (constructors and builders)

- Public platform-thread constructors perform platform-thread permission/checkAccess flow and set inherited context from either an explicit `AccessControlContext` parameter or `AccessController.getContext()`, so `Subject.callAs(...)`-scoped user subjects are captured there as well.
- `Thread.ofPlatform()` / `Thread.ofVirtual()` builder paths document and implement explicit inherited-context capture behavior used by both `unstarted/start` and `factory`.
- In this codebase, builder flows are the recommended mechanism when consistent Subject-bearing context inheritance is required.

#### 11.6.4 `AccessControlContext` and `AccessController.getContext()`

- `AccessController.getContext()` snapshots current effective context (including inherited context and limited-privilege scope), then injects any active scoped non-`WorkerSubject` identities from `Subject.callAs(...)` before returning the optimized `AccessControlContext`.
- `AccessControlContext.checkPermission(...)` evaluates against the encapsulated context (not merely the current thread at check site), enabling safe handoff to worker execution paths.
- Dirty Chai retains authorization-focused ACC behavior and hardens context construction so unauthorized context creation does not result in privilege escalation.

### 11.7 Clock resolution and timing channels

Timing side channels (cache timing, and covert channels between code that shares a JVM) need a clock finer than the effect being measured. Dirty Chai reduces what downloaded code can read, in three parts. None of them eliminates timing channels (see section 13).

**Reduced nanosecond clock resolution (`au.zeus.jdk.nanoTime.granularity`).**

- The property is a VM start-up property, given as `-Dau.zeus.jdk.nanoTime.granularity=<nanoseconds>`. It is read once, at the end of `Arguments::parse`, and cached in `os`. Calling `System.setProperty` afterwards has no effect on the clock.
- The value must be a power of two and less than one second, so the largest accepted value is 2^29 (536,870,912 ns). It is parsed with HotSpot's integer syntax, so the size suffixes `k`, `m`, `g`, `t` (powers of 1024) and `0x` hexadecimal are accepted. A value of 1 means no coarsening.
- If the property is unset, the clock keeps its native resolution. If it is set to a value that does not parse, is not a power of two, or is one second or more, the VM refuses to start and prints the reason. A malformed value never falls back to full resolution (fail-secure).
- Readings are floored, so they never move backwards. `System.nanoTime()` is floored on the monotonic clock. `Instant.now()` and `Clock.systemUTC()` reach the VM through a different native entry (`VM.getNanoTimeAdjustment`); the nanosecond-of-second field is floored there, so a granularity of 2^30 or more would have made them tick once a second, which is why the limit is below one second.
- The coarse clock is applied at every point where Java code can read the clock: the interpreter and native entry `JVM_NanoTime`, the C1 and C2 intrinsics for `System.nanoTime()`, `JVM_GetNanoTimeAdjustment`, and the function address exported to JVMCI compilers (published under the unchanged name `os::javaTimeNanos`).
- Not changed: `System.currentTimeMillis()` (already about 1 ms), and every use of the clock inside the VM itself (garbage collection, safepoints, handshakes, JFR, logging, JVMTI, compilation policy). Those need full resolution and are not reachable by downloaded code.
- The granularity applies to the whole JVM. It is meant for the process-isolated JVM that hosts one remote principal's downloaded code (see `PROCESS_ISOLATION.md`). Client and server JVMs normally leave it unset. A benchmark that times a single operation shorter than the granularity cannot run with it set.

**Clock sources other than `nanoTime`.**

- `ThreadMXBean` thread CPU and user time have nanosecond resolution and are not covered by the property. The six methods that read them in `ThreadImpl` (`getCurrentThreadCpuTime`, `getCurrentThreadUserTime`, `getThreadCpuTime(long)`, `getThreadUserTime(long)` and the two `long[]` forms exposed through `com.sun.management.ThreadMXBean`) call `Util.checkMonitorAccess()`, so they require `ManagementPermission("monitor")`. The check is the first statement in each method, before the check that CPU timing is supported and before the virtual-thread test, so a caller without the grant learns neither.
- Known gap: `OperatingSystemMXBean.getProcessCpuTime()` has no permission check. On Linux it is read with `times()` and is quantised to the kernel tick (normally 10 ms), so it is not a useful clock for cache timing.
- `Perf.highResCounter()` and the JFR counter are guarded by `RuntimePermission("sun.misc.Perf.getPerf")` and `FlightRecorderPermission` respectively.

**Coarsening and the thread gates work as a pair.** A program that can start a thread can build a fine clock by counting in a loop on another thread, whatever `nanoTime` returns; web browsers hit the same problem and had to disable shared-memory counters when they coarsened `performance.now()`. The `createPlatformThread`, `createVirtualThread` and `createInnocuousThread` checks (section 11.1) are what stop downloaded code starting such a thread. Coarsening without the gates leaves the counter clock; the gates without coarsening leave `nanoTime` free.

**Launcher requirements (not enforced by the VM).** A JVM that hosts downloaded code should additionally be started with `--finalization=disabled` (removes the finalizer thread as a counter), `-Djava.util.concurrent.ForkJoinPool.common.parallelism=0` (the common pool then never runs, at the cost that `submit()` and `runAsync()` on it time out), and a module set that leaves out `java.management`, `jdk.management` and `jdk.jfr` when the code does not need them (`--limit-modules`). `JAVA_TOOL_OPTIONS` and `_JAVA_OPTIONS` must not be able to change the property. These belong in the `SubProcessLauncher`, which is not yet wired in production.

**Covered by tests** (`test/jdk/ai/java/lang`, group `tierAI`): `NanoTimeGranularityTest`, `InstantGranularityTest`, `NanoTimeGranularityBadValueTest` and `ThreadCpuTimePermissionTest`. Each test header records the negative controls that were run.

---

## 12) Threats Addressed

- Reflection/proxy/generated-code attempts to bypass SecurityManager installation controls
- `Method.invoke()` and `MethodHandle.invoke*()` attempts to install a custom
  `SecurityManager` (blocked by `validateCallerStackWithStackWalker()`)
- Reflective or MethodHandle calls that traverse a trusted native wrapper without
  `doPrivileged` (untrusted caller `ProtectionDomain` remains on stack)
- Untrusted finalizer or `Cleaner` callbacks attempting sensitive operations (untrusted
  class `ProtectionDomain` is present on finalizer/Cleaner thread stack; finalizer
  threads now run with `AccessControlContext.neverPrivileged()`, and `Cleaner`
  callbacks run on `InnocuousThread` with no permissions)
- Untrusted code triggering `<clinit>`, `invokedynamic` bootstrap methods, or
  `CONSTANT_Dynamic` bootstrap methods of trusted classes (untrusted PD on stack)
- Privilege escalation via overly broad or inherited permission assumptions
- Policy bypass through malformed/ambiguous code source handling
- Unauthorized execution through missing grant constraints
- Ordinary-object deserialization via `ObjectInputStream.readOrdinaryObject()` is
  guarded by `SerialObjectPermission` before object instantiation
- Proxy-class descriptor deserialization via `ObjectInputStream.readProxyDesc()` is
  not covered by `SerialObjectPermission`; proxy-deserialization gadget chains are
  therefore not blocked by the current guard placement (see G-3 in section 13)
- **Content substitution / dependency confusion**: an attacker serving a different artifact
  at a trusted URL cannot satisfy a `digest`-constrained grant — the policy will not match
  unless the artifact's SHA-256 (or other allowed algorithm) matches the pinned value in the
  `digest` clause
- **SPIFFE workload identity forgery**: `SpiffeSubject` is only constructible inside
  `SpiffeCredentialManager` via a `private` constructor, so external code cannot fabricate
  a `SpiffeSubject` and inject forged SPIFFE principals into a `ProtectionDomain`
- **Fine-grained clocks for timing side channels** (reduced, not eliminated): with
  `au.zeus.jdk.nanoTime.granularity` set, `System.nanoTime()`, `Instant.now()` and
  `Clock.systemUTC()` are no finer than the configured granularity in the interpreter, C1,
  C2 and JVMCI-compiled code; thread CPU and user time require
  `ManagementPermission("monitor")` (section 11.7)
- **Counter-thread clocks built from JDK-created threads**: `Cleaner.create()` and
  `ForkJoinPool` workers started on behalf of an unprivileged caller require
  `RuntimePermission("createInnocuousThread")` (section 11.1)

---

## 13) Non-Goals / Limitations

- Dirty Chai is an authorization and policy-enforcement model, not a complete malware sandbox by itself.
- Misconfigured policy can still over-grant privileges.
- Operational security still requires key management, signer governance, secure build pipelines, and review discipline.
- **Trusted-code confused-deputy:** Dirty Chai cannot prevent a trusted class from using
  unrestricted `AccessController.doPrivileged(...)` on paths reachable from untrusted code.
  This is a design obligation for trusted library authors (see `CONTRIBUTING.md` and
  `PROCESS_ISOLATION.md`, "Task N-6 / Confused-Deputy Guidance").
- **Finalizer/Cleaner context escape:** The creator thread's `AccessControlContext` is not
  propagated to finalizer or `Cleaner` threads. Finalizer threads are now unprivileged,
  reducing the residual gap surface, but trusted-object context loss remains. If a trusted
  object's finalization behavior must be restricted by the creator's context, that
  constraint must be enforced at construction time or through an explicit `close()`
  pattern.  Process isolation is the mitigation for this residual gap (see
  `PROCESS_ISOLATION.md`, N-9 analysis).
- **G-3 confirmed — proxy deserialization gap:** `SerialObjectPermission` currently guards
  `ObjectInputStream.readOrdinaryObject()` but not `readProxyDesc()`. Streams that reach
  object creation through `TC_PROXYCLASSDESC` therefore do not hit the current
  `SerialObjectPermission` guard placement.
- **Timing channels are reduced, not eliminated.** Remaining after section 11.7:
  - timing by the proxy's own server over the network (the proxy exists to talk to it; network jitter bounds the resolution, so it is poor for cache lines but adequate for coarser channels);
  - published techniques that amplify a coarse clock, including clock-edge amplification: the clock is floored, with no jitter, so a program that spins until a reading changes can recover a finer clock from the edge (jitter is not implemented);
  - the microarchitectural layer: cache attacks need only shared cache hardware, so they are reduced only by the process boundary together with pinning isolated JVMs to disjoint physical cores (`PROCESS_ISOLATION.md`), and nothing in the current code does the pinning;
  - JDK thread-creation sites that pair `doPrivileged` with thread creation and have not yet been audited (section 11.1). A probe on 2026-10-28 found one such path: code granted only `SocketPermission` `connect,resolve` could open an `AsynchronousSocketChannel` and have its `CompletionHandler` run on an `InnocuousThread` (created by `sun.nio.ch.ThreadPool.defaultThreadFactory()` inside `doPrivileged`), a thread that served as a counter clock (about 7.6 ns per tick). That path is now closed by `getAsynchronousChannelProvider` (section 11.1). Other sites of the same shape, such as the privileged factories in `Executors` and `StructuredTaskScopeImpl`, have not been read;
  - `OperatingSystemMXBean.getProcessCpuTime()` has no permission check (section 11.7).
- **`au.zeus.jdk.nanoTime.granularity` is per JVM and is only a mitigation when downloaded code runs in its own JVM.** Set in a JVM that also hosts trusted code, it degrades that code's timing for no benefit. It also relies on a `SecurityManager` with a restrictive policy: the thread and `ManagementPermission` checks do nothing in a JVM that has no `SecurityManager`. Once a `SecurityManager` is installed it cannot be removed (`System.setSecurityManager(null)` throws `IllegalArgumentException`). Replacing it needs `RuntimePermission("setSecurityManager")`; because privileged blocks are limited to the calling class's own grants, even `java.base` has no authority to fall back on, so a deployment policy that grants the permission to no code at all makes replacement impossible. The remaining exposure is therefore a JVM started without a `SecurityManager`: the launcher must install one at start-up, before any downloaded code is loaded, and no deployment policy may grant `setSecurityManager` to anything. The VM does not enforce this: with `java.security.manager` unset or set to `allow` the JVM starts with no manager, and code that runs before one is installed can install a trusted `SecurityManager` or `CombinerSecurityManager` with only a non-null check. The launcher for a JVM that hosts downloaded code must therefore pass `-Djava.security.manager=default` (or another explicit installing value, never `allow` or nothing) on the command line, so that `System.initPhase3` installs the manager before any application code runs.

---

## 14) Recommended Deployment Pattern

1. **Stage/Audit** with `polpAudit` (`SecurityPolicyWriter`) to discover required permissions.
2. Review and narrow grants (remove over-broad file/socket/all-permission entries).
3. **Production** with strict policy and SecurityManager enabled.
4. Keep policy and signer trust material under change control and audit.

### 14.1 Where a smart proxy runs: trusted and untrusted

- **Trusted proxy:** may run in the client's JVM, or in an isolated process where the class-evolution and backward-compatibility benefits of a separate class path are wanted.
- **Untrusted proxy:** must run in an isolated process. The containment below (a kill, a CPU pin, a lease) can only be applied to a process; a stalled thread cannot be stopped inside the client's JVM.
- **Trust is assigned per SPIFFE ID.** The client's policy decides which SPIFFE IDs of remote servers are trusted and which are not. A valid identity is necessary and is not sufficient: it proves who the server is, and the client's policy decides what that identity is trusted to do. The ID in question is the remote server's, which is also the key under which isolated processes are pooled.
- **Default:** a server whose ID the policy does not mark as trusted is untrusted, so its proxy runs isolated. The other vouching evidence in the design is a SCAP verdict and a pinned content digest. How the classification is implemented has not been reviewed for this section.
- A stranger can hold a valid identity, and a new identity may cost little, so for IDs that are not trusted, attribution, revocation, per-identity detection and rate limits are telemetry and must not be the only control.
- A trusted ID is trusted only as far as the server behind it is uncompromised. A compromised trusted server's proxy in the client's JVM has no containment, so isolating trusted proxies as well is a defence in depth that is bought at the cost of the process overhead.

### 14.2 Containment of an untrusted proxy JVM

This is the deployment intent. The launcher that applies the process-level items is not yet wired in production (the `SubProcessLauncher`).

- **Security manager:** installed from the command line (section 13); `setSecurityManager` granted to no code.
- **Permissions:** the proxy declares the permissions it needs and the client grants from a pre-authorized list. For an untrusted proxy that is `SocketPermission` `connect,resolve` to its own server only, with `SocketPermission` also granted to the system classes that perform the connection, for that server only, which is safe because each proxy JVM serves one remote principal. It receives no `createPlatformThread`, `createVirtualThread`, `createInnocuousThread`, `getAsynchronousChannelProvider` or `ManagementPermission`. It runs on the thread JERI supplies for the call and creates none (section 11).
- **CPU:** pinned to one CPU, with a cgroup CPU quota and memory and process-count limits. A runaway loop then costs at most one core and cannot starve the client or other proxies.
- **Stall handling:** the client's stub sets a deadline on each call. When it expires the launcher kills the process with `SIGKILL`. The kill must come from outside the proxy JVM: a stalled JVM can be frozen at a safepoint, and on one CPU the proxy competes with the JVM's own threads. Killing one process ends all in-flight calls to that one server's proxies; this is the accepted cost.
- **Lease:** the process holds a lease that trusted code inside it renews periodically; the launcher kills the process if the lease lapses. A lease detects an orphaned process (the client has gone) and a wedged JVM. It does not detect a spinning call, because the renewal thread still gets scheduled, so it complements the per-call deadline and does not replace it. The lease term must allow for scheduling delay on a single shared core, and the renewal path must share no lock, logger or class-initialisation lock with proxy code, or a hostile proxy could force a false kill.
- **Control threads:** handle the admin and control channel on platform threads. With one CPU the virtual-thread scheduler has one carrier, so a tight loop in a virtual thread starves every other virtual thread in that JVM.
- **Network:** the `SocketPermission` grant limits which server the proxy can reach only while the security manager holds. Because all proxy JVMs share one uid, an operating-system egress restriction (for example a per-proxy network namespace) is the second layer.
- **Launcher flags:** those listed under "Launcher requirements" in section 11.7.
- **Calls toward the client:** the proxy originates no call toward the client; the wire handoff is client-initiated only. A handback object (a remote reference that the client passes as an argument) is the one way a proxy can call the client. Each is an explicit capability, and calls through it reveal how long the client takes to answer, so for an untrusted proxy its implementation must be trivial and uniform in response time, or no handback object should be passed. What the proxy still sees is what the client gives it: the arguments, and the arrival times and sizes of the client's calls. That is traffic analysis and is inherent in being the callee.
- **Memory-corruption hardening:** run the proxy host with address space layout randomisation (ASLR) enabled, so that a memory-corruption bug in the JVM's native code is harder to turn into code execution. This is a breakout defence and not a timing defence: the cache channels measure the proxy's own accesses against shared physical hardware, so the victim's virtual layout does not affect them, and ASLR is itself often defeated by cache and TLB timing. Linux and OpenBSD enable ASLR by default, as far as is known; Solaris 11.1 and later controls it with `sxadm`, and by default randomises only binaries tagged for it. This was not verified for any particular platform.
- **Linux operating-system controls** (for a Linux proxy host; none was written or tested for this document): SELinux multi-category security gives each proxy process its own category pair, which separates files, signals, `ptrace` and shared memory between proxies that share a uid, and policy can confine files (the JDK image, the policy files and a working directory; a read-only label on the CDS archive; no access to `/tmp/hsperfdata`) and the TCP ports the process may connect to. Port rules do not name destination hosts, so they need packet labelling or a firewall rule as well. The JIT needs executable memory, which the policy must allow. The launcher can also apply `seccomp` (system-call filtering) and Landlock (file restrictions applied by the process to itself), and AppArmor is a path-based alternative. The OpenBSD counterparts are `pledge`, `unveil` and `pf` (not checked here). None of these affects timing channels, and none protects against a compromised kernel.

### 14.3 Side-channel requirements for an untrusted proxy

Reducing clock resolution and denying thread creation (section 11.7) make timing attacks slower. They do not stop a determined proxy. Against a fine timer, a proxy can observe its own core, and the last-level cache and memory system that other cores share; published work has run cache attacks from managed code. What it could learn from the client or from other proxy JVMs is whether they are active, timing of operations that depend on data, and co-residency. To reduce that:

- Give each proxy group whole physical cores, with the sibling hyperthread idle or in the same group. Pinning to one logical CPU alone leaves an SMT sibling shared.
- Partition the last-level cache and memory bandwidth per proxy group where the CPU supports it (for example `resctrl`, Intel CAT and MBA, or the AMD equivalent).
- Do not load the process's SVID private key into the proxy JVM. Speculative-execution attacks work inside one address space, so a timer helps a gadget in the JDK read the key, and the security manager does not stop that.
- Keep CPU microcode and kernel mitigations current.
- Shared file-backed pages (the CDS archive, `libjvm`, `libc`) can be probed across processes. `-Xshare:off` gives private class data but loses the fail-loudly property of `-Xshare:on` for a damaged archive; the choice is a trade-off to be made per deployment.
- Same-uid prerequisites: `kernel.yama.ptrace_scope` of at least 1, and a CDS or AOT archive that is mode `0444` and owned by a trusted uid, never writable by the proxy uid.

**When cache isolation is required.** Cache isolation (separate hardware, or dedicated cores with a partitioned cache) is required whenever a long-lived secret, or another principal's high-value material, shares the chip with an untrusted proxy. Pinning the proxy to an in-order core and randomising the clock together make an attack slow and noisy, but they do not make a shared cache safe: randomised edges defeat clock-edge amplification and not amplification by repetition, and an in-order core removes the speculation attacks and not the cache-timing ones. If an untrusted proxy shares a chip only with proxies of the same trust class, and no long-lived secret is present, the residual cache leakage may be accepted. Timing randomisation is not implemented; it is an optional extra for the case where untrusted proxies must run beside sensitive work.

**Confidential computing (AMD SEV-SNP, Intel TDX, Arm CCA).** These protect a guest's memory contents from the host and the hypervisor. The vendors' threat models exclude timing and cache side channels: AMD lists them as out of scope for SEV-SNP, Intel TDX has partial mitigations only, AMD described the TDXRay techniques as already known and out of scope, and neither vendor plans mitigations for TEE.Fail. The encryption sits at the memory controller, so data in the caches is plaintext and access patterns in a shared cache stay visible to co-resident code. A confidential VM therefore does not stop a neighbouring proxy VM from timing it, and it does not constrain what its guest does. Use these technologies, if at all, for remote attestation (the client verifies a proxy host's measurement before releasing user tokens) and to protect secrets from the operator of a proxy host. Published attacks against both SEV-SNP and TDX also add attack surface. The side-channel scope of Arm CCA was not verified.

**Platform note: separate hardware.** Untrusted proxies run as a group on separate hardware from the client and from any other workload that holds long-lived secrets. The proxy originates no call toward the client, so a proxy on separate hardware shares no cache or memory system with the client and has nothing of the client's to time. The connection between the client and the proxy host is then JERI over TLS with SPIFFE identities instead of a Unix domain socket. A trusted agent on the proxy host should terminate the TLS and reach the untrusted JVM over a local Unix socket, so that the SVID private key stays out of untrusted memory. Spawning, killing and lease renewal become remote operations: the remote launcher is a sensitive component and needs authentication, authorization (a client may start proxies only for itself), quotas and a kill, and a lapsed lease still fails safe. A host that serves a single remote principal keeps an operating-system egress allowlist meaningful; proxies of different principals that share a host also share its caches and memory system.

The separate hardware can be a separate machine or board, or an Arm system on a PCIe card (a DPU or SmartNIC) that has its own cores, memory, operating system and network ports. Examples found in a search, none evaluated here, are SolidRun's SolidNET cards (NXP LX2162A, 16 cores), NVIDIA BlueField (Cortex-A72 or A78) and the Xsight Labs E1 (Neoverse N2). A card shares the chassis and the PCIe link with its host, so treat it as an untrusted peripheral: restrict its DMA with the host IOMMU, keep the host-side driver minimal, and check the provenance of its firmware updates. Its egress firewall runs on the card, and the client reaches it through a virtual network interface across PCIe.

Another form is a rack of single-board blades, each a complete small computer with its own cores, memory, network port and power feed. One example is the Compute Blade, a rack carrier for Raspberry Pi CM4 and CM5 modules with PoE+ power, 1 GbE, an NVMe slot, and a TPM 2.0 option (from the vendor's product page; not evaluated here). Because a blade has no PCIe link to the client's host, the only boundary is the network, and one blade per remote principal fits the rule above. Points to check: a managed switch can enforce a VLAN and an egress allowlist per blade, and can cut a blade's PoE power, which gives a kill that the blade's operating system cannot resist; a blade should be stateless (network boot with a read-only root, or reimaged between uses) so that a compromised proxy cannot persist; a TPM could support measured boot so that the client can check what a blade runs before releasing user tokens; the cores of these modules speculate (as far as is known, the Cortex-A72 in the CM4 and the Cortex-A76 in the CM5 are out-of-order), so the benefit comes from the separate hardware and not from the core type; and the Raspberry Pi boot chain is largely proprietary, so the secure-boot claim, operating-system support and memory error protection have not been verified.

A heterogeneous Arm SoC can place untrusted proxies on in-order cores that are not affected by the speculative-execution attacks, but the cores in one cluster share the last-level cache, so this is not hardware separation. Other operating systems provide different controls and must be checked per platform. For example, OpenBSD has no per-process CPU pinning or cache partitioning that is known to be available. OpenBSD 7.9 adds a system-wide sysctl, `hw.blockcpu`, which takes a sequence of letters selecting what to remove from the scheduler (S for SMT, P for regular performance cores, E for efficient cores, L for lethargic cores; the default is `SL`) and currently works on amd64 and arm64. It is a property of the whole machine, not of a process, so it can configure a dedicated proxy host to use only certain core classes but cannot place one process on a different class from another. The classes are defined by speed, not by microarchitecture, so whether a class corresponds to in-order cores has to be checked for each board.

None of this is implemented in the repository yet; it is a deployment requirement.

---

## 15) Security Invariants (Must Hold)

1. Trusted SecurityManager checks use exact class identity, not subclass trust.
2. Custom SecurityManager installation requires all validation layers.
3. Privileged execution must remain caller-sensitive and context-bounded.
4. Policy evaluation must remain deny-by-default.
5. Validation failures must remain fail-secure.
6. `WorkerSubject` is never injected via scoped-subject handling into an `AccessControlContext`; process identity remains ambient via `ProtectionDomain`.
7. Neither `Subject.callAs(...)` nor `Subject.doAs(...)` accepts a `WorkerSubject` as a bound subject; both throw `IllegalArgumentException`. Process identity is always injected exclusively through `ProtectionDomain` principal stamping at class-load time.
8. A `DigestGrant` never implies a domain whose `CodeSource` is a plain `CodeSource` — the `CodeSource` must be a `DigestCodeSource` with a matching algorithm and digest; otherwise the grant does not apply.
9. `SecureClassLoader` stores a `ProtectionDomain` in `pdcache` only after all permission checks have passed and the digest has been computed; a plain `CodeSource` key is never stored, so no cache hit can bypass the digest requirement on a subsequent `defineClass` call.
10. SPIFFE principal injection into `ProtectionDomain` occurs only when the VM is fully booted (`VM.isBooted()`), a `SecurityManager` is active, and `SpiffeCredentialManager.getSubject()` returns a non-null read-only `SpiffeSubject`; all other conditions result in `pals = null` (fail-secure: no SPIFFE principals injected rather than forged ones).
11. When `au.zeus.jdk.nanoTime.granularity` is set, no clock readable by Java code through `System.nanoTime()`, `Instant.now()` or `Clock.systemUTC()` is finer than the granularity, in the interpreter, C1, C2 and JVMCI-compiled code; the value is fixed at VM start and cannot be changed by running code; a value that does not parse, is not a power of two, or is one second or more prevents the VM from starting.
12. Reading a thread's CPU or user time through `ThreadMXBean` requires `ManagementPermission("monitor")` on every entry point, and the check precedes the support and virtual-thread tests so that its outcome does not depend on them.
13. Where the JDK creates a thread for its caller under `doPrivileged` (`InnocuousThread` factory methods and `ForkJoinPool` worker factories), `RuntimePermission("createInnocuousThread")` is checked before the `doPrivileged`, not inside a shared helper, and never in a static initialiser: the singletons those paths use are initialised in `System.initPhase3` before a `SecurityManager` can be installed.

---

## 16) Related Documents

- `SECURITY_ANALYSIS.md` (detailed findings and historical fixes)
- `STACK_VALIDATION_ANALYSIS.md` (stack-validation trade-offs)
- `VULNERABILITIES_ADDRESSED.md` (resolved issues)
- `SECURITY.md` (security policy and reporting)
- `PROCESS_ISOLATION.md` (reflection/MethodHandle N-8, finalizer/Cleaner N-9, class-init N-10, consolidated lifecycle analysis with attach gating N-11, test plan N-12)
- SPIFFE/SPIRE implementation details: `src/java.base/share/classes/au/zeus/jdk/authorization/spire/`
