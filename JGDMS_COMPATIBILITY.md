# JGDMS Compatibility on Dirty Chai

**Last Reviewed:** 2026-10-19

Dirty Chai re-exports key JGDMS authorization API contracts from the platform `java.base` module so existing JGDMS applications can run without recompilation.

## Re-exported API Surface

Dirty Chai provides the following types in `org.apache.river.api.security`:

* `ScalableNestedPolicy` (interface)
* `PermissionGrant` (abstract class)
* `PermissionGrantBuilder` (interface)

These are the compatibility contracts used by JGDMS policy components and by Dirty Chai's authorization implementation.

## Split Package: `org.apache.river.api.security`

The package `org.apache.river.api.security` is intentionally split between `java.base` and the unnamed module (classpath). This is a deliberate design decision, not an oversight.

Classes in this package that require privileged access to platform internals — for example, `SocketPermission.init()` and other security-sensitive APIs — cannot reside in a named application module because the platform access they require is only granted to code in `java.base`. These classes are therefore defined in `java.base` in Dirty Chai.

However, JGDMS has historically published additional classes in this same package — such as `AbstractPolicy` — that have no relevance to Dirty Chai's platform implementation but must remain loadable by the application classloader for binary compatibility with existing JGDMS deployments.

## ClassLoader Hierarchy and the Split Package Exemption

The Java Platform Module System (JPMS) prohibits split packages between two **named** modules. However, the unnamed module (classpath) is explicitly exempt from this prohibition — this is a deliberate JPMS concession for backward compatibility, documented in the Java module system specification.

Dirty Chai takes advantage of this exemption. `org.apache.river.api.security` is owned by `java.base` as a named module, but additional classes in the same package can still be loaded from the classpath via the unnamed module. Dirty Chai modifies `BuiltinClassLoader.loadClassOrNull()` to support this: when the platform loader cannot find a class in `java.base` for this specific package, loading falls through to the application classpath rather than failing. The check is gated precisely on the package name `org.apache.river.api.security` so no other module-owned package is affected.

Class resolution at runtime therefore works as follows:

1. `AppClassLoader.loadClassOrNull()` finds `org.apache.river.api.security` in `packageToModule`, owned by `java.base`.
2. It delegates to the platform loader.
3. The platform loader searches `java.base` — classes defined there (e.g. `PermissionGrant`, `ScalableNestedPolicy`, `PermissionGrantBuilder`) are returned immediately, preserving platform precedence.
4. For classes not present in `java.base` (e.g. `AbstractPolicy`), the platform loader returns `null`.
5. Dirty Chai's modified `BuiltinClassLoader` detects the null result for this package and falls through to the application classpath, where the JGDMS JAR is found.

Platform types always take precedence. Classpath classes in this package can never shadow or replace types already defined in `java.base`.

## Security Considerations

Allowing classpath classes to be loaded into a module-owned package is a controlled relaxation of the default JPMS split-package prohibition. The security implications are:

* Classpath classes in `org.apache.river.api.security` are loaded by the application classloader into the **unnamed module** — they do not gain any platform module permissions.
* They cannot replace or shadow the platform types in `java.base`, which are always resolved first.
* In a Dirty Chai deployment using `LoadClassPermission`, the policy controls which code sources are permitted to define classes at all, providing a meaningful defence-in-depth layer that makes the relaxed split-package behaviour safe in practice.
* The fallthrough in `BuiltinClassLoader` is gated on an exact package name match, minimising the scope of the exemption to only the affected package.

## Future Modularisation of JGDMS

If JGDMS is later modularised, the split package constraint must be respected: two **named** modules cannot share a package. The recommended approach is:

* Modularise the bulk of JGDMS as a named module (e.g. `org.apache.river.api`) with its own packages.
* Keep the `org.apache.river.api.security` classes that require platform access, or that exist solely for binary compatibility with the classpath, in a **separate unnamed JAR on the classpath**.

This preserves the unnamed module exemption indefinitely and keeps privileged platform-access code physically separated from the rest of the JGDMS module graph — which is desirable from an audit and least-privilege perspective regardless of the compatibility requirement. The `BuiltinClassLoader` modification in Dirty Chai remains valid under this arrangement without further changes.

## `defineClassInPackage` Permission Considerations

JGDMS publishes additional classes in `org.apache.river.api.security`. When those classes are defined by application loaders under an active `SecurityManager`, package-definition checks may require:

* `RuntimePermission "defineClassInPackage.org.apache.river.api.security"`

This is handled by the normal least-privilege audit cycle. Dirty Chai's `SecurityPolicyWriter` (`-Djava.security.manager=polpAudit`) automatically discovers required grants during staged execution and appends them to policy output for review.

## Dynamic Grants: Per ProtectionDomain of the Verified Codebase

> **Status:** design agreed 2026-10-18, being implemented in both trees. The full specification
> and the changes it makes to the earlier JGDMS implementation are in JGDMS
> `docs/SOW-PermissionGrant-Mirror-and-ProtectionDomain-Grants.md`, section 7.

JGDMS makes dynamic grants to proxies after verifying them. Those grants used to apply to the
proxy's class loader as a whole (`PermissionGrantBuilder.CLASSLOADER`, a `ClassLoaderGrant`): every
domain the loader defined received them, whatever its code source, signers or digest. That covered
classes the verification never saw: a jar fetched lazily after its content changed, a URL added
later with `URLClassLoader.addURL`, or bytes defined through a path that skipped the check. A grant
for code that was verified now applies only to domains whose code-source identity was verified.

There are two kinds of dynamic grant, chosen by what the caller could verify:

| Caller | Grant | Applies to a `ProtectionDomain` when |
|---|---|---|
| A codebase verified with a digest per jar, through `Security.grant(Class, CodeSource[], Principal[], Permission[])` | `DigestDomainGrant` (`PermissionGrantBuilder.DIGEST_DOMAIN`) | it was defined by the proxy's loader, the grant's principals are satisfied, and its code-source identity is one of those supplied |
| Anything else: `Security.grant(Class, Permission[])`, codebases with signers only or location only | `ClassLoaderGrant` (`PermissionGrantBuilder.CLASSLOADER`), as before | it was defined by the proxy's loader |

### `DIGEST_DOMAIN` semantics

A `DigestDomainGrant` implies a `ProtectionDomain` only if all of the following hold, checked in
this order:

1. it was defined by the granted class's loader (the loader of the class, not of its domain:
   `Security.grant` is usually given a `java.lang.reflect.Proxy` class, whose shared domain has no
   loader);
2. the grant's principals are satisfied;
3. its code source is a `DigestCodeSource` whose digest `SecureClassLoader` computed
   (`unverified()` is false);
4. its `CodeSourceKey` (RFC 3986 location, signers and digest) equals one of the identities the
   caller supplied.

The caller is JGDMS's `PreferredProxyCodebaseProvider`. After authenticating the server, it builds
one `DigestCodeSource` per jar from the per-jar digests the bootstrap proxy supplies
(`CodebaseAccessor.getCodebaseDigest()` and `getDigestOffsets()`), with the jars' signers.

Consequences:

* **Every verified jar is covered,** including jars whose first class is loaded after the grant,
  for example while a response is unmarshalled with the proxy's loader as default loader. The grant
  holds identities, not a list of domains.
* **Nothing unverified is covered,** even in the proxy's loader. That includes a jar added with
  `addURL`, a jar whose content differs from the supplied digest, a domain carrying a
  `DigestCodeSource` constructed with a supplied digest, and a domain of a mixed-signer jar whose
  signer set was not supplied. A second loader over identical jars is not covered either.
* **A digest is required.** Building with `DIGEST_DOMAIN` from a code source without a digest
  throws `IllegalArgumentException`. A digest proves the exact jar; signers alone prove only "a jar
  this key signed", so a codebase verified by signers alone uses the `ClassLoaderGrant` path.
* **Signers must match exactly.** `CodeSourceKey` compares the certificate arrays, so the supplied
  certificates must be in the order `CodeSource` obtains them from `getCodeSigners()`.
* **On a stock JDK no domain carries a digest,** so JGDMS uses the `ClassLoaderGrant` path there.
* **A class loader alone is never implied,** and neither is a bare `CodeSource`: a dynamic grant
  applies to domains.
* **The grant goes with the proxy.** It holds the loader weakly and becomes void when the loader is
  collected, which is when its domains go, since `SecureClassLoader` holds them strongly. It is not
  serialisable: it is written as its builder, and a deserialised grant is void, never a grant
  without the loader.

### `ClassLoaderGrant` remains the unverified path

`PermissionGrantBuilder.CLASSLOADER` and `ClassLoaderGrant` are **not** deprecated. They serve every
caller that cannot supply verified identities, so existing callers keep their behaviour. The grant
takes the loader from the granted class rather than from its domain, so it is effective for
`Proxy` classes.

Limit what that path can confer through policy: the caller of `Security.grant` needs
`GrantPermission` for whatever it grants. Make only low-risk permissions grantable on the
unverified path, and keep the rest grantable only through the verified overload.

### A grant is no narrower than its loader

Both kinds of dynamic grant are scoped to a loader, so two proxies sharing a loader share their
grants. `PreferredProxyCodebaseProvider` keys its loaders by the bootstrap proxy's invocation
handler (and so its `ObjectEndpoint`), the codebase and the parent loader: one loader per remote
object. A proxy sent without the bootstrap form resolves through `PreferredClassProvider`, keyed by
codebase and parent only, and may share a loader with another service's proxy; such proxies get
only the `ClassLoaderGrant` path. Per-SPIFFE-ID process isolation of downloaded proxies, planned,
separates identities into different JVMs. The isolating JVM downloads and runs foreign code and is
itself an entry point, so least privilege inside it still depends on these rules.

### `DIGEST_DOMAIN = 7`

`DIGEST_DOMAIN` is a compile-time constant, so its value is inlined into JGDMS bytecode. On Dirty
Chai, `java.base`'s `PermissionGrantBuilder` shadows JGDMS's, so the two values must be equal, and
both are `7`. Neither project has made a release with an earlier constant, so the two trees gain it
together; a mismatched build rejects context `7` and fails rather than silently changing what a
grant covers.

### Signer enforcement in static grants

* `signedBy` alone, `codeBase` + `signedBy`, and `digest` + `signedBy` grants all require every
  named signer to be present on the code source, in any order.
* Unsigned code (null or empty certificates) is not implied by any grant that names signers, and is
  never an error.
* A null `CodeSource` is not implied.
* A class loader alone is not implied by a grant that names signers, because a loader carries no
  signers.
* A `digest` grant matches on the content digest and the signers. Its `codeBase`, if present, is
  ignored, because a location is not identity.
* A `digest` grant implies only a `DigestCodeSource` whose digest was computed when its domain was
  created. One constructed with a supplied digest, or deserialised, reports `unverified()` and is not
  implied: otherwise code allowed to create a class loader could define its own bytes in a domain
  carrying a trusted jar's digest.

### Propagation by `Security.grant(fromClass, toClass)`

`DynamicPolicyProvider.getGrants(Class, Principal[])` now evaluates the class's `ProtectionDomain`
rather than its class loader, honouring the supplied principals. Permissions that came from
`signedBy` and `digest` grants therefore propagate, where they were silently dropped before.

### Unparseable `codeBase` URIs

A `codeBase` that cannot be parsed raises `SecurityException` when the grant is built, rather than
being logged and ignored. This fails closed for a new policy. Note that when an edited policy is
refreshed, `ConcurrentPolicyFile.refresh()` keeps the previous grants if parsing fails, so a typo can
leave removed privileges in force until it is corrected. Check the log after refreshing an edited
policy.

### New grant classes exist in both trees

The concrete grant classes in `org.apache.river.api.security` (`PrincipalGrant`,
`ProtectionDomainGrant`, `CertificateGrant`, `URIGrant`, `DigestGrant`, `ClassLoaderGrant`,
`DigestDomainGrant`) are package-private. On Dirty Chai, a JGDMS-only class in this package is
defined by the application loader, which makes it a different runtime package from `java.base`'s
classes of the same name. So:

* A new grant class must exist in **both** Dirty Chai's `java.base` and JGDMS, with the same
  semantics, and be built only through `PermissionGrantBuilder`, with the same context constant in
  both. A JGDMS-only subclass of a package-private grant fails with `IllegalAccessError` on Dirty
  Chai.
* JGDMS-only classes in this package (`ExternallyVoidablePermissionGrant`, `LeasedPermissionGrant`,
  `ConcurrentPolicyFile`, ...) may use only `public` and `protected` members of the `java.base`
  classes, never package-private helpers.

### Behaviour changes

* Dynamic grants made through the verified overload apply only to domains whose digest identity was
  supplied; other domains of the same loader, including jars added later, receive nothing from them.
* Dynamic grants made through `Security.grant(Class, Permission[])` are unchanged: loader-wide.
* A `digest` grant no longer implies a `DigestCodeSource` whose digest was supplied rather than
  computed.
* `Security.grant(fromClass, toClass)` propagates permissions that came from `signedBy` and
  `digest` grants.
* An unparseable `codeBase` URI raises `SecurityException`.

## Obtaining a Pre-Built DirtyChai JDK

A pre-built linux-x64 release JDK is published as a rolling GitHub Release
whenever the **Build JDK for JGDMS** workflow is run.

### Download URL

```
https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz
```

A SHA-256 checksum file is also published alongside the bundle:

```
https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz.sha256
```

### Verification and installation (shell)

```sh
wget -q https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz
wget -q https://github.com/pfirmstone/DirtyChai/releases/download/dirty-chai-latest/jdk-linux-x64.tar.gz.sha256
sha256sum -c jdk-linux-x64.tar.gz.sha256
mkdir -p dirty-chai-jdk
tar -xf jdk-linux-x64.tar.gz -C dirty-chai-jdk --strip-components=1
export DIRTY_CHAI_JAVA_HOME="$(pwd)/dirty-chai-jdk"
"$DIRTY_CHAI_JAVA_HOME/bin/java" -version
```

### Using DirtyChai as the JDK in a JGDMS Maven/Gradle build

Point your build tool at the DirtyChai JDK by setting `JAVA_HOME` before
invoking the build:

```sh
export JAVA_HOME="$DIRTY_CHAI_JAVA_HOME"
mvn test            # Maven
./gradlew test      # Gradle
```

Or pass it explicitly to Maven:

```sh
mvn -Djvm="$DIRTY_CHAI_JAVA_HOME/bin/java" test
```

### Triggering a fresh build

The workflow can be triggered manually from the **Actions** tab of the
DirtyChai repository:

1. Navigate to **Actions → Build JDK for JGDMS**.
2. Click **Run workflow**.
3. Wait for the run to complete (typically 30–60 minutes).
4. The `dirty-chai-latest` release is updated automatically.

---

## Deployment Workflow for JGDMS Applications

1. Run the application in staging with `polpAudit` enabled.
2. Exercise real startup and operational paths so required permissions are observed.
3. Review generated policy output, tighten broad grants where needed.
4. Deploy with `-Djava.security.manager=default` and a reviewed policy file.

## Performance Benefits for JGDMS Workloads

When running on Dirty Chai, JGDMS applications benefit from:

* Lock-free policy evaluation in `ConcurrentPolicyFile`
* Reduced contention through concurrent and cached permission checks
* RFC 3986 URI-based matching (no DNS lookups in policy implication path)
* Optimisations for virtual-thread and high-concurrency workloads

Since compatibility contracts are resolved from the platform loader, these performance gains are available without recompiling JGDMS code.
