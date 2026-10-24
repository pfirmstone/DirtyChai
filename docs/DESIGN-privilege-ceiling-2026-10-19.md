# Design: a privilege ceiling that `doPrivileged` cannot shed

**Status: design note, revision 4 (2026-10-23). Not implemented, not scheduled.** **Read §13 first, then §12.** Revision 4: the per-class policy-reducing intersection is applied to *every* `doPrivileged` form in `executePrivileged` (§13), which removes the elevating forms entirely; the ceiling (§3–§5) and the call-site conversion sweep (§4.6) are both superseded by one change. §12 remains as the step that led there. Records the outcome of a design
discussion between the maintainer and Claude (`claude-fable-5-1`), revised twice after reviews by and discussion
with Claude Opus (`claude-opus-5-5`), against DirtyChai `trunk` at `af6bc547954`. Companion to JGDMS
`docs/ANALYSIS-legacy-API-authority-and-reconstruction-2026-10-19.md`, whose §2 sketch and "weaknesses" list this
note answers. Nothing here has been executed; every claim about current behaviour is from reading
`java.security.AccessController`, `AccessControlContext`, `DomainIdentity`, `ProtectionDomain`, `DomainCombiner`,
`javax.security.auth.Subject`, `SubjectDomainCombiner` and `Policy`.

Revision history:
- r1: ceiling as a policy-granted sealed domain bound in a `ScopedValue`; per-thread default ceiling (`ROOT`).
- r2: `ROOT` dropped (conflicted with the AllPermission rule; bounded lazy JDK singletons); ceiling scoped like
  `Subject`; carried in contexts as an appended sealed domain, not a field.
- r3: **the ceiling caps elevation only** — it is applied when an elevating `doPrivileged` builds its
  privileged context, and plain checks are left to least privilege; the binding is an accumulating immutable
  array; platform threads take the ceiling from the inherited context, `Thread` gains nothing; all java.base
  `doPrivileged` calls convert to the policy-reducing form, which the ceiling does not apply to; §8 corrected
  (the three-argument form is intended design; the static-collection union is the defect).
- r4 (this, §13): **every `doPrivileged` form intersects the caller's per-class policy domain**, in
  `executePrivileged`; no elevating form remains; ceiling and conversion sweep superseded.

> **Authorship note:** analysis and design discussion produced with AI assistance (Claude Fable 5.1, reviewed by
> Claude Opus 5.5), under the OpenJDK Interim Policy on Generative AI as adopted in `CONTRIBUTING.md` — analysis and
> review support, not source, test or shipped documentation. It lives under `docs/`, not the repository root, so the
> *Repository Documentation Exception* in `AI_POLICY.md` does not cover it as written; the Project Lead decides whether
> it moves to the root, stays as an analysis record, or is mirrored to JGDMS (`JGDMS/docs/`) where AI-authored design
> documents are the norm. Nothing in it has been executed; every behavioural claim is from reading source.

## 0. The question, and the limit of the answer

The question that started this: **how do we prevent deserializing into a privileged context?** Anything that
bounds authority during reconstruction must survive a `doPrivileged` call made by trusted code that a
constructor reaches, because that call is exactly how a gadget converts data into authority.

The answer has two halves, and the note is careful to keep them apart:

- A **ceiling** bounds *control flow*: it caps every *elevating* `doPrivileged` made while it is in force, on the
  thread that bound it, on the virtual threads that inherit the binding, and on platform threads whose inherited
  context carries it. It is bound in a `ScopedValue`, so it is orthogonal to the stack: the native stack walk
  cannot see it and no `doPrivileged` cut reaches it.
- A ceiling cannot follow *data*. An object built under a narrow ceiling and later run by a thread outside it
  (a queue, a callback, a third-party executor) arrives with nothing attached, and a trusted-class instance built
  from attacker data is indistinguishable on the stack from one trusted code built itself. That is the taint
  problem, and it is solved the way it always was: authenticate the caller, validate the data, and do not
  construct what has not been vetted (the finite `@AtomicSerial` set, the type gate, two-phase decode — §6).

The ceiling bounds what *elevates*; least privilege bounds what runs without elevating; the vetted set bounds
what exists afterwards.

## 1. What the current fork already provides

These are prerequisites the design builds on; none need to change.

- `AccessControlContext` is immutable and interned (`ContextCache`, weak CAS table), with a sealed
  `ContextBuilder` SPI for java.base callers. The old deferred `createAccessControlContext` check was replaced
  by folding an unauthorised creator's own stack context into the new context, which closes the injection hole
  where one party built a context and another paid for it.
- `DomainIdentity` is a value-equality `ProtectionDomain` for temporary domains, with `UriCodeSource` so
  `equals`/`hashCode` never touch DNS.
- `AccessControlContext.neverPrivileged()` is a static-only, null-codesource `DomainIdentity`: `Policy` cannot
  grant to it and `SubjectDomainCombiner.combine` leaves `staticPermissionsOnly()` domains untouched. This is the
  "unprivileged marker domain" of the JGDMS analysis §2; the defect is only that it is not a ceiling.
- **Limited privilege is an intersection domain, by design.** `doPrivileged(action, ctx, Permission...)` builds
  `new DomainIdentity(getResource(caller), toPermissions(perms), null, null)` — a per-class codesource such as
  `jrt:/java.base/<Class>` that polp policy grants to — and intersects it. This replaced Java 8's limited-context
  state, which made `AccessControlContext` mutable and uncacheable, so contexts stay immutable and interned.
  The bound is per-class least privilege generated by polpAudit. (The `AccessController` class javadoc still
  describes the Java 8 semantics — "checking continues beyond the caller" — and needs updating.)
- `Subject` is carried as a `ScopedValue` that virtual threads spawned inside the scope inherit; `getContext()`
  injects current subjects by adding principals to non-static domains only, never permissions, never removing
  domains. **The ceiling uses exactly this scoping model.**
- `Policy.impliesEphemeral` defines ephemeral authority that polpAudit must never record into the generated floor.

## 2. Why earlier shapes fail

- **Static permission lists are deployment-hostile.** A ceiling expressed as `Permission...` in code is a static
  permission by another name: it cannot be corrected by policy at deployment, and when it is wrong the program
  fails or is painful to debug. polpAudit exists so that permissions are observed, documented and modified in
  policy; a ceiling must be something policy grants to.
- **A domain in a context is only as durable as the context.** The native walk builds a fresh context from
  frames; the next 1-arg `doPrivileged` cuts the walk at its caller with `privilegedContext == null`, and any
  marker domain the enclosing `doPrivileged(action, neverPrivileged())` established is gone. A constructor that
  does a property read sheds the marker. This is the JGDMS analysis's first weakness. The source of truth must
  live outside the stack (§3).
- **A per-thread default ceiling (r1) does not work.** Every thread would descend from a `ROOT` ceiling; sealed
  domains cannot be granted `AllPermission`, so `ROOT`'s grant becomes a second copy of the whole floor. JDK
  singletons start platform threads on first use (`Cleaner`, the `HttpClient` selector, timers,
  `SpiffeCredentialManager`'s channel); if first use happens during a reconstruction the thread is either refused
  or bounded for the life of the JVM, depending on which request arrived first.
- **Intersecting the ceiling on every check (r2) costs more than it buys.** `getContext()` is about 85% of a
  permission check (`ContextCaptureSplit`). Under least privilege a plain check is already bounded by the
  non-java.base floors on the stack, which always include the decoder's and the constructor's jars; only an
  elevating `doPrivileged` cut can exceed them. So the ceiling needs to touch only the elevating path.
- **A replaceable binding is an elevation.** If an inner `ceiling()` rebound the value to its own domain alone,
  the next `doPrivileged` would append only that domain, whose identity is the *inner caller's* codesource — a
  vetted constructor could call `ceiling()` with its own identity and have policy grant it more than the
  decoder's ceiling allows. The binding must accumulate (§3).

## 3. The API and its semantics

```java
public final class AccessController {
    private static final ScopedValue<ProtectionDomain[]> CEILING = ScopedValue.newInstance();

    /**
     * Runs {@code action} under a ceiling identified by the caller's codesource and {@code message}.
     * The caller is captured as for the three-argument doPrivileged. For the duration of the call the
     * ceiling is added to those already in force; every elevating doPrivileged made inside the call,
     * on this thread or on a virtual thread started inside it, is bounded by all of them.
     * {@code message} is an identifier, written as a literal at the call site, never derived from input.
     */
    @CallerSensitive
    public static <T> T ceiling(String message, Callable<T> action) throws Exception;
}
```

**Identity.** The ceiling is a *sealed* `DomainIdentity` (§4.1): codesource = the caller's per-class codesource
with the caller's signer certificates (`getResource(caller)`; see §8 on non-module classes), principals =
`{ new CeilingPrincipal(message) }`. The message is a principal rather than a URL component because the policy
grammar already matches codebase + principals, polpAudit already records principals in the floor, and a sealed
domain may *have* principals set at construction while refusing combiner-added ones.

**Policy.** Ordinary policy text, per site and per phase:

```
grant codebase "jrt:/net.jini.io/net.jini.io.AtomicMarshalInputStream",
      principal java.security.CeilingPrincipal "construct" {
    permission java.util.PropertyPermission "*", "read";
};
```

One class may run different phases under different ceilings (`"decode"`, `"construct"`, `"resolve"`). A denied
check under a ceiling is reported by polpAudit against that codesource and principal; the fix is a policy line.
Ephemeral grants to a ceiling never enter the floor, by the existing rule.

**The binding.** `ceiling()` reads the current `CEILING` array (or empty), copies it with the new sealed domain
appended, and binds the copy with `ScopedValue.where(CEILING, …).call(action)`. The array is immutable by
convention and never leaves `AccessController`; `ceiling()` is the only binder and only appends, so there is no
API through which an inner call can replace rather than extend it. `ceiling()` never calls `getContext()`.

**Scope.** Dynamic, for the duration of the call: when the call returns the previous binding is visible again,
with no unbind step and nothing a callee can do to extend it. A ceiling cannot outlive the call that established
it, except in a virtual thread started inside the call, which inherits the binding as it stood at creation and
keeps it for its life — the intended fail-closed behaviour.

**What the ceiling applies to.** Only `doPrivileged` forms that *elevate*: the one-argument form, the
two-argument (context) form, and the `doPrivilegedWithCombiner` variants. When one of these runs with a ceiling
in force, `executePrivileged` appends the ceiling's sealed domains to the privileged context it creates (for the
one-argument form, a context that was `null` becomes one holding the ceiling domains). The check then walks to
that frame and evaluates `caller ∩ privilegedContext`, so the result can only be narrower. The ceiling does
**not** apply to the three-argument *policy-reducing* form — `doPrivileged(action, ctx, perms)` with an empty
`perms` — which cannot elevate: its authority is `caller ∩ ctx ∩ policy(per-class codesource)`, per-class least
privilege by policy. A three-argument call with a **non-empty** `perms` list is treated as elevating and capped,
because of the static-collection union defect (§8): until it is converted, it grants the listed permissions to a
java.base caller regardless of policy. The runtime test is `perms.length == 0`, not the caller's module.

**Nesting.** Ceilings accumulate; their effect materialises at the next elevating `doPrivileged`, which appends
all of them. A `doPrivileged` made inside the inner call is bounded by `outer + inner`; one made after it returns
by `outer` only. If no elevating `doPrivileged` occurs inside the inner call, nesting has no effect — which is
the point: ceilings cap elevation, nothing else.

**Plain checks** (`checkPermission` with no elevating frame) are unchanged and read no `ScopedValue`. They are
bounded by the non-java.base floors on the stack. This is a **design invariant to record and enforce**: *the
ceiling caps elevation; plain checks rely on least privilege.* polpAudit or the policy loader must flag
`AllPermission`, or broad wildcard grants, to anything other than java.base; one generous platform grant reopens
the plain-check path. (The JGDMS analysis found shipped policies that violate this, M3; the lint is a
precondition.) If a per-site bound on plain checks is ever wanted, intersecting the ceiling there is a one-line
change in the check, at `getContext()` cost — a knob, not a redesign.

**`Callable`, not `PrivilegedAction`.** A distinct type tells the reader and the analyser which kind of call it
is, and the checked exception keeps `ceiling` from being used as a lambda-elevation helper. Returns the result.

**Literal message.** The runtime cannot enforce it; a computed message is bounded by the codebase's own grants,
so it is not a hole, but it corrupts the audit trail. A bytecode lint requires an `ldc` constant at every
`ceiling` call site.

**Errors.** An `AccessControlException` raised under a ceiling names the ceiling (codesource and message).

## 4. Fork touch points

1. **`DomainIdentity.sealed`.** A third mode alongside policy-granted and static-only: *policy-granted but
   sealed*. `Policy` is consulted on every check; no combiner may replace it or add principals;
   `equals`/`hashCode` include the flag. `SubjectDomainCombiner.combine` passes sealed domains through as it does
   `staticPermissionsOnly()` ones; `AccessControlContext.goCombiner` verifies after *any* combiner that every
   sealed domain of the input is still present, throwing otherwise (JGDMS's `DistributedSubjectCombiner` drops
   domains today). `DomainCombiner` contract documented: may add principals, never permissions, never remove
   sealed or static domains. `CeilingPrincipal` added.
2. **`AccessController.executePrivileged`** (elevating forms only): collect sealed ceiling domains from, in order,
   `CEILING` if bound, else the thread's inherited context (§4.4); plus any sealed ceiling domains in the context
   argument of the two-argument form. Append them to the privileged context materialised in the frame. Never
   replace, never widen: a source with none contributes nothing. The three-argument form with empty `perms` skips
   this. Throwing paths deny: a `Policy` that throws in `implies`, a combiner whose output lacks a sealed domain,
   a caller whose codesource cannot be resolved.
3. **`getContext()` splits into two paths.** The *public* `getContext()` — used for snapshots and for
   `Thread`'s inherited context at creation — appends the current `CEILING` domains to the returned context, so a
   snapshot carries the ceiling in force when it was taken and `doPrivileged(action, snapshot)` elsewhere appends
   it (§4.2). The *internal* path `checkPermission` uses does not read the `ScopedValue` and is unchanged (§3,
   plain checks). The interned key already covers domains, so `(stack, ceiling)` pairs are distinct cache
   entries; `optimize()` keeps them; a stored snapshot checked directly intersects with them. **Day-one test:**
   identical stacks with different ceilings must be distinct cache entries; a hit that returned the other would
   be a silent widening. Give the interned context a `hasSealed` flag computed at creation so §4.4's read is a
   field and a boolean.
4. **Threads — `Thread` gains no field.** Virtual threads inherit the `CEILING` binding directly, as they inherit
   `Subject`. A platform thread created inside a ceiling has no binding, and its inherited context (captured via
   the public `getContext()`, §4.3) carries the ceiling's sealed domains; `executePrivileged` on that thread
   takes them from there when `CEILING` is unbound. The java.base infrastructure factories that must start
   platform threads lazily (`InnocuousThread`, the pool factories behind `ForkJoinPool.Context`) create their
   threads from a context with no ceiling, so lazy singletons start clean. This is recorded as a reviewed
   allow-list that elevates a *fresh* thread to fixed or innocuous authority, never the current one; it is not
   to be widened. **Test:** touch each lazy JDK singleton (`Cleaner`, `HttpClient`, `Timer`, the common pool,
   `SpiffeCredentialManager`) for the first time from inside a ceiling; it must start and its thread must carry
   no ceiling.
5. **Java.base hand-offs capture the ceiling only.** Tasks submitted to executors, cleaners, timers and
   completion stages whose threads were created outside the scope (`ThreadPoolExecutor`, `ForkJoinPool`,
   `Cleaner.register`, `Timer.schedule`, `CompletableFuture.*Async`): the submission reads `CEILING` (one
   `ScopedValue` read) and the worker binds it around the task via an internal java.base-only runner. It does
   **not** capture `getContext()`: that would run tasks under the submitter's whole stack context (a semantic
   change for code that submits from restricted code and relies on the worker's authority) at 85% of a check
   per submit. Belt and braces for anything not yet on virtual threads; third-party executors are not covered
   (§0, §6).
6. **Convert all java.base `doPrivileged` calls to the policy-reducing form.** About 406 call sites in 222 files
   under `src/java.base`. java.base is the only `AllPermission` domain, so its unlimited `doPrivileged` is the one
   elevation that reaches full authority; converting it bounds java.base deputies by per-class least privilege on
   *every* thread, ceiling or not, and takes them out of the ceiling's scope by construction (§3). Mechanics:
   - An internal caller-sensitive helper, e.g. `doPrivilegedByPolicy(action)`, building
     `DomainIdentity(getResource(caller), new Permissions(), null, null)` — explicit because
     `doPrivileged(action, null)` resolves to the two-argument overload. The public three-argument form keeps its
     behaviour for third parties.
   - Granularity is **per class, not per call site**. For large deputy classes (provider loading, URL opening,
     file-system providers) check that the union of their blocks' needs is not wider than any single block
     needs; split a block into its own class if it is.
   - Lint java.base for remaining one-argument `doPrivileged`, non-empty limited lists, and `AllPermission` in
     any limited list.
   - **Not every two-argument call is an elevation.** Some `doPrivileged(action, ctx)` sites *install* a captured
     context — to run its combiner, or to evaluate under its restriction — rather than elevate the caller
     (`CombinerSecurityManager`'s combiner capture, §11.3, is the model; the JGDMS inventory's "~60
     context-restore" sites are the likely population in that codebase). Converting one mechanically pushes the
     caller's per-class limiting domain *into the context being evaluated*. Triage before converting: an
     installation site keeps the two-argument form (a bound ceiling's domains are then appended to it, which is
     the intended evaluation bound) or moves to a `ContextBuilder.combine(acc)` primitive; the lint for
     remaining two-argument calls must accept sites annotated as installations.
   - Optional audit cross-check: if call sites keep a documentation-only permission list, polpAudit compares it
     with the generated grant. "Granted but not declared" is drift; "declared but not granted" is stale or
     unexercised.
   - **Residual, recorded:** the per-class floors of java.base's I/O deputies (socket and file providers, URL
     handlers, `ProcessImpl`, the reflection factory) are the bound on what a vetted constructor can reach
     through them, and those floors legitimately contain connect, read/write and exec. The controls are the
     class split above, the §6 escape rule on the finite constructor set, and a polpAudit flag on wildcard
     connect/write/exec grants to java.base per-class codesources for review.

Not recommended, **with a known interaction** recorded so it is not proposed later as a cheap win: a **sticky**
flag on `ProtectionDomain` (a domain that survives a one-argument cut and is intersected into every check while
anywhere on the stack). Proxy code calls platform code (JERI endpoints, the codec) that uses `doPrivileged` to
act *on the proxy's behalf*; sticky downloaded domains would require the proxy's own grant to include every
permission the platform uses for it, sockets included, turning `DigestDomainGrant` into "grant the proxy
everything the platform does for it".

## 5. Where the closure comes from

| Situation | Outcome |
|---|---|
| Elevating `doPrivileged` (1-arg, 2-arg, `WithCombiner`) under a ceiling | privileged context gains all ceiling domains; `caller ∩ ctx ∩ ceilings` |
| Policy-reducing `doPrivileged` (3-arg, empty `perms`) under a ceiling | not capped; bounded by `caller ∩ ctx ∩ policy(per-class codesource)` |
| 3-arg `doPrivileged` with non-empty `perms` under a ceiling | treated as elevating and capped (§8 union defect) until converted |
| Plain check, no elevating frame | unchanged; bounded by non-java.base floors on the stack (invariant: no AllPermission or broad wildcards outside java.base, lint-enforced) |
| Nested `ceiling()` | binding accumulates; inner call bounded by all; outer binding restored on return |
| Virtual thread created inside a ceiling | inherits the binding for its life |
| Platform thread created inside a ceiling | ceiling taken from its inherited context at every elevating `doPrivileged` |
| Lazy java.base infrastructure thread | created from a context with no ceiling (reviewed allow-list) |
| Task handed to a java.base executor / cleaner / timer / async stage on outside threads | ceiling captured at submit, bound around the task on the worker |
| Task handed to a third-party executor, queue or callback | **not covered** — §6 |
| `doPrivileged(action, snapshot)` | snapshot's sealed domains appended alongside the current binding's; a snapshot with none contributes nothing |
| Policy grants a sealed domain `AllPermission`, or matches it by a codebase-only or wildcard grant | not honoured: sealed domains match only grants naming their `CeilingPrincipal`; a resolved grant set implying `AllPermission` is treated as **empty** and logged (fork `PolicyFile`, JGDMS `ConcurrentPolicyFile`) |
| `Policy.implies` throws; combiner output lacks a sealed domain; caller codesource unresolvable | deny |
| No binding and no sealed domains in the inherited context | today's model, unchanged |
| Gate finds no `SecurityManager` / no `Policy` | the gate must **throw**, not return (JGDMS item; the ceiling bounds authority when a check happens and cannot make one happen) |

Fail-closed is a property of the scope, not of the JVM: every elevation made inside a `ceiling()` call, or on a
thread descended from one, is bounded; everything else behaves as today under least privilege. A construction
site with no `ceiling()` is the defect to lint for.

## 6. The other half: what exists after construction

- **Finite constructable set.** With the `Externalizable` and non-`@AtomicSerial` `Serializable` doors in
  `AtomicMarshalInputStream` closed (JGDMS analysis A2) and the type gate in place (refuse classes assignable to
  `PrivilegedAction`, `PrivilegedExceptionAction`, `DomainCombiner`, `Policy`, `ClassLoader`,
  `SecurityManager`), the only constructors that run on wire data are `@AtomicSerial` ones — an enumerable set.
  The per-class analysis the JGDMS §2 sketch wanted for *all* code is needed only for these, and the rule is
  linear and per method: a constructor, `check(GetArg)` or `readResolve` must not let `this`, its arguments or
  anything it builds escape to a static, a queue, an executor, a listener or a thread.
- **Two-phase decode.** Nothing is invoked on a decoded object before admission (decode values → admit →
  resolve proxies and codebases). Until admission the object exists only in the decoder's hands under the
  construction ceiling; afterwards it is an ordinary object under the normal model.
- **Construction ceiling grants** are what polpAudit records against the site; anything a vetted constructor
  needs that looks like a hand-off (thread creation, executor submission) shows up there for review.

A task that reaches a thread outside the ceiling had to come from a vetted constructor that violated the escape
rule, and that rule is checked at build time on a finite list.

## 7. What this removes from the JGDMS analysis §2 sketch

- `restrict`/`Elevation.run`/`resume` and the per-site elevation registry: not needed. With a ceiling in force
  every elevating `doPrivileged`, every `Subject.doAs` and every replayed snapshot is bounded above by the
  ceiling; the analyser's question collapses from "what does this class's privilege call do" (undecidable) to
  "did the gate establish a ceiling, with a literal message" (one call site per gate).
- The per-class bytecode rules for arbitrary constructor classes: replaced by the escape rule on the finite
  `@AtomicSerial` set.
- Dropped along the way: the static-permission ceiling, the per-thread default ceiling (`ROOT`), the ceiling
  field on `AccessControlContext`, intersecting the ceiling on plain checks, a module check for java.base.

What stays: the type gate, two-phase decode, the digest fixes, and the inventory of ~190 true elevations — now
triaged by running the suite under ceilings and reading the polpAudit floor. On the digest fixes, worded to match
the JGDMS work of 2026-10-18: for static `DigestGrant` the fix is the `unverified()` check, **not** loader
scoping; loader scoping belongs only to `DigestDomainGrant`. `RemoteContextCodec.readDigest` accepting any bytes
from the peer is a separate item.

## 8. Independent fixes and checks

- **Defect (not the design):** in the three-argument form the explicit `Permission...` arguments go into the
  limiting domain's *static* collection, so the effective bound is `perms ∪ policy(class)`. For a non-java.base
  caller this is harmless, since the caller's own floor is in the intersection; for a java.base caller, whose
  domain is `AllPermission`, every listed permission is granted regardless of policy. It also puts a shared
  static `PermissionCollection` on the hot path — interned contexts share it across threads, so it is contended.
  Fix: java.base conversions pass no permissions (§4.6), so policy alone decides. The intersection-domain design
  itself is intended and stays.
- **Bug (affects JGDMS gates):** `AccessControlContext.checkAuthorized` keys off `System.getSecurityManager()`
  while every `implies` path uses `Policy.getPolicyNoCheck()` regardless; with no SM anyone can mint any context.
  Route it through `AccessController.checkPermission` so the class works with a `Policy` and no SM, which also
  gives JGDMS gates a way to fail closed without one.
- **Javadoc:** `AccessController`'s class javadoc still describes Java 8 limited semantics ("checking continues
  beyond the caller"); DirtyChai intersects instead and counts policy grants.
- **Check before relying on per-class codesources in grants.** `getResource(caller)` returns
  `jrt:/<module>/<Class>` for module classes. For non-module classes it calls
  `callerLoader.getResource(clazz.getName())` — the dotted class name with no `.class` suffix — which will
  normally return null for jar-loaded classes, falling through to `<codesource location>/<class name>`. Whatever
  it produces, `ConcurrentPolicyFile`'s codebase matching (with `-` and `*`) and polpAudit's writer must agree on
  it; a correct grant that silently does not match is the failure mode to test for.
- Two deprecated constructors plus nine `create` overloads distinguished by argument order and an
  `isAuthorized` boolean are hard to audit; two public factories plus `intersect`/`ceiling` and the sealed
  builder would cover it.
- `getContext()` runs subject injection on every call; sound (principals only, static and sealed domains
  skipped) but could be done once per `(acc, subjects)` pair, or in `optimize()` where the inherited combiner
  already runs.

## 9. Still open

- The cache-distinctness test for `(stack, ceiling)` contexts (§4.3).
- `goCombiner`'s sealed-domain presence check (§4.1).
- The AllPermission-means-empty rule for sealed domains in `PolicyFile`/`ConcurrentPolicyFile` (§5).
- Per-class codesource matching in `ConcurrentPolicyFile` versus polpAudit's writer (§8).
- `checkAuthorized` keying off `getSecurityManager()` (§8).
- Not examined: the native `getStackAccessControlContext`; the exact mechanism by which the fork inherits the
  `Subject` `ScopedValue` into virtual threads (the ceiling reuses it); the `Thread.Context` and
  `ForkJoinPool.Context` builders; what `getResource` returns for non-module classes.

## 10. Suggested order if started

1. `DomainIdentity.sealed`, `CeilingPrincipal`, combiner pass-through, `goCombiner` presence check.
2. Sealed-domain grant matching and the AllPermission-means-empty rule in `PolicyFile`; the
   per-class-codesource matching check; the AllPermission-outside-java.base lint.
3. `getContext()` split (public appends, internal check path unchanged); `hasSealed` flag;
   cache-distinctness test.
4. `AccessController`: `CEILING`, `ceiling()`, `executePrivileged` append for elevating forms, the
   `perms.length == 0` test, ceiling-naming `AccessControlException`; `doPrivilegedByPolicy`; javadoc.
5. Platform-thread path via inherited context; lazy-singleton test; infrastructure allow-list recorded.
6. Ceiling capture at java.base hand-offs.
7. java.base conversion (~406 sites); lints; deputy-class splits as polpAudit reveals them.
8. polpAudit: report ceiling identities; floor emits `CeilingPrincipal` grants; `ldc` lint at `ceiling` call
   sites; flags for `AllPermission` on `CeilingPrincipal` grants and wildcard connect/write/exec on java.base
   per-class codesources.
9. JGDMS: gates throw without SM/Policy; `ceiling("construct", …)` at each reconstruction site on virtual-thread
   dispatch; then the §6 items on their own schedule.

## 11. Impact on `CombinerSecurityManager` (`au.zeus.jdk.authorization.sm`)

Read against the current source (not executed).

1. **SM-mediated checks are ceiling-bounded via the snapshot — a decision to make, not an accident to keep.**
   `checkPermission(perm)` obtains its context from `getSecurityContext()`, the *public* `getContext()`, which
   under §4.3 appends the ceiling's sealed domains. Every check routed through the SM inside a `ceiling()` scope
   is therefore `execution context ∩ ceiling`. This reverses the letter of §3's "plain checks unchanged" for the
   path nearly all JDK checks take, but not its cost rationale: the SM already pays `getContext()`, and the
   increment is one `ScopedValue` read and an interned append. **Recommended: accept it**, since it gives
   SM-mediated plain checks a per-site bound at no extra `getContext()` cost; the consequence is that a ceiling
   grant must contain what the construction path *checks*, not only what it elevates for, which is what
   polpAudit records anyway. To keep §3's letter instead, `getSecurityContext()` uses the internal
   non-appending path. Either way the invariant to state is: *checks against a snapshot are ceiling-bounded; the
   direct `AccessController.checkPermission` path is not.*
2. **`DelegateDomainCombiner` would fail the `goCombiner` presence check (§4.1).** It replaces every assigned
   domain with a single `DelegateProtectionDomain` wrapper, so a sealed domain is never present in its output by
   identity. Fix in the combiner: partition sealed domains out of `assignedDomains` and append them unwrapped
   after the wrapper. Their `implies` is one policy lookup; nothing to parallelise. The wrapper itself is
   static-only with a null codesource and is unaffected.
3. **Two of the SM's three `doPrivileged` sites are elevations; one is not.**
   - `doPrivileged(action, delegateContext)` with `action = getContext()` does not elevate: it installs
     `delegateContext` as the assigned context so that `getContext()` runs `optimize()` → `goCombiner()` and
     returns the combined result. The caller's privilege is irrelevant (the combiner discards `currentDomains`
     and filters the SM's own domain). It must **not** be converted to the three-argument form: the fork's
     three-argument form builds `delegateContext.intersectionPermissions(limitingDomain)`, so the SM's per-class
     limiting domain would land in `assignedDomains`, be wrapped into the `DelegateProtectionDomain`, and become
     a participant in every evaluation. Preferred replacement: a `ContextBuilder.combine(acc)` primitive that
     runs the context's combiner directly and returns the result — `CombinerSecurityManager.Context` is already
     in the sealed `permits` list, so it is a builder method and a one-line change in the SM, and it removes a
     `doPrivileged` from the cache-miss path. Left as the two-argument form, a bound ceiling's domains are
     appended to `delegateContext`, pass through the (partitioned) combiner, and bound the evaluation — so the
     item-1 decision is then made by this site regardless of what `getSecurityContext()` does; with
     `combine(acc)` the decision rests on the snapshot alone.
   - The one-argument `doPrivileged` in `PermissionCheck` and `PermissionOnceCheck` *are* elevations: they exist
     so the policy's internal work is not evaluated against the virtual thread's inherited context, which is
     the very context being checked. They run on `newVirtualThreadPerTaskExecutor` threads created inside the
     check — inside the ceiling scope — and so inherit `CEILING`; capped, they would need the policy provider's
     own needs in every ceiling grant. Convert both to the policy-reducing form
     (`doPrivileged(action, null, /* no perms */)`; §3 exempts it by *form*, not by module), bounded by
     `policy(jrt:/…/CombinerSecurityManager$PermissionCheck)` as polpAudit records it. `ConcurrentPolicyFile`'s
     own privileged operations get the same conversion.
4. **Caches and fast paths.** `checked` and `contextCache` are keyed by context equality, so a ceilinged snapshot
   gets its own entries — correct; test that a permission cached for `ctx` is not reused for `ctx + ceiling`. The
   `SMPrivilegedContext`/`SMConstructorContext` equality fast path misses under a ceiling (extra domains), so the
   endless-loop guard falls to the `TRUSTED_RECURSIVE_CALL` cap; test the SM evaluating a sealed domain whose
   policy lookup itself triggers a check. `Context.build(acc, combiner)` copies `acc.context`, so sealed domains
   survive the `ContextBuilder` with no change — a point in favour of the no-field design (r3), since a ceiling
   field would have had to be threaded through the builder.
5. polpAudit's `SecurityPolicyWriter` is itself a `SecurityManager` and sees the same snapshot, so items 1–4
   apply to it; it is also where ceiling identities are reported and `CeilingPrincipal` grants are written.

## 12. Conclusion (2026-10-22): the conversion is the load-bearing change

After the design settled, the maintainer's assessment — shared by Claude — is that **§4.6, converting every
platform `doPrivileged` to the policy-reducing form, does the heavy lifting, and may be sufficient without the
ceiling.** The reasoning:

- Once every java.base elevation goes through the policy-reducing form, no `doPrivileged` anywhere reaches full
  authority. A constructor on wire data can obtain at most the per-class floor of whatever java.base class it
  reaches; plain checks were already bounded by the non-java.base floors on the stack (§3 invariant).
  "Deserializing into a privileged context" stops being possible because there is no privileged context left:
  only per-class least-privilege contexts.
- The ceiling, in its r3 shape, applies only to the *elevating* forms (§3). In the converted end-state it caps
  nothing in java.base. It is a safety net for unconverted code, and the §4.6 lint can make unconverted code not
  exist in the platform.

Two conditions for "sufficient" to hold:

1. **Scope is platform code, not java.base alone.** JGDMS's own modules (`net.jini.*`, `org.apache.river.*`)
   carry the ~190 true elevations from the JGDMS inventory and floors that include sockets, files and codebase
   download; a gadget reaching those gets that module's floor. Same conversion, same lint, same triage of
   context-installation sites (§4.6). Downloaded and third-party code may keep the old forms: their domains are
   granted little, so their elevations reach little.
2. **The residual is the per-class floor of deputies**, the same residual r3 accepted once the policy-reducing
   form was exempt from the ceiling. Its controls — split deputy classes whose floor is the union of their
   blocks' needs; the polpAudit flag on wildcard connect/write/exec to platform per-class codesources; the
   static-collection fix (§8); the `getResource`/policy-matching check (§8) — are now the *whole* defence rather
   than a backstop, and must be done well rather than eventually.

What falls away if the ceiling is not built: `CEILING` and `ceiling()`, sealed domains and `CeilingPrincipal`,
the `getContext()` split and `hasSealed`, the thread-inheritance questions (§4.4), hand-off capture (§4.5), and
the `CombinerSecurityManager` changes other than its own two `PermissionCheck` conversions (§11.3). What remains
is mechanical and auditable: the call-site conversions, a lint, polpAudit floors per class.

The ceiling design (§3–§5) is retained in this note as the documented option for the case where unconverted or
third-party elevations turn out to matter, or where a per-site bound is wanted on top of per-class floors. It
should not be built until there is evidence it is needed.

**Revised order (supersedes §10):**

1. §8 fixes: the static-collection union (`doPrivilegedByPolicy` with empty permissions); `checkAuthorized` via
   `AccessController.checkPermission`; `AccessController` javadoc.
2. The per-class codesource matching check: what `getResource(caller)` produces for module and non-module
   classes, and that `ConcurrentPolicyFile`'s matching and polpAudit's writer agree on it. A correct grant that
   silently does not match is the failure mode that would make everything else look like it works.
3. Convert java.base (~406 sites, 222 files), triaging installation sites; lint for remaining elevating forms,
   non-empty limited lists, `AllPermission` in any limited list; the infrastructure allow-list recorded.
4. Convert JGDMS platform modules the same way; the AllPermission-outside-java.base lint on shipped policies.
5. polpAudit: per-class floors; deputy-class flags; the documentation-list cross-check.
6. One deliberate deputy test: a vetted constructor reaching a URL handler (or file provider), confirming that
   the per-class floor is what bounds it, under polpAudit and then under the condensed policy.
7. JGDMS gates throw without SM/Policy; then the §6 items (type gate, two-phase decode, `@AtomicSerial` escape
   rule) on their own schedule.
8. The ceiling (§3–§5, §10 steps 1–6), only if step 6 or later evidence shows a need.

## 13. Revision 4 (2026-10-23): apply the policy-reducing intersection to every `doPrivileged`

The maintainer's step after §12: **the three-argument form's per-class intersection can be applied to all
`doPrivileged` forms, in one place.** `executePrivileged` always intersects the caller's per-class policy domain —
`DomainIdentity(perClassCodeSource(caller), new Permissions(), null, null)` — with whatever context the form supplies.
Authority under any form is then `caller ∩ ctx ∩ policy(callerClass)`, which is never more than `caller` alone was.

**Why it is safe against impostors.** The limiting domain is derived from `Reflection.getCallerClass()`, not from any
argument, and it only intersects. A loader that lies about a class's codesource already holds whatever its lying
`ProtectionDomain` is granted; the per-class domain cannot add to that.

**What it supersedes.**
- The ceiling (§3–§5): it capped *elevating* forms; with every form reduced by policy there is no elevating form, and
  nothing to cap. The sections stay as history. The `ScopedValue`, sealed domains, `CeilingPrincipal`, the
  `getContext()` split, the thread-inheritance questions, hand-off capture, and §11.1–11.2 all fall away.
- The call-site conversion sweep (§4.6, §12 steps 3–4): ~406 java.base edits and the JGDMS platform edits become one
  change in `executePrivileged`. Third-party code receives the same bound without being edited. The §4.6 lints for
  one-argument calls and non-empty limited lists are no longer needed.

**What it needs.**
1. **An internal raw primitive.** `getResource(caller)` itself calls `doPrivileged`, so universal reduction would
   recurse; VM initialisation runs before `Policy` exists. `AccessController` needs a non-reducing internal path that
   nothing outside java.base can reach — the "kernel is the only caller of the raw primitive" line from the JGDMS
   analysis §2 sketch, for a different reason.
2. **A per-class cache.** `getResource` builds URIs and a `DomainIdentity` per call. On the hottest security path it
   must be a `ClassValue<DomainIdentity>` lookup; the resulting context is interned already (`ContextCache`).
3. **The per-class domain carries the calling `Class` (decided 2026-10-24).** It is
   `DomainIdentity(pd.getCodeSource(), ∅, pd.getClassLoader(), null, callerClass)` with `pd = callerClass.getProtectionDomain()`
   and a new **strong** `Class<?> callerClass` field included in `equals`/`hashCode`. Nothing is synthesised: the
   codesource is the PD's own — a *verified* `DigestCodeSource` for code a `SecureClassLoader` defined from a downloaded
   jar, the jar URI for local code, `jrt:/<module>` for modules — and the loader is the PD's, so `ClassLoaderGrant` and
   `DigestDomainGrant` match. `getResource(caller)` is deleted; its non-module branch called
   `callerLoader.getResource(clazz.getName())`, which on a `PreferredClassLoader` can reach the network — a codebase fetch
   inside every `doPrivileged`. Consequences:
   - **Existing grants match unchanged.** `DigestDomainGrant.implies` compares the jar digest and covers every class the
     loader defined from that jar, and no class added to the loader later from another jar (that was the point of
     granting to the digest). A `DigestCodeSource` is verified only by local construction — `RemoteContextCodec.readDigest`
     codesources arrive unverified and stay so — so no peer can mint a per-class domain that matches a digest grant.
   - **Per-class refinement is one `class` qualifier on `PermissionGrant`**, valid with any codesource kind:
     `grant codebase "digest:sha256:D", class "pkg.Cls" { … }`, `grant codebase "jrt:/java.base", class "…" { … }`. The
     digest or URI identifies the jar; the name selects a member within it (consistent with "a name is not an identity").
     polpAudit's writer emits the qualifier from the domain's class; the condenser drops it where a jar's classes share a
     floor. This is the only policy-grammar change.
   - **Dynamic code.** A proxy's elevation ceiling is whatever its prepare step granted its loader — the advisory
     `PERMISSIONS.LIST` condensed by `ProxyPolicyGenerator` into the `GrantPermission` ceiling — intersected with its own
     domain. Four `-dl` sites call `doPrivileged` today (`Bootstrap.getProxyLoader`, phoenix `AID.classLoader`,
     `SpaceProxy2` :310, reggie `Item` :105; two via `Security.doPrivileged`), all mechanical. They convert to plain
     `AccessController.doPrivileged`; the proxy lint forbids calling through a platform wrapper, because the wrapper's
     per-class floor, not the proxy's, becomes the bound.
   - **`Security.doPrivileged` and `Security.doAs*` are removed (decided 2026-10-24 10:27).** `Security.doPrivileged`
     (`Security.java:712`, `:746`) is an outer one-argument `doPrivileged` — making `Security` the caller — around
     `doPrivileged(action, createPrivilegedContext(caller, acc))`. Under §13 any wrapper that calls `doPrivileged` on a
     caller's behalf is a confused deputy by construction: its per-class floor must be the union of every caller's
     needs, which is the shape a gadget wants to reach. Its original purpose (elevate only to the caller's own domain)
     is now what every `doPrivileged` does. ~~Its one extra property — folding the inherited `acc` in so the stack is
     never cut — needs no wrapper: `AccessController.doPrivileged(action, AccessController.getContext())` at the site.~~
     **Struck 2026-10-24 12:30 (agent finding, confirmed against `Security.java` and analysis B5):** the wrapper's
     `createPrivilegedContext(caller, acc)` carries only the caller's own domain and uses `acc` for its combiner; it
     does not keep the inherited stack. The exact equivalent is therefore the **one-argument** form.
     Call sites in `main` (VERIFIED 2026-10-24, scoped grep): 32 files — jgdms-platform 8, jgdms-jeri 18,
     pref-class-loader 1, url-integrity 1, activation 1, phoenix 1, services 2 (61 call sites in 29 files by the
     converting agent's count); ~~none in `qa`~~ — **wrong:** `qa` holds tests of the wrapper itself (`FakeCaller`,
     `DoPrivilegedTest`, `DoPrivilegedExceptionTest`, jtreg `Security/doPrivileged/`), which are deleted with it.
     ~~**Conversion rule:** semantics-preserving first — `doPrivileged(action, AccessController.getContext())` … and the
     one-argument form only later~~ **Struck 2026-10-24 12:30:** that rule was backwards. The two-argument snapshot
     *adds* every inherited domain and is narrower than the wrapper (it can throw where the old code did not, e.g.
     static initialisers reading properties). **Conversion rule: the one-argument `AccessController.doPrivileged(action)`,
     which is the exact equivalent** (caller's own domain; the fork applies subject principals in `getContext()`
     regardless of form) and becomes `caller ∩ policy(callerClass)` under §13. `doAs`/`doAsPrivileged` were already
     removed on the branch (2026-10-23); zero callers. Branch: `claude/remove-security-doprivileged`.
   - **Strong reference, not weak.** A weak `Class` reference would make a stored context's authority depend on when the
     collector ran: `doPrivileged(action, stored)` passing one day and denying the next with no change to policy, code
     or input, unreproducibly — and every captured context (executors, `Subject.doAs` snapshots, the SM's caches) would
     carry the same nondeterminism. A `ProtectionDomain` already holds its `ClassLoader` strongly, so every context
     today pins its domains' loaders for as long as it is reachable; the class field pins the same loader for the same
     lifetime. A context must mean the same thing for as long as it exists. Not a trade-off; the weak variant is a
     correctness defect.
4. **Installation sites.** A `doPrivileged(action, ctx)` whose purpose is to *evaluate* `ctx` (run its combiner, check
   under its restriction) would now have the installer's class floor appended to the evaluated context. For
   `CombinerSecurityManager` that floor is broad, so it is a no-op, but the principled fix is the
   `ContextBuilder.combine(acc)` primitive (§11.3): evaluation without a `doPrivileged`, no limit at all. The
   "installation site" lint shrinks to: SecurityManagers and policy tooling evaluate with `combine`.
5. **The static-collection union** (§8): the universal path passes no permissions, so policy alone decides. The public
   three-argument form either keeps the union for third parties, documented, or loses it; either way it is no longer on
   java.base's path.
6. **A transition path.** This is a fail-closed cliff for every library on DirtyChai: each class that calls
   `doPrivileged` needs a grant. Per-class codesources are `<location>/<Class>`, so the existing `-` codebase wildcard
   gives a per-module or per-jar grant for free: `grant codebase "jrt:/java.base/-" { … }` expresses today's behaviour
   as policy, and polpAudit refines it per class over time. The rollout is a policy change, not a flag day. The
   AllPermission-outside-java.base lint (§3) applies to these coarse grants too.

**Residual, unchanged from §12.** The per-class floors of deputies (socket and file providers, URL handlers,
`ProcessImpl`, the reflection factory) are now the *only* bound on what a vetted constructor reaches through them. The
controls are the same and matter more: split deputy classes whose floor is the union of their blocks' needs; the
polpAudit flag on wildcard connect/write/exec to platform per-class codesources; the §6 escape rule on the finite
`@AtomicSerial` set; two-phase decode.

**Revised order (supersedes §12's):**

1. The internal raw primitive; `ClassValue` per-class domain cache; per-class codesource derived from the
   `ProtectionDomain` codesource.
2. The per-class codesource matching check (§8), now load-bearing: a correct grant that silently does not match makes
   everything deny.
3. `executePrivileged`: intersect the per-class domain on every form; `checkAuthorized` via
   `AccessController.checkPermission`; `AccessController` javadoc rewritten for the new semantics (not Java 8's).
4. `ContextBuilder.combine(acc)`; `CombinerSecurityManager` and polpAudit's `SecurityPolicyWriter` evaluate with it;
   `PermissionCheck`/`PermissionOnceCheck` need no change (their one-argument calls are now bounded like everything
   else, by `policy(CombinerSecurityManager$PermissionCheck)`, which the coarse grant covers).
5. Shipped coarse grants (`jrt:/<module>/-` per module; per-jar for JGDMS platform jars) so existing deployments run;
   the AllPermission-outside-java.base lint.
6. polpAudit: per-class floors; deputy-class flags; condensation from coarse to per-class.
7. One deliberate deputy test (constructor → URL handler) under the coarse grant, then under the condensed policy.
8. JGDMS gates throw without SM/Policy; then the §6 items on their own schedule.

**The per-class domain takes principals (decided 2026-10-23 16:01).** It is a four-argument, non-static
`DomainIdentity`, so `SubjectDomainCombiner` adds the authenticated `Subject`'s principals to it as to any other domain.
polpAudit therefore records each privileged action's grant *with the principals present when it was observed*, and
after condensation the per-class floor is split by identity: a deputy's floor under the admin's subject may include
what it did for the admin; the same deputy under an unauthenticated peer, or no subject, has only what was observed in
that state — the narrowest floor by construction. This shrinks the deputy residual from "everything the class ever
did" to "everything the class did for this kind of caller", and it is why the `(class × subject)` context variants are
the policy's resolution, not cache overhead. Three conditions: (1) the condenser must never widen a principal-qualified
grant into an unqualified one — same lint family as codebase-only `AllPermission` (JGDMS analysis M3); (2) audit runs
must have identity bound the way production does, or the floor records unqualified grants for whatever the harness
exercised without a subject; (3) principals come only from the authenticated `Subject` (TLS, Kerberos, SPIFFE), never
from peer-claimed domains (`RemoteContextCodec`).

**Still open:** whether the `limit` should be kept out of the context's domain array (a separate field intersected at
`implies` time, never handed to combiners) rather than appended — the appended form is what the three-argument
implementation does today and what makes installation sites see it; a separate field would make `combine` unnecessary
but is a new field on an interned, VM-visible class. Decide when the first installation site other than the SM is found.

## 14. Prior art (2026-10-23)

A three-researcher survey (~60 primary sources) is at JGDMS `docs/PRIOR-ART-privilege-design-2026-10-23.md`. Its
per-mechanism verdicts, each stated as a negative with the searches that established it:

- **§13 (every `doPrivileged` policy-bounded by caller class): no precedent found.** JEP 140 let privileged code name
  its own bound; Elasticsearch entitlements removed the stack intersection and trivially allow every JDK module except
  `java.desktop`/`java.xml`; JEP 486 removed enforcement. The closest precedent for observe-runs → infer policy →
  intersect all frames is **ZTD_JAVA (2023, arXiv 2310.14117)**: DaCapo median overhead −0.03% vs 21.06% for the
  SecurityManager, keyed on dependency namespaces, never touches `doPrivileged`. Read it for how it handled deputies.
  Koved/Pistoia (OOPSLA 2002; Pistoia 2005 "tainted privileged code") is the static complement to the §13 deputy test.
- **Receiver provenance (handover §4.4): no precedent for the mechanism.** Two citations to distinguish from:
  **Trishul** (VU Amsterdam IR-CS-45, modified Kaffe) — a method's initial context taint includes the taint of `this`,
  policies match `thisTaint`, enforced at runtime, +167% CPU-bound with full propagation and shadow memory; and
  **IBAC** (Pistoia/Banerjee/Naumann, IEEE S&P 2007) — permission sets as per-value labels checked at the same points
  as stack inspection *and through privileged blocks*, static prototype only. **Design consequence:** .NET removed
  `Deny` because `Assert` masked it; a receiver provenance domain below a `doPrivileged` frame is masked by the cut
  the same way — on exactly the gadget path. Provenance collection must continue past privileged frames (IBAC's
  choice): provenance domains are the one case where the §4 "sticky" behaviour is required, and the proxy objection
  does not apply to them. Laminar labels by *allocation* context — a trap: a deserialized object would carry the
  decoder's label, not the peer's. `LiveStackFrame` is package-private and gated by a permission JEP 486 disabled.
- **Schema-digest gating (Atomic DER): no production system found that gates decoding on a schema digest.** Avro's
  fingerprints "are not meant to provide any security guarantees"; Cap'n Proto IDs are name-derived. Almost no
  hash-keyed authorization system canonicalises its input (identity = shipped bytes); the exceptions are Nix, Authenticode
  and Avro's Parsing Canonical Form. Every hashed canonical form has produced a "verifier hashes form A, consumer acts
  on form B" bug (CMS BER/DER, BIP 66, XML C14N, CBOR 7049→8949, JCS `-0`); the fix is always to reject non-distinguished
  input before hashing and act on the hashed bytes — which DER-by-definition gives for free, provided the decoder rejects
  non-DER. "Compress the public schema, never the data" has no name in the literature but exact precedents: the BREACH
  authors' "completely different compression context" and HPACK's static table + never-indexed literals (RFC 7541 §7.1.3).

**Receiver provenance is now designed** in JGDMS `docs/DESIGN-serial-data-identity-2026-10-23.md`: a sealed
`DomainIdentity` over the schema leaf digest (`DigestCodeSource`, verified path) with the delivering connection's
principals, passed explicitly from the gate (the dispatcher decodes before the Subject wrap — N1), stamped on every
decoded `@AtomicSerial` object, collected from frame receivers by the native walk continuing past the privileged frame,
fail-closed when a compiled frame has dropped `this`. It composes with §13 by intersection.

