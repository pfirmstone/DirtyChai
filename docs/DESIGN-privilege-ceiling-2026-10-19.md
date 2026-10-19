# Design: a privilege ceiling that `doPrivileged` cannot shed

**Status: design note (2026-10-19). Not implemented, not scheduled.** Records the outcome of a design
discussion between the maintainer and Claude (`claude-fable-5-1`) against DirtyChai `trunk` at `af6bc547954`.
Companion to JGDMS `docs/ANALYSIS-legacy-API-authority-and-reconstruction-2026-10-19.md`, whose §2 sketch and
"weaknesses" list this note answers. Nothing here has been executed; every claim about current behaviour is from
reading `java.security.AccessController`, `AccessControlContext`, `DomainIdentity`, `ProtectionDomain`,
`DomainCombiner`, `javax.security.auth.SubjectDomainCombiner` and `Policy`.

## 0. The question, and the limit of the answer

The question that started this: **how do we prevent deserializing into a privileged context?** Anything that
bounds authority during reconstruction must survive a `doPrivileged` call made by trusted code that a
constructor reaches, because that call is exactly how a gadget converts data into authority.

The answer has two halves, and the note is careful to keep them apart:

- A **ceiling** bounds *control flow*. It is bound in a `ScopedValue`, so it is orthogonal to the stack: the
  native stack walk that builds an `AccessControlContext` cannot see it and no `doPrivileged` cut reaches it.
  It bounds everything that *runs* during reconstruction.
- A ceiling cannot follow *data*. An object built under a narrow ceiling and later run by a wide thread
  (a queue, a callback, a third-party executor) arrives with nothing attached, and a trusted-class instance built
  from attacker data is indistinguishable on the stack from one trusted code built itself. That is the taint
  problem, and it is solved the way it always was: authenticate the caller, validate the data, and do not
  construct what has not been vetted (the finite `@AtomicSerial` set, the type gate, two-phase decode —
  §6). The ceiling bounds what runs; the vetted set bounds what exists afterwards.

Readers who expect the ceiling to solve the second half will rediscover the limit the hard way; it is stated
here first for that reason.

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
- Limited privilege (`doPrivileged(action, ctx, Permission...)`) is an intersection with a permission-bearing
  `DomainIdentity`, not special frame walking.
- `Subject` is carried as a `ScopedValue`; `getContext()` injects current subjects by adding principals to
  non-static domains only, never permissions, never removing domains.
- `Policy.impliesEphemeral` defines ephemeral authority that polpAudit must never record into the generated floor.

## 2. Why today's shapes fail

- **Static permission lists are deployment-hostile.** A ceiling expressed as `Permission...` in code is a static
  permission by another name: it cannot be corrected by policy at deployment, and when it is wrong the program
  fails or is painful to debug. polpAudit exists so that permissions are observed, documented and modified in
  policy; a ceiling must be something policy grants to.
- **A domain in a context is only as durable as the context.** The native walk builds a fresh context from
  frames; the next 1-arg `doPrivileged` cuts the walk at its caller with `privilegedContext == null`, and any
  marker domain the enclosing `doPrivileged(action, neverPrivileged())` established is gone. A constructor that
  does a property read sheds the marker. This is the JGDMS analysis's first weakness, and it also kills the
  obvious repair of folding a ceiling domain into `getContext()`: that domain is stripped the same way.
- **The 3-arg limited form can be elevated again.** An inner `doPrivileged` inside the limited action is
  unbounded relative to the limit. The limiting domain is also built with the 4-arg `DomainIdentity`
  constructor, so `Policy` is consulted for the per-class codesource and the bound is
  `max(perms, policy(callerCS))`, not `perms` (see §8).
- **"No ceiling" as the normal state is fail-open.** Threads created at startup, tasks escaping to pre-existing
  pools, VM-created threads, and any path where the binding is absent all run with full stack authority.

## 3. The API

```java
public final class AccessController {
    /**
     * Runs {@code action} under a ceiling identified by the caller's codesource and {@code message}.
     * The caller is captured as for the 3-argument doPrivileged. The ceiling is bound in a ScopedValue
     * for the duration of the action and intersected with any ceiling already in force; it can be narrowed
     * by a nested call and cannot be widened, shed or elevated past by any form of doPrivileged.
     * {@code message} is an identifier, written as a literal at the call site, never derived from input.
     */
    @CallerSensitive
    public static <T> T ceiling(String message, Callable<T> action) throws Exception;
}
```

- **Identity.** The ceiling is a *sealed* `DomainIdentity` (§4) whose codesource is the caller's per-class
  codesource with the caller's signer certificates (`getResource(caller)` already produces this) and whose
  principals are `{ new CeilingPrincipal(message) }`. The message is a principal rather than a URL component
  because the policy grammar already matches codebase + principals, polpAudit already records principals in the
  floor, and a sealed domain may *have* principals set at construction while refusing combiner-added ones.
- **Policy.** The grant is ordinary policy text, per site and per phase:

  ```
  grant codebase "jrt:/net.jini.io/net.jini.io.AtomicMarshalInputStream",
        principal java.security.CeilingPrincipal "construct" {
      permission java.util.PropertyPermission "*", "read";
  };
  ```

  One class may run different phases under different ceilings (`"decode"`, `"construct"`, `"resolve"`) with
  separate grants. A denied check inside a ceiling is reported by polpAudit against that codesource and
  principal, so the fix is a policy line, not a code change. Ephemeral grants to a ceiling (a leased or
  single-use grant, e.g. "this one decode may fetch codebase X") never enter the floor, by the existing rule.
- **`Callable`, not `PrivilegedAction`.** A distinct type tells the reader and the analyser which kind of call
  it is at the call site, and the checked exception keeps `ceiling` from being used as a lambda-elevation
  helper. It returns the action's result.
- **Semantics.** Inside the action every check is `stack ∩ effective ceiling`; every form of `doPrivileged`
  is `… ∩ effective ceiling`; the 3-arg form's "elevate again" door is closed because the binding is not on the
  stack to be cut. Nested ceilings bind `outer ∩ inner`, never replace.
- **Errors.** An `AccessControlException` raised under a ceiling names the ceiling (codesource and message) so
  the audit trail says which ceiling denied.

## 4. Fork touch points

1. **`DomainIdentity.sealed`.** A third mode alongside policy-granted and static-only: *policy-granted but
   sealed*. `Policy` is consulted on every check; no combiner may replace it or add principals;
   `equals`/`hashCode` include the flag. `SubjectDomainCombiner.combine` passes sealed domains through exactly
   as it does `staticPermissionsOnly()` ones, and `AccessControlContext.goCombiner` verifies after *any*
   combiner runs that every sealed domain of the input is still present, throwing otherwise. This makes a
   ceiling robust against arbitrary `DomainCombiner` implementations (JGDMS's `DistributedSubjectCombiner`
   drops domains today). The `DomainCombiner` contract is documented accordingly: may add principals, never
   permissions, never remove sealed or static domains.
2. **`Thread.ceiling`.** A final field set once at construction to the creating thread's *effective* ceiling
   (§5). The primordial thread gets `ROOT`, a sealed domain `ceiling:/root` that policy must grant to like any
   other. Only java.base can set it (`Thread.Context`); nothing can set it afterwards. Virtual threads take it
   from their creator; carriers are irrelevant because the field and the binding live on the virtual thread.
   Pools capture the ceiling when the *pool* is built, not when a worker is lazily created
   (`ForkJoinPool.Context` is the existing hook), so the common pool's workers are not bounded by whichever
   request first touched it.
3. **`AccessControlContext.ceiling` field** (alongside `privilegedContext`, `combiner`). `getContext()` sets it
   from the current effective ceiling; every derived context (`create(acc, combiner)`,
   `intersectionPermissions`, `optimize`, `goCombiner`, the cache key) copies it; no public path produces a
   context with a weaker ceiling than its source. The field is **not** the source of truth on the thread that
   holds the binding (the native walk would strip it); it exists so that (a) `doPrivileged(action, snapshot)`
   can *re-establish* the binding on another thread, and (b) `snapshot.checkPermission(perm)` on a stored
   context is bounded even when it is never run.
4. **`AccessController`.** `ceiling(message, action)` binds `ScopedValue<AccessControlContext> CEILING` to
   `current ∩ new`. `executePrivileged`, for every form, rebinds to `current ∩ ctx.ceiling` when the context
   argument carries one (a null field contributes nothing — rebinding never widens). `checkPermission` reads the
   effective ceiling from the binding, not from any context. java.base executors (`ThreadPoolExecutor`,
   `ForkJoinPool`) wrap each submitted task with `getContext()` and run it via `doPrivileged(task, captured)`,
   unconditionally — what `Executors.privilegedThreadFactory` did by opt-in — so every java.base hand-off
   carries the submitter's ceiling onto the worker.

Optional, same machinery: a **sticky** flag on `ProtectionDomain`, meaning a 1-arg `doPrivileged` cut removes
ordinary frames but a sticky domain anywhere on the thread's stack is intersected into every check regardless.
Applied to downloaded-codebase domains, untrusted *classes* can never get trusted code to elevate past their own
grants on any thread. It does not address attacker-built instances of trusted classes (§0).

## 5. Layering and the fail-closed rules

Three layers, each able only to narrow the one above:

1. **Thread ceiling** — set at creation, immutable, inherited from the creator's effective ceiling.
2. **Binding** — `CEILING`, established only by `ceiling()` or by an `executePrivileged` rebind; always
   `current ∩ new`.
3. **Stack** — the ordinary walk.

Effective ceiling = `CEILING.isBound() ? CEILING.get() : thread.ceiling`. A check is
`stack ∩ effective ceiling`. Invariant, by construction: `effective ⊆ thread.ceiling ⊆ creator's effective at
creation`. There is no unbound state.

Fail-closed rules, each pointing the same way:

| Situation | Outcome |
|---|---|
| No binding on the thread | `thread.ceiling` applies; the primordial thread's is `ROOT` |
| Context with a null ceiling field used in `doPrivileged(action, ctx)` | contributes nothing; current binding stays |
| Snapshot checked directly | `snapshot ∩ current effective ceiling` |
| Policy grants a sealed domain `AllPermission`, or matches it by a codebase-only or wildcard grant | not honoured: sealed domains match only grants naming their `CeilingPrincipal`; a resolved grant set implying `AllPermission` is treated as **empty** and logged (fork `PolicyFile`, JGDMS `ConcurrentPolicyFile`) |
| `Policy.implies` throws; combiner output lacks a sealed domain; caller codesource unresolvable | deny |
| Gate finds no `SecurityManager` / no `Policy` | the gate must **throw**, not return (JGDMS item; the ceiling bounds authority when a check happens and cannot make one happen) |
| Thread or executor created inside a ceiling | inherits it for its whole life; a pool built under a ceiling is permanently bounded — correct, and will surprise someone once |
| Task handed to a pre-existing pool through a java.base executor | submitter's ceiling arrives via the captured context and the rebind |
| Task handed to a third-party executor, queue or callback with no context capture | **not covered by the ceiling** — runs under the worker's thread ceiling and its own class domain; see §6 |

A fresh deployment with an empty policy runs nothing until polpAudit has produced a floor. That is the intended
workflow, and the note says so here so it is not reported as a defect.

## 6. The other half: what exists after construction

The ceiling bounds what *runs* during reconstruction. What *exists* afterwards is bounded by:

- **Finite constructable set.** With the `Externalizable` and non-`@AtomicSerial` `Serializable` doors in
  `AtomicMarshalInputStream` closed (JGDMS analysis A2) and the type gate in place (refuse classes assignable to
  `PrivilegedAction`, `PrivilegedExceptionAction`, `DomainCombiner`, `Policy`, `ClassLoader`,
  `SecurityManager`), the only constructors that run on wire data are `@AtomicSerial` ones — an enumerable set.
  The per-class analysis the JGDMS §2 sketch wanted for *all* code is needed only for these, and the rule is
  linear and per method: a constructor, `check(GetArg)` or `readResolve` must not let `this`, its arguments or
  anything it builds escape to a static, a queue, an executor, a listener or a thread.
- **Two-phase decode.** Nothing is invoked on a decoded object before admission (decode values → admit →
  resolve proxies and codebases). Until admission the object exists only in the decoder's hands under the
  construction ceiling; afterwards it is an ordinary object under the normal stack model.
- **Construction ceiling grants.** Thread creation and java.base executor submission are checkable in the
  fork; the construction ceiling's grant does not include them, and polpAudit surfaces any vetted constructor
  that needs one.

So the fail-closed statement is: a task that reaches a wide thread had to come from a vetted constructor that
violated the escape rule, and that rule is checked at build time on a finite list.

## 7. What this removes from the JGDMS analysis §2 sketch

- `restrict`/`Elevation.run`/`resume` and the per-site elevation registry: not needed. With a ceiling in force
  every form of `doPrivileged`, every `Subject.doAs` and every stored context is bounded above by the ceiling;
  the analyser's question collapses from "what does this class's privilege call do" (undecidable) to "did the
  gate establish a ceiling" (one call site per gate, with a literal message).
- The per-class bytecode rules (no raw privilege calls, `invokedynamic` allow-list, no reflection, …) for
  arbitrary constructor classes: replaced by the escape rule on the finite `@AtomicSerial` set.
- The static-permission ceiling variant floated during this discussion: dropped (§2).

What stays from that sketch: the type gate, two-phase decode, the digest-forgery fixes (`DigestGrant.implies`
ignores the loader; `RemoteContextCodec.readDigest` accepts any bytes), and the inventory of ~190 true
elevations — which are now triaged by running the suite under ceilings and reading the polpAudit floor rather
than by reading each site.

## 8. Independent clean-ups noticed on the way

- `doPrivileged(action, ctx, Permission...)` builds its limiting domain with the 4-arg `DomainIdentity`
  constructor, so `Policy` is consulted for the per-class codesource and may grant more than `perms`. Either
  document that policy may *add* to a limited action, or use the 2-arg static constructor with a null
  codesource so the bound is `perms`.
- `AccessControlContext.checkAuthorized` keys off `System.getSecurityManager()` while every `implies` path uses
  `Policy.getPolicyNoCheck()` regardless; with no SM anyone can mint any context. Route it through
  `AccessController.checkPermission` so the class works with a `Policy` and no SM — which also gives JGDMS gates
  a way to fail closed without an SM.
- Two deprecated constructors plus nine `create` overloads distinguished by argument order and an
  `isAuthorized` boolean are hard to audit; two public factories plus `intersect`/`ceiling` and the sealed
  builder would cover it.
- `getContext()` runs subject injection on every `checkPermission`; it is sound (principals only, static and
  sealed domains skipped) but could be done once per `(acc, subjects)` pair, or in `optimize()` where the
  inherited combiner already runs.
- Deprecate the 1-arg `doPrivileged` in the fork's own code and lint for it; under a ceiling it is safe, outside
  one it is the only form that cannot be classified.

## 9. Not verified

Nothing was executed. Not examined: the native `getStackAccessControlContext`, the `Thread.Context` and
`ForkJoinPool.Context` builders' current inheritance behaviour, the cost of a `ScopedValue` lookup on the
`checkPermission` hot path, and whether `ScopedValue` bindings in this fork are inherited by platform threads
created inside a scope (the design does not depend on it — the `Thread.ceiling` field covers that case — but
inheritance would make the common path cheaper).

## 10. Suggested order if started

1. `DomainIdentity.sealed`, combiner pass-through, `goCombiner` presence check, `CeilingPrincipal`.
2. Sealed-domain grant matching and the `AllPermission`-means-empty rule in `PolicyFile`.
3. `Thread.ceiling` and `ROOT`; pool-creation capture in `ForkJoinPool.Context`.
4. `AccessControlContext.ceiling` field with copy-through; `AccessController.ceiling`; `executePrivileged`
   rebind; `checkPermission` reads the binding; ceiling-naming `AccessControlException`.
5. java.base executor task wrapping.
6. polpAudit: report ceiling identities; floor emits `CeilingPrincipal` grants; lint for `AllPermission` on
   `ceiling:/` or `CeilingPrincipal` grants.
7. JGDMS: gates throw without SM/Policy; `ceiling("construct", …)` at each reconstruction site; then the §6
   items on their own schedule.
