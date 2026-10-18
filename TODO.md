# TODO — `javax.security.auth.Subject`: thread-propagation contract

**Scope of this document.** A punch-list of defects and required additions for the
thread-propagation documentation on `Subject`. Produced as advisory analysis under
`AI_POLICY.md` Zone U (§4, "describe required changes") — it contains **no drafted
JavaDoc prose**, only a specification of what the documentation must state. Human-authored
wording required; no AI trailer on any commit that acts on this list.

**Target file.** `src/java.base/share/classes/javax/security/auth/Subject.java`
(line references below are against the working tree as of 2026-07-26; the file has
uncommitted modifications, so re-check offsets before editing).

---

## 0. Authoritative statement of actual behaviour (project lead, 2026-07-26)

> A binding cannot survive the extent on a platform thread. Only virtual threads propagate
> and outlive the original binding.

This is the reference point for the whole list: **the implementation is correct; the
documentation is wrong.** The doc describes propagation to all spawned threads, which does
not happen. Every defect below is a documentation defect, not a code defect.

Two consequences follow, and they pull in opposite directions:

1. Platform threads do not propagate, so no binding can escape the extent that way.
2. Virtual threads do propagate **and their inherited binding can outlive the granting
   `callAs` extent** — bounded by the child task's lifetime, not by the extent that granted
   the authority. This is the security-relevant fact and it is currently obscured.

---

## 1. Structural finding — fix once, not twice

The **"Thread propagation" block is duplicated verbatim** in two places:

- `callAs(...)` — approx. lines 505-524
- the `doAs` variant documented as "intended for user identity" — approx. lines 672-690

Both copies carry every defect listed in §2. Any correction must be applied to both, or
the text extracted to one canonical location and cross-referenced. Leaving two copies is
itself a defect: they will drift.

---

## 2. Defects in the current text

- **[BLOCKER] It documents propagation that does not occur.** "Any threads spawned during
  the execution of `action` will inherit the current subject" (~505-507, dup ~672-674) is
  **false**: only virtual threads propagate. A reader relying on this will assume a
  platform thread carries the user identity when it does not — and will therefore assume
  authority is present where it is absent.

- **[BLOCKER] It conceals that inherited authority outlives the granting extent.** "The
  inherited subject is active for exactly the lifetime of the spawned task and cannot leak
  beyond it" (~511-512, dup ~679-680) is technically true of the *child task*, but "it" is
  read by every reasonable reader as the `callAs` extent. A propagated virtual thread can
  still be running, holding the user's identity, after `callAs` has returned. The document
  must state which boundary bounds the authority, and say plainly that it is not the
  granting extent.

- **The OpenJDK-divergence paragraph is wrong as written** (~514-520). It claims
  "propagation occurs for all spawned threads regardless of whether structured concurrency
  is used." Propagation is virtual-thread-only. The genuine divergence from OpenJDK — if
  any remains — needs restating in terms of *which virtual threads* propagate (see §4 Q1),
  not all threads.

- **The rule is not derivable from the text.** "All spawned threads inherit" (~505) and
  "Executor tasks do not inherit" (~521) are presented as two unrelated facts with no
  unifying principle. Even once corrected to virtual-only, a reader cannot predict cases
  not listed: a pool created inside the extent, a `ForkJoinPool.commonPool()` task, a
  `CompletableFuture` continuation.

- **The Executor carve-out is given without rationale**, so it reads as arbitrary and
  inconsistent with the claim immediately above it.

- **Implicit propagation is presented purely as convenience** ("without requiring explicit
  propagation by the caller", ~508-509) with no counterweight. That is the
  `InheritableThreadLocal` rationale; nothing explains why `ScopedValue`'s bounded model
  exists or what it protects against.

- **Class-level documentation (~59-62) scopes user identity to `callAs(Subject, Callable)`
  only** — it never mentions the multi-Subject `callAs(Callable, UserSubject...)`, which is
  the form that carries more than one identity and the one JGDMS dispatches through.

- **"compatible with virtual threads" (~70) asserts nothing checkable** — and is now known
  to be the load-bearing distinction in the whole model, so it must say what the
  compatibility consists of.

- **Prose defects in the `doAs`-variant block (~665-668):** an incomplete sentence ("The
  ScopedValue Subject for the duration of action, remains available..."), the possessive
  error "Principal's", and a run-on that makes the ACC-snapshot-vs-`ScopedValue`
  distinction hard to parse.

- **Contract and advice are not separated.** "will inherit" (a guarantee) and "should
  explicitly call `callAs`" (advice) sit at the same level, with no `@apiNote` /
  `@implNote` split, so a reader cannot tell what is promised from what merely happens to
  be true today.

---

## 3. Required additions

- **The governing principle, stated once:** identity attaches to the *task*, not the
  *thread*. A virtual thread is one-per-task, so propagation and task scope coincide; a
  platform thread is a pooled, long-lived resource shared across unrelated tasks, so
  identity must attach to the submission instead. Every case below then follows from the
  principle rather than being enumerated.

- **The normative virtual-vs-platform rule**, stated as the contract it now is, and what a
  child observes (`current()` / `currentAll()`).

- **The lifetime boundary, explicitly.** State that a propagated binding is bounded by the
  *child task's* lifetime and may outlive the granting `callAs` extent — and, if that is
  intended, why it is safe (or what the caller must do about it).

- **What happens on a platform thread**, stated positively rather than by omission: no
  propagation, therefore no identity, therefore authorization fails closed.

- **Why Executor-submitted tasks are excluded**, tied to the same principle: pooling and
  reuse mean identity must attach to the submission, not the thread.

- **A cross-reference to the supported crossing mechanism** for pooled threads: capture at
  submit, re-establish around the task on the worker, unbind at completion
  (`SubjectAwareExecutor`).

- **Multi-Subject semantics:** whether all elements propagate, and whether a child sees the
  full set or only the first.

- **`WorkerSubject` vs `UserSubject` propagation** — which scope each belongs to, and that a
  platform thread's natural ambient identity is the workload identity. This is what makes
  the rule principled rather than a special case.

- **Permission semantics:** whether inheritance is itself a checked operation; what
  `AuthPermission("callAs")` is required where; and the fact that an inherited identity
  confers authority without a check at the inheritance point.

- **Interaction with the `STACK_CONTEXT` guard** (the principal-injection prevention around
  `AccessController.getContext()`) — whether that binding propagates as well.

- **Interaction with `doAs`'s ACC snapshot** — what a child sees when both a `ScopedValue`
  subject and an ACC snapshot are live, since the duplicated block appears on that method.

- **The read-only requirement** — `callAs` rejects a non-read-only subject; state whether an
  inherited subject is subject to the same constraint.

- **Detection guidance:** a platform thread started inside a bound extent silently has no
  user identity. Say how that is detected, since it fails closed and therefore quietly.

---

## 4. Open questions — trace before documenting

Questions about what the implementation **does today**, not about intent. §0 settled the
platform-thread question; these remain:

1. Do **all** virtual threads propagate, or only those forked within a
   `StructuredTaskScope`? This determines what the OpenJDK-divergence paragraph should say.
2. Does the `STACK_CONTEXT` binding propagate to spawned threads?
3. For `callAs(Callable, UserSubject...)`, does a child see the full set via `currentAll()`
   or only the outermost element?

---

## 5. Constraints on the fix

- **Authoring:** JavaDoc is production/shipped documentation in the divergent security core.
  Under `AI_POLICY.md` as ratified, Zone D is **not adopted** — a human writes the wording.
  This list describes *what to say*, not *how to say it*.
- **Commit trailers:** Zone U forbids AI trailers. No `Co-Authored-By` for AI on commits
  acting on this list.
- **Apply to both duplicate sites** (§1) or extract to one.

---

## 6. Progress log

**2026-07-26 — project lead, first pass.** Site 1 (`callAs`, ~505-511) corrected:
propagation now scoped to VirtualThread, and the unenforceable "cannot leak beyond it"
clause removed.

Resolved:
- §2 blocker 1 — at site 1 only.
- §2 blocker 2 — no longer states a false containment guarantee; now silent on the
  boundary rather than wrong about it (see remaining item below).

Outstanding, in priority order:
1. **Site 2 (~674-680) not updated** — still reads "Any threads spawned" and "cannot leak
   beyond it". The two copies have now drifted and the file contradicts itself. §1 applies:
   fix both or extract to one.
2. **Divergence paragraph now self-contradicting** (~518, dup ~687): "all spawned threads"
   contradicts the corrected sentence above it. Correct the noun, or delete the paragraph
   entirely if §4 Q1 resolves to "only StructuredTaskScope forks propagate" (in which case
   there is no divergence to describe).
3. **Authority outliving the granting extent is still unstated.** The remaining sentence is
   accurate but bounds the binding by the child's lifetime without saying that this may
   exceed the `callAs` extent.
4. **Platform threads excluded only by omission** — state positively, with the fail-closed
   consequence.
5. **Markup:** the sentence at ~511 lost its `<p>` and now renders joined to the preceding
   paragraph.
6. §3 additions all still outstanding.
