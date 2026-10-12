/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  This particular file is
 * subject to the "Classpath" exception as provided in the LICENSE file
 * that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/**
 * @test
 * @summary The AccessControlContext cache must never return a context whose
 *          domains differ from the ones requested, even when the cache keys
 *          of two different contexts have the same hash code; a context
 *          returned by AccessControlContext.create must encapsulate exactly
 *          the requested domains, or permission checks are evaluated against
 *          domains the caller never had (over-grant or spurious denial).
 *          Defends SECURITY_MODEL.md section 11.6.4, "AccessControlContext.
 *          checkPermission(...) evaluates against the encapsulated context",
 *          section 4 guarantee 2, "Least privilege", and section 15
 *          invariant 4, "Policy evaluation must remain deny-by-default".
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow ContextCacheCollisionTest
 */

import java.lang.ref.Reference;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * The AccessControlContext cache (java.security.ContextCache) is a
 * ConcurrentSkipListMap keyed by AccessControlContext.ContextKey.  A skip
 * list locates entries with compareTo only; equals is never consulted.  If
 * the ordering treats two keys with equal hash codes as the same key, a
 * lookup for one context returns a cached context containing different
 * ProtectionDomains, and permission checks are then evaluated against
 * domains the caller never had.
 *
 * Hash collisions between unrelated contexts happen naturally: roughly
 * (live cache entries / 2^32) per lookup.  With plain ProtectionDomains,
 * which use identity equality, every SubjectDomainCombiner.combine() call
 * creates new domains, so the number of live entries grows with load.  This
 * test forces the collision deterministically with a ProtectionDomain
 * subclass that returns a fixed hash code while keeping identity equality.
 *
 * Each scenario uses its own hash value so the scenarios cannot satisfy
 * each other's lookups.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation below is applied to AccessControlContext.create(), the test
 * is run, and the failing checks are recorded.  OBSERVED entries must be
 * filled in from an actual run before this test is merged; until then this
 * test has not been demonstrated load-bearing.
 * <ol>
 * <li>M1: return a cache hit (from get or putIfAbsent) without checking
 *     that its domains match the requested ones, as on trunk b138bbd1.
 *     EXPECTED: "escalation: distinct contexts for colliding keys",
 *     "escalation: unprivileged context must not imply SECRET",
 *     "denial: distinct contexts for colliding keys" and
 *     "denial: privileged context must imply SECRET" fail.
 *     OBSERVED: not yet recorded.</li>
 * <li>M2: treat every cache hit as a mismatch, so nothing is ever served
 *     from the cache.
 *     EXPECTED: "control: value-equal domains intern to one cached context"
 *     and "control: empty contexts intern to one cached context" fail.
 *     OBSERVED: not yet recorded.</li>
 * <li>M3: compare a null key domain set with an empty set when matching a
 *     hit, so a context with no domains never matches itself.
 *     EXPECTED: "control: empty contexts intern to one cached context" fails.
 *     OBSERVED: not yet recorded.</li>
 * </ol>
 */
public class ContextCacheCollisionTest {

    private static final Permission SECRET =
            new RuntimePermission("ContextCacheCollisionTest.secret");

    /**
     * A ProtectionDomain with a chosen hash code and inherited identity
     * equality.  Two instances with the same hash are unequal, so any
     * correct cache must keep them apart.
     */
    static final class FixedHashDomain extends ProtectionDomain {
        private final int hash;

        FixedHashDomain(int hash, PermissionCollection perms) {
            super(null, perms);
            this.hash = hash;
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public String toString() {
            return "FixedHashDomain@" + System.identityHashCode(this)
                    + "[hash=" + hash + "]";
        }
    }

    /**
     * Grants every permission to every domain except the test's
     * FixedHashDomains, which keep only their static permissions.  This lets
     * the test install a SecurityManager (which enables the context cache)
     * without the policy itself granting SECRET to the domains under test.
     */
    static final class TestPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            return !(domain instanceof FixedHashDomain);
        }
    }

    private static int failures;

    public static void main(String[] args) throws Exception {
        Policy.setPolicy(new TestPolicy());
        // The first SecurityManager to be set enables the context cache.
        System.setSecurityManager(new SecurityManager());

        cachedGrantedThenRequestDenied(0x5EC0C0DE);
        cachedDeniedThenRequestGranted(0x5EC0C0DF);
        distinctHashesStayDistinct(0x5EC0C0E0, 0x5EC0C0E1);
        equalDomainsShareOneContext();
        emptyContextsShareOneContext();

        if (failures > 0) {
            throw new RuntimeException(failures + " check(s) failed, see output");
        }
        System.out.println("PASSED");
    }

    /**
     * Escalation direction: a context holding SECRET is cached first.  A
     * different context with the same key hash, holding no permissions, must
     * not be handed the cached privileged context.
     */
    private static void cachedGrantedThenRequestDenied(int hash) {
        ProtectionDomain granted = new FixedHashDomain(hash, permits(SECRET));
        ProtectionDomain denied = new FixedHashDomain(hash, new Permissions());

        AccessControlContext grantedAcc =
                AccessControlContext.create(new ProtectionDomain[] { granted });
        AccessControlContext deniedAcc =
                AccessControlContext.create(new ProtectionDomain[] { denied });

        check("escalation: distinct contexts for colliding keys",
                deniedAcc != grantedAcc);
        check("escalation: unprivileged context must not imply SECRET",
                !implies(deniedAcc, SECRET));
        check("escalation: privileged context still implies SECRET",
                implies(grantedAcc, SECRET));

        // Keep the cached entry strongly reachable: the cache holds weakly
        // referenced values that may otherwise be cleared mid-test.
        Reference.reachabilityFence(grantedAcc);
        Reference.reachabilityFence(deniedAcc);
    }

    /**
     * Denial direction: a context with no permissions is cached first.  A
     * different context with the same key hash, holding SECRET, must not
     * be handed the cached unprivileged context.
     */
    private static void cachedDeniedThenRequestGranted(int hash) {
        ProtectionDomain denied = new FixedHashDomain(hash, new Permissions());
        ProtectionDomain granted = new FixedHashDomain(hash, permits(SECRET));

        AccessControlContext deniedAcc =
                AccessControlContext.create(new ProtectionDomain[] { denied });
        AccessControlContext grantedAcc =
                AccessControlContext.create(new ProtectionDomain[] { granted });

        check("denial: distinct contexts for colliding keys",
                grantedAcc != deniedAcc);
        check("denial: privileged context must imply SECRET",
                implies(grantedAcc, SECRET));
        check("denial: unprivileged context still denies SECRET",
                !implies(deniedAcc, SECRET));

        Reference.reachabilityFence(deniedAcc);
        Reference.reachabilityFence(grantedAcc);
    }

    /** Control: contexts whose keys hash differently are already kept apart. */
    private static void distinctHashesStayDistinct(int hashA, int hashB) {
        ProtectionDomain a = new FixedHashDomain(hashA, permits(SECRET));
        ProtectionDomain b = new FixedHashDomain(hashB, new Permissions());

        AccessControlContext accA =
                AccessControlContext.create(new ProtectionDomain[] { a });
        AccessControlContext accB =
                AccessControlContext.create(new ProtectionDomain[] { b });

        check("control: distinct hashes give distinct contexts", accA != accB);
        check("control: distinct-hash unprivileged context denies SECRET",
                !implies(accB, SECRET));

        Reference.reachabilityFence(accA);
        Reference.reachabilityFence(accB);
    }

    /**
     * Control: value-equal DomainIdentity instances must still share one
     * cached context.  A fix that simply stops caching would pass the
     * collision checks above but fail here.
     */
    private static void equalDomainsShareOneContext() throws Exception {
        CodeSource cs = new CodeSource(
                new URL("file:/ContextCacheCollisionTest/equal/"), (Certificate[]) null);
        ProtectionDomain first = new DomainIdentity(cs, new Permissions());
        ProtectionDomain second = new DomainIdentity(cs, new Permissions());

        check("control: value-equal DomainIdentity instances are equal",
                first.equals(second) && first.hashCode() == second.hashCode());

        AccessControlContext firstAcc =
                AccessControlContext.create(new ProtectionDomain[] { first });
        AccessControlContext secondAcc =
                AccessControlContext.create(new ProtectionDomain[] { second });

        check("control: value-equal domains intern to one cached context",
                firstAcc == secondAcc);

        Reference.reachabilityFence(firstAcc);
        Reference.reachabilityFence(secondAcc);
    }

    /**
     * Control: a context with no domains (stored as a null domain array) is
     * the most common context of all, the one seen when only system code is
     * on the stack.  A hit check that compares a null domain set with an
     * empty one would reject every such hit and stop these contexts being
     * cached.
     */
    private static void emptyContextsShareOneContext() {
        AccessControlContext first =
                AccessControlContext.create(new ProtectionDomain[0]);
        AccessControlContext second =
                AccessControlContext.create(new ProtectionDomain[0]);

        check("control: empty contexts intern to one cached context",
                first == second);

        Reference.reachabilityFence(first);
        Reference.reachabilityFence(second);
    }

    private static PermissionCollection permits(Permission p) {
        Permissions perms = new Permissions();
        perms.add(p);
        return perms;
    }

    private static boolean implies(AccessControlContext acc, Permission p) {
        try {
            acc.checkPermission(p);
            return true;
        } catch (AccessControlException e) {
            return false;
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok      " : "FAILED  ") + what);
        if (!ok) failures++;
    }
}
