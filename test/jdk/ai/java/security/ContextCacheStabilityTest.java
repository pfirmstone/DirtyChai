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
 * @summary Repeating AccessController.getContext() (or
 *          SecurityManager.getSecurityContext()) from the same call site,
 *          with the same domains on the stack and in the inherited context,
 *          must return the same cached AccessControlContext instance.
 *          CombinerSecurityManager's checked-permission and delegate caches
 *          are keyed by the execution context (SECURITY_MODEL.md section 5.1,
 *          "CombinerSecurityManager.checkPermission"), so a context that is
 *          rebuilt on every call defeats them and every permission check
 *          pays for a full policy evaluation.  The returned context must
 *          still be the effective context of section 11.6.4,
 *          "AccessController.getContext() snapshots current effective
 *          context (including inherited context ...)": each call must give a
 *          context equal to the first.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @build ContextCacheStabilityHelper
 * @run main/othervm -Djava.security.manager=allow ContextCacheStabilityTest
 */

import java.io.InputStream;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.ref.Reference;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Measures how many distinct AccessControlContext instances a fixed call
 * site produces over {@link #CALLS} identical calls.  A working context
 * cache gives exactly one, the instance returned by the first call, which
 * the test keeps strongly reachable so the cache's weakly referenced value
 * cannot be cleared mid-scenario.
 *
 * <p>Found while profiling the jgdms-benchmarks policy-overhead benchmark:
 * there, both AccessControlContext.create calls made by each
 * getContext() (the one from the native stack walk and the one from
 * optimize()) took the cache-miss branch on essentially every permission
 * check, and each check cost about 4 microseconds.
 *
 * <p>A second, separately loaded copy of {@link ContextCacheStabilityHelper}
 * with its own ProtectionDomain supplies a second non-system domain, so the
 * scenarios cover:
 * <ol>
 * <li>the stack context alone (main thread);</li>
 * <li>a stack domain combined with a different inherited domain, which goes
 *     through optimize();</li>
 * <li>two stack domains plus an inherited domain, the shape of a benchmark
 *     check (workload and harness on the stack);</li>
 * <li>the same domain twice on the stack, separated by another domain
 *     (A calls B calls A).  The VM's stack walk collapses only adjacent
 *     duplicates, so the domain array holds A twice;</li>
 * <li>SecurityManager.getSecurityContext(), on both threads;</li>
 * <li>cases 1, 5 and 3 again (6a to 6c) without holding any result, in a
 *     loop long enough to be JIT-compiled, as a permission check uses the
 *     context.  The benchmark's contexts are discarded straight away, so
 *     only the cache's weakly referenced value keeps them.</li>
 * </ol>
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation below is applied to AccessControlContext.create(), the test
 * is run, and the failing checks are recorded.  OBSERVED entries must be
 * filled in from an actual run before this test is merged; until then this
 * test has not been demonstrated load-bearing.
 * <ol>
 * <li>M1: skip the cache lookup and insertion, always returning a new
 *     AccessControlContext.
 *     EXPECTED: every "one cached instance" check fails; every "equal to
 *     the first" check passes.
 *     OBSERVED: not yet recorded.</li>
 * <li>M2: add System.identityHashCode of the domain array to the
 *     ContextKey hash, so equal keys built from different arrays never
 *     meet.
 *     EXPECTED: every "one cached instance" check fails.
 *     OBSERVED: not yet recorded.</li>
 * <li>M3: hold cached values only for the duration of the call (for
 *     example, return the new context without inserting it when the
 *     cached value has been cleared).
 *     EXPECTED: the 6a to 6c "cached between garbage collections" checks
 *     fail; scenarios 1 to 5 pass, because they hold their first result.
 *     OBSERVED: not yet recorded.</li>
 * </ol>
 *
 * <p>Note on scenario 4: the stack walk's array holds A twice, and
 * ContextKey.match() compares the key's domain set size with that array's
 * length, so the intermediate stack context is not served from the cache.
 * optimize() removes the duplicate before building the context that
 * getContext() returns, so this scenario passes regardless; it guards the
 * returned context, not the intermediate one.
 */
public class ContextCacheStabilityTest {

    private static final int CALLS = 1000;

    /** Enough calls for the loop and the context code to be JIT-compiled. */
    private static final int UNHELD_CALLS = 200_000;

    private static final String HELPER = "ContextCacheStabilityHelper";

    /** Grants every permission: this test is about caching, not policy. */
    static final class TestPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            return true;
        }
    }

    /** Defines the helper with a ProtectionDomain of its own. */
    static final class HelperLoader extends ClassLoader {
        private final ProtectionDomain domain;

        HelperLoader() throws Exception {
            super("ContextCacheStabilityTest-helper",
                    ClassLoader.getPlatformClassLoader());
            CodeSource cs = new CodeSource(
                    new URL("file:/ContextCacheStabilityTest/helper/"),
                    (Certificate[]) null);
            domain = new ProtectionDomain(cs, null, this, null);
        }

        Class<?> define(byte[] bytes) {
            return defineClass(HELPER, bytes, 0, bytes.length, domain);
        }
    }

    private static Function<Object, Object> helper;
    private static int failures;

    @SuppressWarnings("removal")
    public static void main(String[] args) throws Throwable {
        Policy.setPolicy(new TestPolicy());
        // The first SecurityManager to be set enables the context cache.
        System.setSecurityManager(new SecurityManager());

        helper = loadHelper();

        expectOneInstance("1. stack context, main thread",
                ContextCacheStabilityTest::stackContext);
        expectOneInstance("5a. security context, main thread",
                ContextCacheStabilityTest::securityContext);

        Throwable[] thrown = new Throwable[1];
        helper.apply((Runnable) () -> {
            try {
                expectOneInstance("2. stack domain with a different inherited domain",
                        ContextCacheStabilityTest::stackContext);
                expectOneInstance("3. two stack domains with an inherited domain",
                        () -> helper.apply("getContext"));
                expectOneInstance("4. same domain twice on the stack (A, B, A)",
                        () -> helper.apply((Supplier<Object>)
                                ContextCacheStabilityTest::stackContext));
                expectOneInstance("5b. security context, inherited domain",
                        ContextCacheStabilityTest::securityContext);
            } catch (Throwable t) {
                thrown[0] = t;
            }
        });
        if (thrown[0] != null) {
            throw thrown[0];
        }

        expectCachedWhileUnheld("6a. stack context, unheld, hot loop",
                ContextCacheStabilityTest::stackContext);
        expectCachedWhileUnheld("6b. security context, unheld, hot loop",
                ContextCacheStabilityTest::securityContext);
        helper.apply((Runnable) () -> {
            try {
                expectCachedWhileUnheld("6c. two stack domains with an inherited domain, unheld, hot loop",
                        () -> helper.apply("getContext"));
            } catch (Throwable t) {
                thrown[0] = t;
            }
        });
        if (thrown[0] != null) {
            throw thrown[0];
        }

        if (failures > 0) {
            throw new RuntimeException(failures + " check(s) failed, see output");
        }
        System.out.println("PASSED");
    }

    @SuppressWarnings("removal")
    private static Object stackContext() {
        return AccessController.getContext();
    }

    @SuppressWarnings("removal")
    private static Object securityContext() {
        return System.getSecurityManager().getSecurityContext();
    }

    /**
     * Calls {@code source} {@link #CALLS} times after a first call, and
     * checks that every result is the first result: the same instance, and
     * (as a diagnostic for when it is not) an equal context.
     */
    private static void expectOneInstance(String scenario, Supplier<Object> source) {
        Object first = source.get();
        check(scenario + ": returns an AccessControlContext",
                first instanceof AccessControlContext);

        Set<Object> instances = Collections.newSetFromMap(new IdentityHashMap<>());
        instances.add(first);
        int unequal = 0;
        for (int i = 0; i < CALLS; i++) {
            Object next = source.get();
            if (next != first) {
                instances.add(next);
                if (!first.equals(next)) {
                    unequal++;
                }
            }
        }
        System.out.println("        " + scenario + ": " + instances.size()
                + " distinct instance(s) over " + (CALLS + 1) + " calls");
        check(scenario + ": one cached instance", instances.size() == 1);
        check(scenario + ": every result equal to the first", unequal == 0);

        Reference.reachabilityFence(first);
    }

    /**
     * As a permission check uses it: each context is discarded as soon as it
     * is returned, so only the cache's weakly referenced value keeps it, and
     * the loop runs long enough to be compiled.  The cached instance may
     * legitimately be replaced after a garbage collection clears it, so the
     * check allows a few replacements per collection (one for the stack
     * context and one for the optimized context, plus slack), but not one
     * per call.
     */
    private static void expectCachedWhileUnheld(String scenario, Supplier<Object> source) {
        long gcBefore = gcCount();
        int previous = System.identityHashCode(source.get());
        int replacements = 0;
        for (int i = 0; i < UNHELD_CALLS; i++) {
            int id = System.identityHashCode(source.get());
            if (id != previous) {
                replacements++;
                previous = id;
            }
        }
        long gcs = gcCount() - gcBefore;
        long allowed = 2 * (gcs + 1) + 2;
        System.out.println("        " + scenario + ": instance replaced " + replacements
                + " time(s) over " + UNHELD_CALLS + " calls, " + gcs
                + " garbage collection(s), " + allowed + " allowed");
        check(scenario + ": cached between garbage collections", replacements <= allowed);
    }

    private static long gcCount() {
        long count = 0;
        for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            count += Math.max(0, gc.getCollectionCount());
        }
        return count;
    }

    @SuppressWarnings("unchecked")
    private static Function<Object, Object> loadHelper() throws Exception {
        byte[] bytes;
        try (InputStream in = ContextCacheStabilityTest.class.getClassLoader()
                .getResourceAsStream(HELPER + ".class")) {
            if (in == null) {
                throw new IllegalStateException(HELPER + ".class not found");
            }
            bytes = in.readAllBytes();
        }
        Class<?> c = new HelperLoader().define(bytes);
        check("setup: helper has its own protection domain",
                c.getProtectionDomain()
                        != ContextCacheStabilityTest.class.getProtectionDomain());
        return (Function<Object, Object>) c.getDeclaredConstructor().newInstance();
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok      " : "FAILED  ") + what);
        if (!ok) failures++;
    }
}
