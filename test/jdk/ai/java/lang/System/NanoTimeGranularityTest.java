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
 * @summary With -Dau.zeus.jdk.nanoTime.granularity=G (nanoseconds, a power of
 *          two) System.nanoTime() is no finer than G in every execution tier
 *          (interpreter, C1, C2), never goes backwards, and cannot be made
 *          finer by the running program.  With the property unset the clock
 *          keeps its native resolution, so the coarse runs cannot pass
 *          because the platform clock is coarse.  The proxy JVM hosts
 *          downloaded code that must not build a fine clock; a coarse
 *          nanoTime is the half of the mitigation that does not depend on
 *          thread-creation gates.  Defends PROCESS_ISOLATION.md
 *          "Fundamental In-Process Limits", item 2, "Side-channel attacks".
 *          SECURITY_MODEL.md has no timing-specific invariant; the gap is
 *          reported, not worked around.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @comment -Xcomp compiles the sampling loop on first call, so each tier is
 *          exercised without relying on warm-up.  The C1 run caps compilation
 *          at tier 1; the C2 run disables tiered compilation.
 * @run main/othervm -Xint -Dau.zeus.jdk.nanoTime.granularity=1048576 NanoTimeGranularityTest 1048576
 * @run main/othervm -Xcomp -XX:TieredStopAtLevel=1 -Dau.zeus.jdk.nanoTime.granularity=1048576 NanoTimeGranularityTest 1048576
 * @run main/othervm -Xcomp -XX:-TieredCompilation -Dau.zeus.jdk.nanoTime.granularity=1048576 NanoTimeGranularityTest 1048576
 * @run main/othervm -Xint NanoTimeGranularityTest 0
 * @run main/othervm -Xcomp -XX:-TieredCompilation NanoTimeGranularityTest 0
 */

import java.util.ArrayList;
import java.util.List;

/**
 * Argument 0 is the granularity the run was started with, or 0 for the
 * control runs that leave the property unset.
 *
 * The check that every reading is a multiple of G describes a clock that is
 * floored.  If jitter is later added, that one check is the one to revisit;
 * the rate bound and the minimum step still hold.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * The mutation is the absence of the feature: no coarsening exists in the
 * built JDK yet, so the property is ignored.
 *
 * <ol>
 * <li>M1: coarse run with the property set, built JDK without the feature,
 *     -Xint.  OBSERVED: six checks FAIL - for both the initial window and the
 *     window after setProperty, readings that are not a multiple of G, too
 *     many distinct values, and a step below G.</li>
 * <li>M2: control runs with the property unset, -Xint and -Xcomp
 *     -XX:-TieredCompilation.  OBSERVED: both PASS, so the platform clock
 *     is fine-grained and the coarse runs measure the feature.</li>
 * <li>Against the implemented feature (unmutated HotSpot, private copy of the
 *     built JDK, runs executed directly with java rather than through
 *     jtreg): all five @run lines PASS.</li>
 * </ol>
 *
 * Call-site mutations.  Each reverted ONE call site to the uncoarsened clock,
 * rebuilt libjvm (make hotspot), put it in a private copy of the JDK image,
 * and restored the source with git checkout.
 * <ol>
 * <li>M3: JVM_NanoTime (interpreter and native entry) returns
 *     os::javaTimeNanos().  OBSERVED: the -Xint coarse run FAILS and the C2
 *     coarse run FAILS; the C1 coarse run PASSES.  The C2 run fails because
 *     its first compile of sample() is discarded by an uncommon trap and the
 *     loop finishes in the interpreter before the OSR compile, so part of
 *     that run reads the clock through JVM_NanoTime.  The C1 run is compiled
 *     once and never uses JVM_NanoTime.</li>
 * <li>M4: the C2 intrinsic (library_call.cpp) uses os::javaTimeNanos.
 *     OBSERVED: only the C2 coarse run FAILS.</li>
 * <li>M5: the C1 intrinsic (c1_LIRGenerator.cpp) uses os::javaTimeNanos.
 *     OBSERVED: only the C1 coarse run FAILS.  An earlier version of this
 *     test did not catch this mutation: -Xcomp compiles sample() at its first
 *     call, before this class had executed System.nanoTime(), so the
 *     constant-pool entry was unresolved, the compiler reported the callee as
 *     "(not loaded) failed to inline", and C1 emitted an ordinary call to the
 *     native method.  main() now runs System.nanoTime() and
 *     System.currentTimeMillis() once before sample() is first called;
 *     -XX:+PrintInlining then shows System::nanoTime inlined as an intrinsic
 *     in the C1 compile of sample().</li>
 * </ol>
 *
 * Not covered: the function address exported to JVMCI compilers
 * (vmStructs_jvmci.cpp) needs a JVMCI compiler to exercise and was not tested.
 */
public class NanoTimeGranularityTest {

    static final String PROP = "au.zeus.jdk.nanoTime.granularity";

    static final class Stats {
        long calls;
        long distinct = 1;
        long backwards;
        long notMultiple;
        long minStep = Long.MAX_VALUE;
    }

    static Stats sample(long windowMs, long g) {
        Stats s = new Stats();
        long end = System.currentTimeMillis() + windowMs;
        long prev = System.nanoTime();
        while (System.currentTimeMillis() < end) {
            long t = System.nanoTime();
            s.calls++;
            if (t < prev) {
                s.backwards++;
            } else if (t > prev) {
                s.distinct++;
                s.minStep = Math.min(s.minStep, t - prev);
            }
            if (g > 0 && Math.floorMod(t, g) != 0) {
                s.notMultiple++;
            }
            prev = t;
        }
        return s;
    }

    static void checkCoarse(String label, Stats s, long g, long windowMs, List<String> failures) {
        long maxDistinct = windowMs * 1_000_000L / g + 4;
        if (s.backwards != 0) {
            failures.add(label + ": nanoTime went backwards " + s.backwards + " times");
        }
        if (s.notMultiple != 0) {
            failures.add(label + ": " + s.notMultiple + " readings are not a multiple of " + g);
        }
        if (s.distinct > maxDistinct) {
            failures.add(label + ": " + s.distinct + " distinct values in " + windowMs
                    + " ms, more than " + maxDistinct + " allowed by granularity " + g);
        }
        if (s.distinct < 5) {
            failures.add(label + ": only " + s.distinct + " distinct values; the clock did not advance");
        }
        if (s.distinct > 1 && s.minStep < g) {
            failures.add(label + ": smallest step " + s.minStep + " ns is below granularity " + g);
        }
    }

    /** Keeps the warm-up readings live so they cannot be discarded. */
    static volatile long warm;

    public static void main(String[] args) {
        // Under -Xcomp sample() is compiled the first time it is called.  If
        // this class has not yet executed System.nanoTime() and
        // System.currentTimeMillis(), those constant-pool entries are still
        // unresolved, the compiler sees the callees as "not loaded", and C1
        // emits an ordinary call to the native method instead of the
        // intrinsic, so the C1 run would never reach the C1 call site.  Run
        // each call once here so the compile of sample() sees them resolved.
        warm = System.nanoTime() + System.currentTimeMillis();

        long g = Long.parseLong(args[0]);
        List<String> failures = new ArrayList<>();

        if (g == 0) {
            if (System.getProperty(PROP) != null) {
                throw new RuntimeException("control run must not set " + PROP);
            }
            Stats s = sample(20, 0);
            if (s.distinct <= 500) {
                failures.add("control: only " + s.distinct + " distinct values in 20 ms; the platform"
                        + " clock is too coarse for the coarse runs to mean anything");
            }
            if (s.minStep >= 1000) {
                failures.add("control: smallest step " + s.minStep + " ns is not fine-grained");
            }
        } else {
            checkCoarse("coarse", sample(100, g), g, 100, failures);

            // Running code must not be able to refine the clock by changing the property.
            System.setProperty(PROP, "1");
            checkCoarse("after setProperty(" + PROP + ", 1)", sample(30, g), g, 30, failures);
        }

        for (String f : failures) {
            System.out.println("FAIL: " + f);
        }
        if (!failures.isEmpty()) {
            throw new RuntimeException(failures.size() + " check(s) failed");
        }
    }
}
