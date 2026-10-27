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
 * <li>Not run: the C1 coarse run and the C2 coarse run against the
 *     unimplemented JDK (jtreg stops at the first failing @run), and every
 *     coarse run against a correct implementation.  Nothing is claimed that
 *     the coarse runs PASS; that needs the implementation.</li>
 * <li>Not run: a mutation that coarsens in one tier only (for example
 *     JVM_NanoTime but not the C2 call site).  Once the feature exists, that
 *     is the mutation to apply to each of the three call sites in turn.</li>
 * </ol>
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

    public static void main(String[] args) {
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
