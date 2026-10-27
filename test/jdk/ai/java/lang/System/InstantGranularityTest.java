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
 * @summary With -Dau.zeus.jdk.nanoTime.granularity=G, Instant.now() and
 *          Clock.systemUTC().instant() change no more often than once per G
 *          nanoseconds.  They reach the VM through VM.getNanoTimeAdjustment,
 *          a different native entry from System.nanoTime, and were measured
 *          at 32 ns, so coarsening nanoTime alone leaves a public fine
 *          clock.  The control run leaves the property unset so the coarse
 *          run cannot pass because the platform clock is coarse.  Defends
 *          PROCESS_ISOLATION.md "Fundamental In-Process Limits", item 2,
 *          "Side-channel attacks".  SECURITY_MODEL.md has no timing-specific
 *          invariant; the gap is reported, not worked around.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Dau.zeus.jdk.nanoTime.granularity=1048576 InstantGranularityTest 1048576
 * @run main/othervm -Xint -Dau.zeus.jdk.nanoTime.granularity=1048576 InstantGranularityTest 1048576
 * @run main/othervm InstantGranularityTest 0
 */

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Argument 0 is the granularity the run was started with, or 0 for the
 * control run.
 *
 * The check is a bound on how many distinct instants appear in a window, not
 * a statement about their low bits, so it holds for a floored or a jittered
 * implementation and does not depend on how the nanosecond-of-second field is
 * floored.  Wall-clock time can step, so nothing here asserts monotonicity.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * The mutation is the absence of the feature: no coarsening exists in the
 * built JDK yet, so the property is ignored.
 *
 * <ol>
 * <li>M1: coarse run with the property set, built JDK without the feature.
 *     OBSERVED: two checks FAIL - Instant.now() produced 1,799,540 distinct
 *     instants in 100 ms and Clock.systemUTC().instant() 2,226,504, against
 *     a limit of 99.</li>
 * <li>M2: control run with the property unset.  OBSERVED: PASS.</li>
 * <li>Against the implemented feature (unmutated HotSpot, private copy of the
 *     built JDK, runs executed directly with java rather than through
 *     jtreg): all three @run lines PASS.</li>
 * <li>M3: JVM_GetNanoTimeAdjustment calls os::javaTimeSystemUTC instead of
 *     os::javaTimeSystemUTCCoarse, with nanoTime still coarse.  OBSERVED: both
 *     coarse runs (default and -Xint) FAIL, the control run PASSES.  This is
 *     the mutation the test exists to catch.</li>
 * </ol>
 */
public class InstantGranularityTest {

    static long distinct(long windowMs, boolean useClock) {
        Clock clock = Clock.systemUTC();
        long end = System.currentTimeMillis() + windowMs;
        long prev = Long.MIN_VALUE;
        long distinct = 0;
        while (System.currentTimeMillis() < end) {
            Instant i = useClock ? clock.instant() : Instant.now();
            long t = Math.addExact(Math.multiplyExact(i.getEpochSecond(), 1_000_000_000L), i.getNano());
            if (t != prev) {
                distinct++;
                prev = t;
            }
        }
        return distinct;
    }

    public static void main(String[] args) {
        long g = Long.parseLong(args[0]);
        List<String> failures = new ArrayList<>();

        if (g == 0) {
            long n = distinct(20, false);
            if (n <= 500) {
                failures.add("control: only " + n + " distinct instants in 20 ms; the platform clock is"
                        + " too coarse for the coarse runs to mean anything");
            }
        } else {
            long window = 100;
            long max = window * 1_000_000L / g + 4;
            for (boolean useClock : new boolean[] { false, true }) {
                String label = useClock ? "Clock.systemUTC().instant()" : "Instant.now()";
                long n = distinct(window, useClock);
                if (n > max) {
                    failures.add(label + ": " + n + " distinct instants in " + window
                            + " ms, more than " + max + " allowed by granularity " + g);
                }
                if (n < 5) {
                    failures.add(label + ": only " + n + " distinct instants; the clock did not advance");
                }
            }
        }

        for (String f : failures) {
            System.out.println("FAIL: " + f);
        }
        if (!failures.isEmpty()) {
            throw new RuntimeException(failures.size() + " check(s) failed");
        }
    }
}
