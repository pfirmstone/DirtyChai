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
 * @summary A malformed -Dau.zeus.jdk.nanoTime.granularity makes the VM refuse
 *          to start, and a well-formed one starts normally.  A launcher typo
 *          must not leave the proxy JVM running with an unmitigated clock;
 *          the failure is secure, not silent.  The valid-value controls stop
 *          the rejections passing because the VM fails to start for some
 *          other reason.  Defends the fail-secure rule in CLAUDE.md
 *          (P6, HC-2).  SECURITY_MODEL.md has no timing-specific invariant;
 *          the gap is reported, not worked around.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm NanoTimeGranularityBadValueTest
 */

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Starts a child JVM per value with -version.  The value set assumes the
 * rules in the design: a positive integer number of nanoseconds, a power of
 * two, no unit suffix.  Zero is treated as malformed, not as "off"; to turn
 * coarsening off, leave the property unset.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * The mutation is the absence of the feature: no validation exists in the
 * built JDK yet, so the property is ignored and every value starts the VM.
 *
 * <ol>
 * <li>M1: built JDK without the feature.  OBSERVED: eight checks FAIL, one
 *     per malformed value, because the VM started.  The two valid-value
 *     controls PASS.</li>
 * <li>Not run: any run against a correct implementation, so nothing is
 *     claimed that the valid values are accepted once validation exists.
 *     The test also does not show that the malformed values are rejected
 *     for the right reason; it checks only the exit status.</li>
 * </ol>
 */
public class NanoTimeGranularityBadValueTest {

    static final String PROP = "au.zeus.jdk.nanoTime.granularity";

    static final String[] BAD = {
        "0", "-1048576", "3", "1000", "1ms", "", "abc", "99999999999999999999",
    };

    static final String[] GOOD = { "1024", "1048576" };

    static int run(String value) throws Exception {
        String home = System.getProperty("test.jdk", System.getProperty("java.home"));
        String java = home + File.separator + "bin" + File.separator + "java";
        ProcessBuilder pb = new ProcessBuilder(java, "-D" + PROP + "=" + value, "-version");
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
        Process p = pb.start();
        if (!p.waitFor(60, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new RuntimeException("child JVM did not exit for value '" + value + "'");
        }
        return p.exitValue();
    }

    public static void main(String[] args) throws Exception {
        List<String> failures = new ArrayList<>();
        for (String v : BAD) {
            int rc = run(v);
            if (rc == 0) {
                failures.add("value '" + v + "' was accepted, the VM started");
            }
        }
        for (String v : GOOD) {
            int rc = run(v);
            if (rc != 0) {
                failures.add("value '" + v + "' was rejected, exit " + rc);
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
