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
 * @summary Reading a thread's CPU or user time through ThreadMXBean requires
 *          ManagementPermission("monitor") when a security manager is
 *          installed, on every public entry point, and the check happens
 *          before any dependence on whether CPU timing is supported or on
 *          the kind of thread, so a caller without the grant learns nothing.
 *          Thread CPU time has nanosecond resolution and is not covered by
 *          the nanoTime granularity property, so an ungated read is a
 *          second fine-grained clock for code that is denied System.nanoTime
 *          precision.  Defends SECURITY_MODEL.md section 4 guarantee 2,
 *          "Least privilege", and PROCESS_ISOLATION.md "Fundamental
 *          In-Process Limits", item 2, "Side-channel attacks".
 *          SECURITY_MODEL.md has no timing-specific invariant; the gap is
 *          reported, not worked around.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules jdk.management
 * @run main/othervm -Djava.security.manager=allow ThreadCpuTimePermissionTest
 */

import java.lang.management.ManagementFactory;
import java.lang.management.ManagementPermission;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Two phases over the same entry points.  In the denied phase the policy
 * withholds ManagementPermission("monitor") from every domain and every
 * entry point must throw SecurityException.  In the granted phase the policy
 * grants it and every entry point must complete, which stops the denied
 * phase passing because a call fails for some unrelated reason.
 *
 * The entry points are the six ThreadImpl methods that read CPU or user
 * time, reached the way a caller reaches them: the one-id and current-thread
 * forms on ThreadMXBean and the id-array forms that only
 * com.sun.management.ThreadMXBean exposes.  The two current-thread forms are
 * also run on a virtual thread, where an unchecked implementation returns -1
 * without ever consulting the policy.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation removed the Util.checkMonitorAccess() call from one ThreadImpl
 * method in a copy of the working-tree source, compiled and loaded with
 * --patch-module over the built tierAI JDK; the source tree was not modified.
 * The baseline before the checks existed (the built JDK image, without the
 * ThreadImpl edit) fails all eight denied-phase checks and passes all eight
 * granted-phase checks.  The working tree passes 16 of 16.
 *
 * <ol>
 * <li>M1: remove the check from getCurrentThreadCpuTime().
 *     OBSERVED: two checks FAIL - getCurrentThreadCpuTime() and the same
 *     call on a virtual thread.</li>
 * <li>M2: remove the check from getCurrentThreadUserTime().
 *     OBSERVED: two checks FAIL - getCurrentThreadUserTime() and the same
 *     call on a virtual thread.</li>
 * <li>M3, M4: remove the check from getThreadCpuTime(long) or from
 *     getThreadUserTime(long) alone.
 *     OBSERVED: no check FAILS.  Those wrappers delegate to the id-array
 *     method, which checks, so each wrapper check is redundant with the
 *     array method's.  This test cannot show either wrapper check
 *     load-bearing on its own; see M7.</li>
 * <li>M5: remove the check from getThreadCpuTime(long[]).
 *     OBSERVED: one check FAILS - getThreadCpuTime(long[]).  The one-id form
 *     still passes because its wrapper checks.</li>
 * <li>M6: remove the check from getThreadUserTime(long[]).
 *     OBSERVED: one check FAILS - getThreadUserTime(long[]).</li>
 * <li>M7: remove the checks from both getThreadCpuTime(long) and
 *     getThreadCpuTime(long[]); and the same pair for the user-time methods.
 *     OBSERVED: two checks FAIL in each case - the one-id form and the
 *     id-array form.</li>
 * </ol>
 *
 * Not covered: com.sun.management.OperatingSystemMXBean.getProcessCpuTime(),
 * which has no check and is not a fine clock on Linux (it reads times()).
 */
@SuppressWarnings("removal")
public class ThreadCpuTimePermissionTest {

    static volatile boolean monitorGranted;

    static final List<String> failures = new ArrayList<>();

    /** Grants everything except ManagementPermission("monitor"), which follows monitorGranted. */
    static final class MonitorPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (permission instanceof ManagementPermission
                    && "monitor".equals(permission.getName())) {
                return monitorGranted;
            }
            return true;
        }
    }

    record Case(String name, Callable<Object> call) { }

    static Object onVirtualThread(Callable<Object> call) throws Exception {
        Object[] result = new Object[1];
        Throwable[] error = new Throwable[1];
        Thread t = Thread.ofVirtual().start(() -> {
            try {
                result[0] = call.call();
            } catch (Throwable e) {
                error[0] = e;
            }
        });
        t.join();
        if (error[0] instanceof Exception e) {
            throw e;
        }
        if (error[0] != null) {
            throw (Error) error[0];
        }
        return result[0];
    }

    public static void main(String[] args) throws Exception {
        com.sun.management.ThreadMXBean bean =
                ManagementFactory.getPlatformMXBean(com.sun.management.ThreadMXBean.class);
        if (!bean.isCurrentThreadCpuTimeSupported()) {
            throw new RuntimeException("thread CPU time unsupported here: the test would pass vacuously");
        }
        long id = Thread.currentThread().threadId();
        long[] ids = { id };

        List<Case> cases = List.of(
            new Case("getCurrentThreadCpuTime()", bean::getCurrentThreadCpuTime),
            new Case("getCurrentThreadUserTime()", bean::getCurrentThreadUserTime),
            new Case("getThreadCpuTime(long)", () -> bean.getThreadCpuTime(id)),
            new Case("getThreadUserTime(long)", () -> bean.getThreadUserTime(id)),
            new Case("getThreadCpuTime(long[])", () -> bean.getThreadCpuTime(ids)),
            new Case("getThreadUserTime(long[])", () -> bean.getThreadUserTime(ids)),
            new Case("getCurrentThreadCpuTime() on a virtual thread",
                     () -> onVirtualThread(bean::getCurrentThreadCpuTime)),
            new Case("getCurrentThreadUserTime() on a virtual thread",
                     () -> onVirtualThread(bean::getCurrentThreadUserTime)));

        Policy.setPolicy(new MonitorPolicy());
        System.setSecurityManager(new SecurityManager());

        monitorGranted = false;
        for (Case c : cases) {
            try {
                c.call().call();
                failures.add("denied phase, NOT denied: " + c.name());
            } catch (SecurityException expected) {
                // the invariant holds for this entry point
            } catch (Throwable other) {
                failures.add("denied phase, wrong exception for " + c.name() + ": " + other);
            }
        }

        monitorGranted = true;
        for (Case c : cases) {
            try {
                c.call().call();
            } catch (Throwable t) {
                failures.add("granted phase, should succeed: " + c.name() + ": " + t);
            }
        }

        for (String f : failures) {
            System.out.println("FAIL: " + f);
        }
        System.out.println(cases.size() * 2 - failures.size() + " of " + cases.size() * 2 + " checks passed");
        if (!failures.isEmpty()) {
            throw new RuntimeException(failures.size() + " check(s) failed");
        }
    }
}
