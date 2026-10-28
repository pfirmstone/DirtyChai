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
 * @summary Every route to the system-wide AsynchronousChannelProvider
 *          requires RuntimePermission("getAsynchronousChannelProvider") when
 *          a security manager is installed: opening a socket or server
 *          socket channel on the default group, calling
 *          AsynchronousChannelProvider.provider() directly, and creating a
 *          channel group (including one built on an executor that creates
 *          no thread).  The default group creates its completion threads
 *          inside doPrivileged, so the thread permissions never see the
 *          caller; this permission is what stops code that holds only a
 *          SocketPermission from obtaining a JDK-created thread that runs its
 *          CompletionHandler and can be used as a counter clock.  A denial
 *          must not leave the provider unusable for a caller that holds the
 *          permission.  Defends SECURITY_MODEL.md section 11.1 (asynchronous
 *          I/O provider) and section 4 guarantee 2, "Least privilege".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow AsyncChannelProviderPermissionTest
 */

import java.nio.channels.AsynchronousChannelGroup;
import java.nio.channels.AsynchronousServerSocketChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.nio.channels.spi.AsynchronousChannelProvider;
import java.security.Permission;
import java.security.Policy;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Two phases over the same entry points.  In the denied phase the policy
 * grants everything except RuntimePermission("getAsynchronousChannelProvider")
 * and every entry point must throw SecurityException.  In the granted phase
 * the policy grants it and every entry point must complete, which stops the
 * denied phase passing because a call fails for some unrelated reason.  The
 * denied phase runs first, so the granted phase also shows that a denial did
 * not leave the provider's lazily loaded state unusable.
 *
 * The same-thread executor in the group cases creates no thread, so those
 * cases cannot be stopped by a thread permission.  They are the route
 * through which a group, and then group.provider(), could otherwise be
 * obtained.
 *
 * Not covered: code that is handed an existing group or channel by code that
 * did hold the permission.  group.provider() and channel.provider() return the
 * real provider, so such a reference reaches the default group without a
 * check.  That is outside what this permission can enforce.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation was a patched copy of the named class, compiled and loaded
 * with --patch-module over the built tierAI JDK, which already contains the
 * check in AsynchronousChannelProvider.provider(); the source tree was not
 * modified.  With that check the test passes 12 of 12.
 *
 * <ol>
 * <li>M1: AsynchronousChannelProvider.provider() without any check (the file
 *     as committed before the check was added).
 *     OBSERVED: all six denied-phase checks FAIL, none was denied; the six
 *     granted-phase checks pass.</li>
 * <li>M2: no check in provider(); a check only in the default-group branch of
 *     AsynchronousSocketChannel.open(group), the obvious wrapper placement.
 *     OBSERVED: five checks FAIL - AsynchronousServerSocketChannel.open(),
 *     AsynchronousChannelProvider.provider(), the direct
 *     provider().openAsynchronousSocketChannel(null), the group built on a
 *     same-thread executor, and that group followed by group.provider().
 *     Only AsynchronousSocketChannel.open() is denied.</li>
 * <li>M3: the check moved into ProviderHolder.load(), which runs in the
 *     holder's static initialiser, with none in provider().
 *     OBSERVED: all twelve checks FAIL.  The first denial raises
 *     ExceptionInInitializerError, every later call, denied or granted,
 *     raises NoClassDefFoundError, and the provider stays unusable for the
 *     rest of the JVM.  This is the failure the denied-then-granted order of
 *     the two phases exists to catch.</li>
 * </ol>
 *
 * Not run: a mutation that checks in the platform provider's toPort(group)
 * instead of provider().  By reading the code it would stop the two open()
 * cases and the direct provider().openAsynchronousSocketChannel(null) call,
 * which reach toPort, but not AsynchronousChannelProvider.provider() itself
 * or the two group cases, which do not; this was not applied.
 */
@SuppressWarnings("removal")
public class AsyncChannelProviderPermissionTest {

    static volatile boolean granted;

    static final List<String> failures = new ArrayList<>();

    /** Grants everything except getAsynchronousChannelProvider, which follows the flag. */
    static final class ProviderPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (permission instanceof RuntimePermission
                    && "getAsynchronousChannelProvider".equals(permission.getName())) {
                return granted;
            }
            return true;
        }
    }

    record Case(String name, Callable<Object> call) { }

    /** An executor that runs each task on the calling thread and so creates none. */
    static ExecutorService sameThreadExecutor() {
        return new AbstractExecutorService() {
            public void execute(Runnable r) { r.run(); }
            public void shutdown() { }
            public List<Runnable> shutdownNow() { return List.of(); }
            public boolean isShutdown() { return false; }
            public boolean isTerminated() { return false; }
            public boolean awaitTermination(long t, TimeUnit u) { return false; }
        };
    }

    public static void main(String[] args) throws Exception {
        List<Case> cases = List.of(
            new Case("AsynchronousSocketChannel.open()", () -> {
                AsynchronousSocketChannel c = AsynchronousSocketChannel.open();
                c.close();
                return "opened";
            }),
            new Case("AsynchronousServerSocketChannel.open()", () -> {
                AsynchronousServerSocketChannel c = AsynchronousServerSocketChannel.open();
                c.close();
                return "opened";
            }),
            new Case("AsynchronousChannelProvider.provider()", () -> {
                return AsynchronousChannelProvider.provider();
            }),
            new Case("provider().openAsynchronousSocketChannel(null)", () -> {
                AsynchronousSocketChannel c =
                        AsynchronousChannelProvider.provider().openAsynchronousSocketChannel(null);
                c.close();
                return "opened";
            }),
            new Case("AsynchronousChannelGroup.withThreadPool(same-thread executor)", () -> {
                AsynchronousChannelGroup g = AsynchronousChannelGroup.withThreadPool(sameThreadExecutor());
                g.shutdownNow();
                return "created";
            }),
            new Case("group built on a same-thread executor, then group.provider() used", () -> {
                AsynchronousChannelGroup g = AsynchronousChannelGroup.withThreadPool(sameThreadExecutor());
                AsynchronousSocketChannel c = g.provider().openAsynchronousSocketChannel(null);
                c.close();
                g.shutdownNow();
                return "opened";
            }));

        Policy.setPolicy(new ProviderPolicy());
        System.setSecurityManager(new SecurityManager());

        granted = false;
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

        granted = true;
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
