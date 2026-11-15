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
 * @summary Code whose protection domain is not granted
 *          RuntimePermission("createVirtualThread") cannot start a virtual
 *          thread by any public route: Thread.startVirtualThread, the
 *          Thread.ofVirtual() builder (start, unstarted, factory) and the two
 *          per-task executors.  The call must be refused, with an
 *          AccessControlException naming createVirtualThread, and the task
 *          handed to it must not run.  A virtual thread runs concurrently
 *          with its creator, so any unchecked route gives downloaded code the
 *          second thread it needs to count in a loop and read the count as a
 *          clock, whatever System.nanoTime returns.  The check is
 *          unconditional; it does not depend on clock coarsening.  Run under
 *          -Djava.security.manager=default with a policy written by
 *          polpAudit.  Defends SECURITY_MODEL.md section 11.1 (Virtual
 *          threads: RuntimePermission("createVirtualThread")) and section
 *          11.7 ("Coarsening and the thread gates work as a pair").
 * @author Claude Fable 5.2 (claude-fable-5-2) and Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @library /test/lib
 * @run main/othervm VirtualThreadCreationPermissionTest
 */

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

/**
 * The program under test is {@link Child}.  It is trusted code: it asks
 * {@link Untrusted} to start a probe by each route.  The two classes are put
 * on the child's class path as two directories, so each has its own code
 * source and its own grant in the policy.
 *
 * Steps, each child in its own JVM:
 * <ol>
 * <li><b>Audit.</b> The program runs under polpAudit with an empty policy,
 *     which writes the policy the program needs.  Paths are written as
 *     properties (polpAudit.path.properties), which is the only widening
 *     applied.</li>
 * <li><b>Strip.</b> Every line naming "createVirtualThread" is removed from
 *     the untrusted code source's grant, and from nowhere else.  The rest of
 *     that grant is kept, so the untrusted class still loads and runs and a
 *     denial can only be the one under test.</li>
 * <li><b>Denied replay.</b> The program under
 *     {@code -Djava.security.manager=default} with the stripped policy.
 *     Every route must throw, the exception or one of its causes must be an
 *     AccessControlException naming createVirtualThread, and the probe must
 *     not run.  This is the invariant.</li>
 * <li><b>Control.</b> Only when the audit recorded the permission for the
 *     untrusted code source: the same replay with the policy as written.
 *     Every route must now run the probe on a virtual thread.  The denied
 *     replay and the control differ by that one permission on that one code
 *     source, so the control shows what the denied replay's result depends
 *     on, and that the routes work at all.</li>
 * </ol>
 *
 * If the audit records no createVirtualThread check against the untrusted
 * code source, there is nothing to strip.  That means a virtual thread can
 * be started without the check, and the test fails saying so; the denied
 * replay is still run so the report shows which routes ran.
 *
 * The denied replay is a bounded observation: after a refusal the child
 * waits 500 ms for the probe, and when a route is not refused it waits 5 s
 * so the report can say whether the task ran.  It does not prove a task
 * would never run later.
 *
 * The child avoids lambdas, method references and string concatenation, as
 * SecurityPolicyWriterStartupReadsTest does, so that the program audited
 * and replayed makes no use of invokedynamic bootstrap.  It also uses no
 * member of this outer class at run time (the constants it names are
 * compile-time constants), so the child JVM, whose class path holds only
 * the two directories, never needs the test library.  No clock coarsening
 * or common-pool option is passed to the child, because the check under
 * test is unconditional.
 *
 * Not covered: a ThreadFactory obtained from Thread.ofVirtual().factory()
 * by code that held the permission and then handed to code that does not
 * (SECURITY_MODEL.md section 11.4 places the check at factory(), not at
 * newThread()); a virtual thread started by trusted code that then runs a
 * task supplied by untrusted code; StructuredTaskScope, whose API status in
 * this tree was not checked when the test was written.
 *
 * <h2>History (AI_POLICY.md 5.3)</h2>
 * This file was rewritten on 2026-11-15.  The first version installed a
 * plain SecurityManager at run time through -Djava.security.manager=allow
 * and flipped a flag in a Policy subclass between a denied and a granted
 * phase in one JVM.  The Project Lead said on 2026-11-15 that allow is not
 * used in this project, and -Djava.security.manager=default installs
 * CombinerSecurityManager, which caches decisions, so that design could not
 * be carried over; that is why the test was rewritten.  Three results were
 * observed for the first version and are kept as history only; they are
 * not controls for this version:
 * <ul>
 * <li>stock OpenJDK 21.0.12, no thread checks at all: all six denied-phase
 *     checks failed, none denied and each task running on a virtual thread,
 *     6 of 12;</li>
 * <li>DirtyChai build 27-internal-adhoc.peter.DirtyChai, jtreg 8.2.1, run by
 *     the Project Lead 2026-11-15 10:57 AEST, before
 *     Thread.startVirtualThread made any check: 11 of 12, failing only on
 *     Thread.startVirtualThread(Runnable), which was not denied and whose
 *     task ran on a virtual thread;</li>
 * <li>the same build configuration at 12:56 AEST, after the Project Lead
 *     added the createVirtualThread check to Thread.startVirtualThread:
 *     12 of 12.</li>
 * </ul>
 * The authors did not run either DirtyChai result; both are recorded from
 * the jtreg reports the Project Lead supplied.
 *
 * <h2>Status of this version</h2>
 * <ol>
 * <li>PASS, OBSERVED by the Project Lead, 2026-11-15 16:53 AEST, jtreg 8.2.1,
 *     DirtyChai build 27-internal-adhoc.peter.DirtyChai
 *     (windows-x86_64-server-release), a tree in which
 *     Thread.startVirtualThread checks createVirtualThread.  The audit wrote
 *     this grant for the untrusted code source: LoadClassPermission "ALLOW",
 *     a FilePermission to read its directory, RuntimePermission
 *     "createVirtualThread" and RuntimePermission "modifyThread"; one line
 *     was stripped.  Denied replay, 6 of 6: every route threw
 *     AccessControlException naming createVirtualThread and no probe
 *     ran.</li>
 * <li>Control, OBSERVED in the same run: with the policy as written, so the
 *     untrusted code source holds the permission, all six routes ran the
 *     probe on a virtual thread, 6 of 6.  The denied replay and the control
 *     differ only by the one stripped line, so the denial is shown to
 *     depend on that permission for that code source.</li>
 * </ol>
 *
 * The authors did not run these; they are recorded from the jtreg report
 * the Project Lead supplied.
 *
 * PASS again, OBSERVED by the Project Lead's tierAI run, result file stamped 2026-11-15
 * 18:28 AEST (27 of 27), on an image the Project Lead said was rebuilt
 * after the submission checks were limited to the common pool:
 * audit 6 of 6, denied 6 of 6, granted 6 of 6.
 *
 * STILL OWED: a failure on a tree where one route lacks the check (for
 * example Thread.startVirtualThread without it), expected to show that
 * route as "NOT denied" in the denied replay.  The control above removes
 * the permission's effect through the policy, not a check from the code, so
 * this version has not yet been seen to fail when a check is absent.  The
 * first version was seen to fail on such a tree (see the history above),
 * but that is not this code.
 *
 * The authors' own checks were limited to: compiling against JDK 21 with
 * stand-ins for the two test-library classes; checking with javap that the
 * child's classes contain no invokedynamic and no reference to a member of
 * this outer class; and running {@link Child} on stock JDK 21 without a
 * security manager, three times in each mode, with the classes split into
 * two directories as the driver splits them.  There "audit" and "granted"
 * printed 6 of 6 ALL and exited 0, and "denied" reported all six routes as
 * NOT denied with the task having run on a virtual thread, and exited
 * non-zero.  The driver, polpAudit, the policy strip and the refusal path
 * were not exercised by the authors.
 */
public class VirtualThreadCreationPermissionTest {

    static final String PREFIX = "VirtualThreadCreationPermissionTest";
    static final String UNTRUSTED_PREFIX = "VirtualThreadCreationPermissionTest$Untrusted";
    static final String CHILD = "VirtualThreadCreationPermissionTest$Child";

    static final String TRUSTED_URL_PROPERTY = "ai.test.vthread.trusted.url";
    static final String TRUSTED_PATH_PROPERTY = "ai.test.vthread.trusted.path";
    static final String UNTRUSTED_URL_PROPERTY = "ai.test.vthread.untrusted.url";
    static final String UNTRUSTED_PATH_PROPERTY = "ai.test.vthread.untrusted.path";

    static final String PERMISSION_NAME = "createVirtualThread";
    static final String WRITER_THREAD = "SecurityPolicyWriter policy creation thread";

    /** Records that it ran, and on which thread. */
    public static class Probe implements Runnable {
        final CountDownLatch ran = new CountDownLatch(1);
        volatile Thread thread;

        @Override
        public void run() {
            thread = Thread.currentThread();
            ran.countDown();
        }
    }

    /**
     * The code that is not granted the permission.  It is copied to its own
     * class path directory, so it has its own code source.  Every attempt to
     * start a virtual thread in the denied replay is made from here.
     */
    public static class Untrusted {
        public static void start(int route, Runnable probe) {
            switch (route) {
                case 0:
                    Thread.startVirtualThread(probe);
                    break;
                case 1:
                    Thread.ofVirtual().start(probe);
                    break;
                case 2:
                    Thread.ofVirtual().unstarted(probe).start();
                    break;
                case 3:
                    Thread.ofVirtual().factory().newThread(probe).start();
                    break;
                case 4: {
                    ExecutorService e = Executors.newVirtualThreadPerTaskExecutor();
                    try {
                        e.execute(probe);
                    } finally {
                        e.shutdown();
                    }
                    break;
                }
                case 5: {
                    ExecutorService e = Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory());
                    try {
                        e.execute(probe);
                    } finally {
                        e.shutdown();
                    }
                    break;
                }
                default:
                    throw new IllegalArgumentException(String.valueOf(route));
            }
        }
    }

    /** The audited and replayed program.  Its argument is audit, denied or granted. */
    @SuppressWarnings("removal")
    public static class Child {

        static final String[] ROUTES = {
            "Thread.startVirtualThread(Runnable)",
            "Thread.ofVirtual().start(Runnable)",
            "Thread.ofVirtual().unstarted(Runnable), then start()",
            "Thread.ofVirtual().factory().newThread(Runnable), then start()",
            "Executors.newVirtualThreadPerTaskExecutor().execute(Runnable)",
            "Executors.newThreadPerTaskExecutor(Thread.ofVirtual().factory()).execute(Runnable)",
        };

        public static void main(String[] args) throws Exception {
            String mode = args[0];
            boolean audit = "audit".equals(mode);
            boolean denied = "denied".equals(mode);
            boolean granted = "granted".equals(mode);
            if (!audit && !denied && !granted) {
                throw new IllegalArgumentException(mode);
            }
            List<String> failures = new ArrayList<>();

            String trusted = String.valueOf(
                    Child.class.getProtectionDomain().getCodeSource().getLocation());
            String untrusted = String.valueOf(
                    Untrusted.class.getProtectionDomain().getCodeSource().getLocation());
            System.out.println(cat("CHILD codesources trusted=", trusted, " untrusted=", untrusted,
                    " distinct=", !trusted.equals(untrusted)));

            for (int route = 0; route < ROUTES.length; route++) {
                String name = ROUTES[route];
                Probe probe = new Probe();
                Throwable thrown = null;
                try {
                    Untrusted.start(route, probe);
                } catch (Throwable t) {
                    thrown = t;
                }
                long waitMillis;
                if (denied) {
                    // A denial must also mean the task never runs.  When the
                    // call was not denied, wait longer so the report can say
                    // whether it ran.
                    waitMillis = thrown != null ? 500 : 5000;
                } else if (granted) {
                    waitMillis = 10000;
                } else {
                    waitMillis = 5000;
                }
                boolean ran = probe.ran.await(waitMillis, TimeUnit.MILLISECONDS);
                Thread thread = probe.thread;
                boolean virtual = thread != null && thread.isVirtual();

                String outcome;
                if (thrown == null) {
                    outcome = ran ? (virtual ? "not-refused-ran-on-virtual-thread"
                                             : "not-refused-ran-on-platform-thread")
                                  : "not-refused-did-not-run";
                } else if (isRefusal(thrown)) {
                    outcome = ran ? "refused-but-ran" : "refused-did-not-run";
                } else {
                    outcome = ran ? "other-exception-and-ran" : "other-exception-did-not-run";
                }
                System.out.println(cat("CHILD route ", route, " [", name, "] outcome=", outcome,
                        " ran=", ran, " thread=", thread, " virtual=", virtual,
                        " thrown=", thrown));

                if (denied) {
                    if (thrown == null) {
                        failures.add(cat("NOT denied: ", name, ran
                                ? cat(" (the task ran on ", thread, ")")
                                : " (the task did not run)"));
                    } else {
                        if (!isRefusal(thrown)) {
                            failures.add(cat("wrong exception for ", name, ": ", thrown));
                        }
                        if (ran) {
                            failures.add(cat("an exception was thrown but the task still ran on ",
                                    thread, ": ", name));
                        }
                    }
                } else if (granted) {
                    if (thrown != null) {
                        failures.add(cat("should succeed: ", name, ": ", thrown));
                    } else if (!ran) {
                        failures.add(cat("the task did not run: ", name));
                    } else if (!virtual) {
                        failures.add(cat("the task did not run on a virtual thread (", thread, "): ",
                                name));
                    }
                }
            }

            for (String f : failures) {
                System.out.println(cat("CHILD FAIL: ", f));
            }
            System.out.println(cat("CHILD ", mode, ": ", ROUTES.length - failures.size(), " of ",
                    ROUTES.length, failures.isEmpty() ? " ALL" : " NOT-ALL"));
            if (!audit && !failures.isEmpty()) {
                throw new RuntimeException(cat(failures.size(), " failure(s) in mode ", mode));
            }
        }

        /** Joins the parts as text, without string concatenation. */
        static String cat(Object... parts) {
            StringBuilder sb = new StringBuilder();
            for (Object part : parts) {
                sb.append(part);
            }
            return sb.toString();
        }

        /** True if t, or a cause of t, is a denial of the permission under test. */
        static boolean isRefusal(Throwable t) {
            for (Throwable c = t; c != null; c = c.getCause()) {
                if (c instanceof java.security.AccessControlException) {
                    java.security.Permission p =
                            ((java.security.AccessControlException) c).getPermission();
                    if (p != null && PERMISSION_NAME.equals(p.getName())) {
                        return true;
                    }
                }
                if (c.getCause() == c) {
                    break;
                }
            }
            return false;
        }
    }

    public static void main(String[] args) throws Exception {
        List<String> failures = new ArrayList<>();

        // Two class path directories, so two code sources.
        File classes = new File(System.getProperty("test.classes")).getCanonicalFile();
        File trustedDir = new File("vt-trusted").getCanonicalFile();
        File untrustedDir = new File("vt-untrusted").getCanonicalFile();
        Files.createDirectories(trustedDir.toPath());
        Files.createDirectories(untrustedDir.toPath());
        int trustedCount = 0;
        int untrustedCount = 0;
        File[] files = classes.listFiles();
        if (files == null) {
            throw new RuntimeException(cat("cannot list ", classes));
        }
        for (File f : files) {
            String name = f.getName();
            if (!name.startsWith(PREFIX) || !name.endsWith(".class")) {
                continue;
            }
            boolean untrusted = name.startsWith(UNTRUSTED_PREFIX);
            File target = new File(untrusted ? untrustedDir : trustedDir, name);
            Files.copy(f.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
            if (untrusted) {
                untrustedCount++;
            } else {
                trustedCount++;
            }
        }
        System.out.println(cat("copied ", trustedCount, " trusted and ", untrustedCount,
                " untrusted class files"));
        if (trustedCount == 0 || untrustedCount == 0) {
            throw new RuntimeException("the class files were not found in test.classes");
        }

        String trustedUrl = stripSlash(trustedDir.toURI().toString());
        String untrustedUrl = stripSlash(untrustedDir.toURI().toString());
        String trustedPath = trustedDir.getPath();
        String untrustedPath = untrustedDir.getPath();
        String classPath = cat(trustedPath, File.pathSeparator, untrustedPath);

        Path paths = Path.of("virtual-thread-paths.properties").toAbsolutePath();
        Files.writeString(paths,
                cat(TRUSTED_URL_PROPERTY, "=", trustedUrl, "\n",
                    TRUSTED_PATH_PROPERTY, "=", trustedPath.replace('\\', '/'), "\n",
                    UNTRUSTED_URL_PROPERTY, "=", untrustedUrl, "\n",
                    UNTRUSTED_PATH_PROPERTY, "=", untrustedPath.replace('\\', '/'), "\n"),
                StandardCharsets.ISO_8859_1);

        String[] locations = {
            cat("-D", TRUSTED_URL_PROPERTY, "=", trustedUrl),
            cat("-D", TRUSTED_PATH_PROPERTY, "=", trustedPath),
            cat("-D", UNTRUSTED_URL_PROPERTY, "=", untrustedUrl),
            cat("-D", UNTRUSTED_PATH_PROPERTY, "=", untrustedPath),
        };

        // 1. Audit.
        Path policy = Path.of("virtual-thread.policy").toAbsolutePath();
        Files.deleteIfExists(policy);
        Files.createFile(policy);
        OutputAnalyzer audit = run(classPath, locations,
                "-Djava.security.manager=polpAudit",
                cat("-Djava.security.policy==", policy),
                cat("-DpolpAudit.path.properties=", paths),
                "audit");
        if (audit.getExitValue() != 0) {
            failures.add(cat("audit child exited with ", audit.getExitValue()));
        }
        String auditErr = audit.getStderr();
        int writerTrace = auditErr.indexOf(cat("Exception in thread \"", WRITER_THREAD, "\""));
        if (writerTrace >= 0) {
            failures.add(cat("the policy writer threw at shutdown:\n", auditErr.substring(writerTrace)));
        }
        if (!audit.getStdout().contains("distinct=true")) {
            failures.add("precondition: the trusted and untrusted classes do not have distinct"
                    + " code sources in the child, so the test cannot tell them apart");
        }

        // 2. Strip the permission from the untrusted code source's grant only.
        String written = Files.readString(policy, StandardCharsets.UTF_8);
        StringBuilder kept = new StringBuilder();
        StringBuilder untrustedGrant = new StringBuilder();
        boolean inUntrusted = false;
        boolean sawUntrusted = false;
        int removed = 0;
        for (String line : written.split("\\R", -1)) {
            if (line.startsWith("grant")) {
                inUntrusted = line.contains(UNTRUSTED_URL_PROPERTY) || line.contains(untrustedUrl);
                if (inUntrusted) {
                    sawUntrusted = true;
                }
            }
            if (inUntrusted) {
                untrustedGrant.append(line).append('\n');
                if (line.contains(cat("\"", PERMISSION_NAME, "\""))) {
                    removed++;
                    continue;
                }
            }
            kept.append(line).append('\n');
        }
        System.out.println(cat("----- the untrusted code source's grant as written -----\n",
                untrustedGrant, "----- end; lines naming ", PERMISSION_NAME, " removed: ", removed,
                " -----"));
        Path stripped = Path.of("virtual-thread-stripped.policy").toAbsolutePath();
        Files.writeString(stripped, kept.toString(), StandardCharsets.UTF_8);

        if (!sawUntrusted) {
            failures.add(cat("the written policy has no grant for the untrusted code source, so",
                    " the replay cannot load it; full policy:\n", written));
        } else {
            // 3. Denied replay.
            OutputAnalyzer denied = run(classPath, locations,
                    "-Djava.security.manager=default",
                    cat("-Djava.security.policy==", stripped),
                    null,
                    "denied");
            boolean deniedPassed = denied.getExitValue() == 0
                    && denied.getStdout().contains("CHILD denied: ")
                    && denied.getStdout().contains(" ALL");
            if (removed == 0) {
                failures.add(cat("the audit recorded no ", PERMISSION_NAME, " check against the",
                        " untrusted code source: a virtual thread can be started without the",
                        " check"));
            }
            if (!deniedPassed) {
                failures.add(cat("denied replay failed (exit ", denied.getExitValue(), "); ",
                        describe(denied)));
            }

            // 4. Control.
            if (removed > 0) {
                OutputAnalyzer control = run(classPath, locations,
                        "-Djava.security.manager=default",
                        cat("-Djava.security.policy==", policy),
                        null,
                        "granted");
                boolean controlPassed = control.getExitValue() == 0
                        && control.getStdout().contains("CHILD granted: ")
                        && control.getStdout().contains(" ALL");
                if (!controlPassed) {
                    failures.add(cat("control: with the permission left in the untrusted grant the",
                            " routes did not all run on a virtual thread (exit ",
                            control.getExitValue(), "), so the denied replay does not show",
                            " the permission is what stops them; ",
                            describe(control)));
                }
            }
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException(cat("virtual thread creation: ", failures.size(),
                    " failure(s):\n- ", String.join("\n- ", failures)));
        }
        System.out.println("PASSED: without the permission every route was refused and none ran,"
                + " and with it every route ran on a virtual thread");
    }

    /** The child's own failure lines, or its first access denial, for the message. */
    private static String describe(OutputAnalyzer out) {
        StringBuilder sb = new StringBuilder();
        for (String line : out.getStdout().split("\\R")) {
            if (line.startsWith("CHILD FAIL: ")) {
                sb.append("\n    ").append(line);
            }
        }
        if (sb.length() > 0) {
            return sb.toString();
        }
        for (String line : out.getStderr().split("\\R")) {
            if (line.contains("access denied")) {
                return cat("first denial: ", line.trim());
            }
        }
        return cat("no failure line or access denial was printed:\n", out.getStderr());
    }

    private static String stripSlash(String s) {
        while (s.length() > 1 && (s.endsWith("/") || s.endsWith("\\"))) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static OutputAnalyzer run(String classPath, String[] locations, String manager,
                                      String policy, String pathProperties, String mode)
            throws Exception {
        List<String> command = new ArrayList<>();
        // Placed after the class path the test library adds; the last one given is used.
        command.add("-cp");
        command.add(classPath);
        command.add(manager);
        command.add(policy);
        if (pathProperties != null) {
            command.add(pathProperties);
        }
        for (String location : locations) {
            command.add(location);
        }
        command.add(CHILD);
        command.add(mode);
        ProcessBuilder pb = ProcessTools.createTestJavaProcessBuilder(command.toArray(new String[0]));
        OutputAnalyzer out = new OutputAnalyzer(pb.start());
        System.out.println(cat("----- child: ", String.join(" ", command),
                " (exit ", out.getExitValue(), ")"));
        System.out.println(out.getStdout());
        System.err.println(out.getStderr());
        return out;
    }

    /** Joins the parts as text, without string concatenation. */
    static String cat(Object... parts) {
        StringBuilder sb = new StringBuilder();
        for (Object part : parts) {
            sb.append(part);
        }
        return sb.toString();
    }
}
