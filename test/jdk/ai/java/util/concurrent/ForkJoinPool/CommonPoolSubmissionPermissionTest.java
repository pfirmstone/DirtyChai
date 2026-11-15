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
 * @summary With clock coarsening active (au.zeus.jdk.nanoTime.granularity
 *          set), code whose protection domain is not granted
 *          RuntimePermission("createInnocuousThread") cannot get its task
 *          executed on a ForkJoinPool common-pool worker thread, by any of:
 *          commonPool().execute and submit, ForkJoinTask.fork from a
 *          non-pool thread, the CompletableFuture async methods, and a
 *          parallel stream.  This must hold when common-pool workers already
 *          exist because code that does hold the permission used the pool
 *          earlier.  A task that runs on a worker runs concurrently with its
 *          submitter, so it can count in a loop and be read as a clock.
 *          Run under -Djava.security.manager=default with a policy written
 *          by polpAudit.  Defends SECURITY_MODEL.md section 11.1 ("Code that
 *          depends on those paths (parallel streams, CompletableFuture async
 *          methods, Cleaner.create()) needs this grant") and section 11.7
 *          ("Coarsening and the thread gates work as a pair").
 * @author Claude Fable 5.2 (claude-fable-5-2) and Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @library /test/lib
 * @run main/othervm CommonPoolSubmissionPermissionTest
 */

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ForkJoinTask;
import java.util.concurrent.TimeUnit;
import java.util.function.IntConsumer;
import java.util.function.Supplier;
import java.util.stream.IntStream;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

/**
 * The program under test is {@link Child}.  It is trusted code: it warms the
 * common pool, so both workers exist and are idle, and then asks
 * {@link Untrusted} to submit a probe by each route.  The two classes are
 * put on the child's class path as two directories, so each has its own
 * code source and its own grant in the policy.
 *
 * Steps, each child in its own JVM, all with clock coarsening on:
 * <ol>
 * <li><b>Audit.</b> The program runs under polpAudit with an empty policy,
 *     which writes the policy the program needs.  Paths are written as
 *     properties (polpAudit.path.properties), which is the only widening
 *     applied.</li>
 * <li><b>Strip.</b> Every line naming "createInnocuousThread" is removed from
 *     the untrusted code source's grant, and from nowhere else.  The rest of
 *     that grant is kept, so the untrusted class still loads and runs and a
 *     denial can only be the one under test.</li>
 * <li><b>Denied replay.</b> The program under
 *     {@code -Djava.security.manager=default} with the stripped policy.
 *     Each route must either be refused, with an AccessControlException
 *     naming createInnocuousThread, or accept the probe and never run it on
 *     another thread.  This is the invariant.  A refusal counts whether it
 *     is thrown or arrives as the exceptional completion of the
 *     CompletableFuture the route returned, and each route's line says
 *     which of these happened (outcome= and refusalSeen=).</li>
 * <li><b>Control.</b> Only when the audit recorded the permission for the
 *     untrusted code source: the same replay with the policy as written.
 *     Each route must now run the probe on another thread.  The denied
 *     replay and the control differ by that one permission on that one code
 *     source, so the control shows what the denied replay's result depends
 *     on, and that the routes work at all.</li>
 * </ol>
 *
 * If the audit records no createInnocuousThread check against the untrusted
 * code source, there is nothing to strip.  That means submission is not
 * checked, and the test fails saying so; the denied replay is still run so
 * the report shows which routes ran.
 *
 * The denied replay is a bounded observation: a probe that has not run on
 * another thread within {@link Child#QUIET_MILLIS} is taken not to run.
 * With an idle worker already parked, an unchecked submission is picked up
 * in well under that time.  It does not prove a task would never run later.
 *
 * The child avoids lambdas and string concatenation, as
 * SecurityPolicyWriterStartupReadsTest does, so that the program audited
 * and replayed makes no use of invokedynamic bootstrap.  It also uses no
 * member of this outer class at run time (the constants it names are
 * compile-time constants), so the child JVM, whose class path holds only
 * the two directories, never needs the test library.
 *
 * Not covered: SubmissionPublisher, the scheduling methods of ForkJoinPool
 * and the other users of the common pool not listed above;
 * Arrays.parallelSort and ForkJoinPool.invoke, where the submitting thread
 * may do all the work itself so the control cannot be asserted reliably; a
 * pool or executor created by trusted code and handed to untrusted code;
 * the finalizer thread; a JVM without clock coarsening, where by design
 * (as discussed with the Project Lead on 2026-11-15) submission is not
 * checked.
 *
 * The invariant does not depend on how it is enforced.  It holds if
 * submission is checked.  It also holds if a JVM that hosts downloaded code
 * never has a live common-pool worker, but this test does not exercise that
 * arrangement: its warm-up deliberately creates workers.  If the project
 * settles on the second arrangement, this test should be replaced by one
 * that asserts it, not kept.
 *
 * <h2>History and negative controls (AI_POLICY.md 5.3)</h2>
 * This file was rewritten on 2026-11-15.  The first version installed a
 * plain SecurityManager at run time through -Djava.security.manager=allow
 * and flipped a flag in a Policy subclass between a denied and a granted
 * phase in one JVM.  The Project Lead pointed out that allow is not used in
 * this project, and -Djava.security.manager=default installs
 * CombinerSecurityManager, which caches decisions, so that design could not
 * be carried over.  Two results were observed for the first version and are
 * kept as history only; they are not controls for this version:
 * <ul>
 * <li>stock OpenJDK 21.0.12, no thread checks at all: all seven
 *     denied-phase checks failed, 7 of 14;</li>
 * <li>DirtyChai build 27-internal-adhoc.peter.DirtyChai, jtreg 8.2.1, run by
 *     the Project Lead at 10:57 AEST, before any submission check existed:
 *     all seven denied-phase checks failed, each probe running on a
 *     common-pool worker, 7 of 14.</li>
 * </ul>
 *
 * <h2>Observed for this version, revision before the future was inspected</h2>
 * <ol>
 * <li>PASS, OBSERVED by the Project Lead, 2026-11-15 16:16 AEST, jtreg 8.2.1,
 *     DirtyChai build 27-internal-adhoc.peter.DirtyChai
 *     (windows-x86_64-server-release), a tree in which the Project Lead had
 *     added a check of createInnocuousThread on submission to the common
 *     pool when clock coarsening is on.  The audit wrote this grant for the
 *     untrusted code source: LoadClassPermission "ALLOW", a FilePermission
 *     to read its directory, and RuntimePermission "createInnocuousThread";
 *     one line was stripped.  Denied replay, 7 of 7: six routes threw
 *     AccessControlException naming createInnocuousThread, and
 *     completedFuture(null).thenRunAsync threw nothing and did not run its
 *     probe on another thread.  (By reading CompletableFuture, that method
 *     catches a failure of execute and completes the returned future with
 *     it; that revision did not inspect the future.)</li>
 * <li>Control, OBSERVED in the same run: with the policy as written, so the
 *     untrusted code source holds the permission, all seven routes ran the
 *     probe on ForkJoinPool.commonPool-worker-1, 7 of 7.  The denied replay
 *     and the control differ only by the one stripped line, so the denial
 *     is shown to depend on that permission for that code source.</li>
 * </ol>
 *
 * The pass and the control above were observed for the revision BEFORE the
 * returned future was inspected.  This revision inspects it: Untrusted
 * returns what each route produced, and if a route returns without throwing
 * a CompletableFuture that is completed exceptionally, that exception is
 * treated exactly like a thrown one.  This is so that a refusal which
 * CompletableFuture reports through the future is seen and checked to name
 * the permission, instead of passing only because the probe did not run.
 * THIS REVISION: PASS, OBSERVED by the Project Lead's tierAI run, result file stamped 2026-11-15
 * 18:28 AEST (27 of 27), on an image the Project Lead said was rebuilt
 * after the submission checks were limited to the common pool:
 * audit 7 of 7, denied 7 of 7, granted 7 of 7.  Six routes were refused by
 * a thrown AccessControlException; completedFuture(null).thenRunAsync was
 * refused through the future (refusalSeen=future).
 *
 * The author did not run any DirtyChai result; they are recorded from the
 * jtreg report the Project Lead supplied.  For this revision the authors'
 * own checks were limited to: compiling against JDK 21 with stand-ins for
 * the two test-library classes; checking with javap that the child's
 * classes contain no invokedynamic and no reference to a member of this
 * outer class; and running {@link Child} on stock JDK 21 without a security
 * manager, three times in each mode, with the classes split into two
 * directories as the driver splits them.  There "audit" and "granted"
 * printed 7 of 7 ALL and exited 0, and "denied" reported all seven routes
 * as having run on another thread and exited non-zero.  The driver,
 * polpAudit, the policy strip and the refusal path, including a refusal
 * through the returned future, were not exercised.
 *
 * STILL OWED for this version: the result on a tree with no submission
 * check, expected to be the failure "the audit recorded no
 * createInnocuousThread check against the untrusted code source".  The
 * control above removes the permission's effect through the policy, not the
 * check from the code, so the test has not yet been seen to fail when the
 * check itself is absent.  The first version was seen to fail on such a
 * tree (see the history above), but that is not this code.
 */
public class CommonPoolSubmissionPermissionTest {

    static final String PREFIX = "CommonPoolSubmissionPermissionTest";
    static final String UNTRUSTED_PREFIX = "CommonPoolSubmissionPermissionTest$Untrusted";
    static final String CHILD = "CommonPoolSubmissionPermissionTest$Child";

    static final String TRUSTED_URL_PROPERTY = "ai.test.commonpool.trusted.url";
    static final String TRUSTED_PATH_PROPERTY = "ai.test.commonpool.trusted.path";
    static final String UNTRUSTED_URL_PROPERTY = "ai.test.commonpool.untrusted.url";
    static final String UNTRUSTED_PATH_PROPERTY = "ai.test.commonpool.untrusted.path";

    static final String PERMISSION_NAME = "createInnocuousThread";
    static final String GRANULARITY = "-Dau.zeus.jdk.nanoTime.granularity=1024";
    static final String PARALLELISM = "-Djava.util.concurrent.ForkJoinPool.common.parallelism=2";
    static final String WRITER_THREAD = "SecurityPolicyWriter policy creation thread";

    /** Records whether it ran on a thread other than the one that created it. */
    public static class Probe implements Runnable {
        final Thread submitter = Thread.currentThread();
        final CountDownLatch offThread = new CountDownLatch(1);
        final long pauseMillis;
        volatile boolean armed = true;
        volatile String where;

        Probe(long pauseMillis) {
            this.pauseMillis = pauseMillis;
        }

        @Override
        public void run() {
            Thread t = Thread.currentThread();
            if (armed && t != submitter) {
                where = t.getName();
                offThread.countDown();
            }
            if (pauseMillis > 0) {
                try {
                    Thread.sleep(pauseMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    /**
     * The code that is not granted the permission.  It is copied to its own
     * class path directory, so it has its own code source.  Every submission
     * to the common pool in the denied replay is made from here.
     */
    public static class Untrusted {
        /** Returns what the route produced: a future or task, or null if it produces none. */
        public static Object submit(int route, final Runnable probe) {
            switch (route) {
                case 0:
                    ForkJoinPool.commonPool().execute(probe);
                    return null;
                case 1:
                    return ForkJoinPool.commonPool().submit(probe);
                case 2:
                    return ForkJoinTask.adapt(probe).fork();
                case 3:
                    return CompletableFuture.runAsync(probe);
                case 4:
                    return CompletableFuture.supplyAsync(new Supplier<Object>() {
                        @Override
                        public Object get() {
                            probe.run();
                            return null;
                        }
                    });
                case 5:
                    return CompletableFuture.completedFuture(null).thenRunAsync(probe);
                case 6:
                    IntStream.range(0, 256).parallel().forEach(new IntConsumer() {
                        @Override
                        public void accept(int i) {
                            probe.run();
                        }
                    });
                    return null;
                default:
                    throw new IllegalArgumentException(String.valueOf(route));
            }
        }
    }

    /** The audited and replayed program.  Its argument is audit, denied or granted. */
    @SuppressWarnings("removal")
    public static class Child {

        /** How long the denied replay watches for a probe to run on another thread. */
        static final long QUIET_MILLIS = 1500;

        static final String[] ROUTES = {
            "ForkJoinPool.commonPool().execute(Runnable)",
            "ForkJoinPool.commonPool().submit(Runnable)",
            "ForkJoinTask.adapt(Runnable).fork() from a non-pool thread",
            "CompletableFuture.runAsync(Runnable)",
            "CompletableFuture.supplyAsync(Supplier)",
            "CompletableFuture.completedFuture(null).thenRunAsync(Runnable)",
            "IntStream.range(0, 256).parallel().forEach",
        };

        /** Slept inside the probe, for the route that calls it many times. */
        static final long[] PAUSE_MILLIS = {0, 0, 0, 0, 0, 0, 2};

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

            // Warm-up by trusted code: both workers exist and are then idle.
            final CountDownLatch bothRunning = new CountDownLatch(2);
            final CountDownLatch release = new CountDownLatch(1);
            for (int i = 0; i < 2; i++) {
                ForkJoinPool.commonPool().execute(new Runnable() {
                    @Override
                    public void run() {
                        bothRunning.countDown();
                        try {
                            release.await(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                });
            }
            boolean warmed = bothRunning.await(10, TimeUnit.SECONDS);
            release.countDown();
            if (!warmed) {
                throw new RuntimeException("precondition: two common-pool workers did not start");
            }
            ForkJoinPool.commonPool().awaitQuiescence(10, TimeUnit.SECONDS);
            System.out.println(cat("CHILD warmed poolSize=", ForkJoinPool.commonPool().getPoolSize()));

            for (int route = 0; route < ROUTES.length; route++) {
                String name = ROUTES[route];
                if (ForkJoinPool.commonPool().getPoolSize() == 0) {
                    failures.add(cat("precondition lost, no live common-pool worker before: ", name));
                    continue;
                }
                boolean ran = false;
                Throwable failure = null;
                String via = "none";
                String where = null;
                // A parallel stream may, rarely, be completed by the submitting
                // thread alone, so the granted mode allows three attempts.
                int attempts = granted ? 3 : 1;
                for (int attempt = 0; attempt < attempts && !ran && failure == null; attempt++) {
                    Probe probe = new Probe(PAUSE_MILLIS[route]);
                    Object result = null;
                    try {
                        result = Untrusted.submit(route, probe);
                    } catch (Throwable t) {
                        failure = t;
                        via = "thrown";
                    }
                    ran = probe.offThread.await(denied ? QUIET_MILLIS : 5000, TimeUnit.MILLISECONDS);
                    where = probe.where;
                    probe.armed = false;
                    // CompletableFuture catches a failure of execute in some
                    // methods and completes the returned future with it, so a
                    // refusal can arrive there instead of being thrown.
                    if (failure == null && result instanceof CompletableFuture) {
                        failure = exceptionOf((CompletableFuture<?>) result);
                        if (failure != null) {
                            via = "future";
                        }
                    }
                }
                String outcome;
                if (failure == null) {
                    outcome = ran ? "ran-on-another-thread"
                                  : "accepted-never-ran-on-another-thread";
                } else if (isRefusal(failure)) {
                    outcome = cat("refused-", via, ran ? "-but-ran" : "");
                } else {
                    outcome = cat("other-exception-", via, ran ? "-and-ran" : "");
                }
                System.out.println(cat("CHILD route ", route, " [", name, "] outcome=", outcome,
                        " refusalSeen=", via, " ranOnAnotherThread=", ran, " where=", where,
                        " exception=", failure));
                if (denied) {
                    if (failure != null && !isRefusal(failure)) {
                        failures.add(cat("wrong exception (", via, ") for ", name, ": ", failure));
                    }
                    if (ran) {
                        failures.add(cat("the task ran on ", where, " without ", PERMISSION_NAME,
                                ": ", name));
                    }
                } else if (granted) {
                    if (failure != null) {
                        failures.add(cat("should succeed (", via, "): ", name, ": ", failure));
                    } else if (!ran) {
                        failures.add(cat("the task never ran on another thread: ", name));
                    }
                }
            }

            for (String f : failures) {
                System.out.println(cat("CHILD FAIL: ", f));
            }
            System.out.println(cat("CHILD ", mode, ": ", ROUTES.length - failures.size(), " of ",
                    ROUTES.length, failures.isEmpty() ? " ALL" : " NOT-ALL"));
            if (!audit && !failures.isEmpty()) {
                throw new RuntimeException(cat(failures.size(), " route(s) failed in mode ", mode));
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

        /**
         * The exception a future was completed with, or null if it is not
         * completed exceptionally.  Waits at most 200 ms, and never joins or
         * uses the async pool, so a refused submission cannot stall it.
         */
        static Throwable exceptionOf(CompletableFuture<?> f) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(200);
            while (!f.isDone() && System.nanoTime() - deadline < 0) {
                Thread.sleep(10);
            }
            if (!f.isCompletedExceptionally()) {
                return null;
            }
            try {
                f.getNow(null);
            } catch (CompletionException | CancellationException e) {
                return e;
            }
            return null;
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
        File trustedDir = new File("cp-trusted").getCanonicalFile();
        File untrustedDir = new File("cp-untrusted").getCanonicalFile();
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

        Path paths = Path.of("common-pool-paths.properties").toAbsolutePath();
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
        Path policy = Path.of("common-pool.policy").toAbsolutePath();
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
        Path stripped = Path.of("common-pool-stripped.policy").toAbsolutePath();
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
                        " untrusted code source: a submission to the common pool is not checked",
                        " with clock coarsening on"));
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
                            " routes did not all run (exit ", control.getExitValue(), "), so the",
                            " denied replay does not show the permission is what stops them; ",
                            describe(control)));
                }
            }
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException(cat("common pool submission: ", failures.size(),
                    " failure(s):\n- ", String.join("\n- ", failures)));
        }
        System.out.println("PASSED: without the permission no route reached a common-pool worker,"
                + " and with it every route did");
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
        command.add(GRANULARITY);
        command.add(PARALLELISM);
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
