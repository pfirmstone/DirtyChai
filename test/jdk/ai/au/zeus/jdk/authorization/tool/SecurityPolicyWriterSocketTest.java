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
 * @summary polpAudit (SecurityPolicyWriter) must write a complete, parseable,
 *          portable policy.  Starting from an empty policy file, a child JVM
 *          under -Djava.security.manager=polpAudit uses loopback sockets,
 *          creates, writes, reads and deletes a temporary file, and reads
 *          properties whose names contain a double quote and a backslash.  At
 *          exit the writer must record every permission without throwing,
 *          close every grant, substitute the configured URL and path
 *          properties (the longest value first, so a codeBase URL is never
 *          rewritten through its own path), name temporary files through
 *          ${java.io.tmpdir}, and escape names so the policy parser reads them
 *          back unchanged.  A second child under the standard SecurityManager
 *          with only the written policy must then be allowed the same file and
 *          property operations.  Observed in jgdms-benchmarks: each audited
 *          JVM stopped writing immediately after
 *          {@code permission java.net.SocketPermission "} (a
 *          NullPointerException from an unguarded hostname replacement),
 *          leaving the policy unparseable.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @library /test/lib
 * @run main/othervm SecurityPolicyWriterSocketTest
 */

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

/**
 * Steps, each child in its own JVM:
 * <ol>
 * <li><b>Audit.</b> {@link Child} runs under polpAudit with an empty policy
 *     file and a {@code polpAudit.path.properties} file naming the test
 *     classes directory both as a URL ({@value #URL_PROPERTY}) and as a path
 *     ({@value #PATH_PROPERTY}).  The writer runs from a shutdown hook, so an
 *     exception it throws is only visible on that thread's stderr, which this
 *     test captures.</li>
 * <li><b>Structure.</b> One {@code "};"} per {@code grant}; every
 *     {@code permission} line a complete statement; no {@code // not recorded}
 *     lines; a complete loopback SocketPermission.</li>
 * <li><b>Substitution.</b>
 *     <ul>
 *     <li>The test classes' grant is {@code codeBase "${URL_PROPERTY}..."},
 *         and no codeBase contains {@code ${PATH_PROPERTY}}: the path is a
 *         substring of the URL, so substituting it first would produce
 *         {@code file:/${PATH_PROPERTY}}, which expands to an invalid URL.</li>
 *     <li>A FilePermission names the classes directory as
 *         {@code ${PATH_PROPERTY}...}.</li>
 *     <li>The temporary file's FilePermissions are
 *         {@code ${java.io.tmpdir}${/}-}, never the literal directory.</li>
 *     </ul></li>
 * <li><b>Replay.</b> A child under the standard SecurityManager with only the
 *     written policy, and the two properties defined, repeats the file and
 *     property operations.  A policy with a syntax error is ignored entirely,
 *     and a name that was not escaped is read back as a different name, so
 *     either makes this step fail.  The socket operations are replayed too,
 *     on fresh ephemeral ports, which only the widened loopback grants allow.</li>
 * <li><b>Loopback ports.</b> Connect and accept to a loopback ephemeral port
 *     are written once each as the range {@value #DEFAULT_RANGE}, never as the
 *     exact port; {@code localhost:0} (listen on any ephemeral port) is kept.</li>
 * <li><b>Malformed range.</b> A second audit with
 *     {@code -DpolpAudit.ephemeralPorts=49152} (no range) must still start,
 *     write, and use the default range: a bad setting must neither stop the
 *     SecurityManager from installing nor narrow the grant to one port.</li>
 * </ol>
 *
 * <p>OBSERVED (2026-10-16, before the escaping and substitution changes):
 * the socket-only version of this test passed outside JMH; the truncation in
 * jgdms-benchmarks came from a JDK build without the hostname guard.
 * OBSERVED for the extended checks (2026-10-18, writer with escape() but the
 * old name handling still in place): fails on the awkward PropertyPermission,
 * written double-escaped as {@code q\\\"uote\\back}, and on the temporary
 * directory, written as the literal escaped path followed by
 * {@code ${${/}}-}.
 * After the name handling was corrected (2026-10-18): passes, including the
 * replay under the standard SecurityManager.
 * Loopback range, socket replay and malformed-range checks (2026-10-18, with
 * socketName writing the parsed bounds): pass; the malformed setting falls
 * back to {@code 32768-65535} and the replay is granted fresh ephemeral ports.
 */
public class SecurityPolicyWriterSocketTest {

    static final String MARKER_PROPERTY = "ai.test.policywriter.marker";
    /** A property name the policy file can only carry correctly if escaped. */
    static final String AWKWARD_PROPERTY = "ai.test.policywriter.q\"uote\\back";
    static final String URL_PROPERTY = "ai.test.policywriter.classes.url";
    static final String PATH_PROPERTY = "ai.test.policywriter.classes.path";
    static final String WRITER_THREAD = "SecurityPolicyWriter policy creation thread";
    static final String DEFAULT_RANGE = "32768-65535";
    /** Loopback host forms a SocketPermission name can carry (textual; no DNS). */
    static final String LOOPBACK = "(?:localhost|127(?:\\.\\d+){3}|\\[::1\\]|\\[0:0:0:0:0:0:0:1\\])";

    /** The audited workload; replay mode repeats it under the written policy. */
    public static class Child {
        public static void main(String[] args) throws IOException {
            boolean replay = args.length > 0 && args[0].equals("replay");
            String marker = System.getProperty(MARKER_PROPERTY);       // PropertyPermission read
            System.getProperty(AWKWARD_PROPERTY);                       // needs escaping in the policy

            Path tmp = Files.createTempFile("ai-policywriter", ".tmp"); // FilePermission under tmpdir
            Files.writeString(tmp, "x");
            String back = Files.readString(tmp);
            Files.delete(tmp);

            InetAddress lo = InetAddress.getLoopbackAddress();
            try (ServerSocket server = new ServerSocket(0, 1, lo);          // listen on localhost:0
                 Socket client = new Socket(lo, server.getLocalPort());    // connect to an ephemeral port
                 Socket accepted = server.accept()) {                      // accept from an ephemeral port
                System.out.println("CHILD socket port=" + server.getLocalPort());
            }
            System.out.println("CHILD done replay=" + replay + " marker=" + marker + " tmp=" + back);
        }
    }

    public static void main(String[] args) throws Exception {
        Path policy = Path.of("audit.policy").toAbsolutePath();
        Files.deleteIfExists(policy);
        Files.createFile(policy);                                   // audit from nothing

        // The directory the child's classes load from, as the class loader names it.
        File classes = new File(System.getProperty("test.classes")).getCanonicalFile();
        String classesUrl = stripSlash(classes.toURI().toString());          // file:/C:/.../x.d
        String classesPath = classes.getPath();                               // native separators
        Path paths = Path.of("audit-paths.properties").toAbsolutePath();
        // Forward slashes: a backslash is an escape character in a .properties file.
        Files.writeString(paths,
                URL_PROPERTY + "=" + classesUrl + "\n"
                + PATH_PROPERTY + "=" + classesPath.replace('\\', '/') + "\n",
                StandardCharsets.ISO_8859_1);

        // 1. Audit.
        OutputAnalyzer audit = run(
                "-Djava.security.manager=polpAudit",
                "-Djava.security.policy==" + policy,
                "-DpolpAudit.path.properties=" + paths,
                "-D" + MARKER_PROPERTY + "=present",
                Child.class.getName());
        List<String> failures = new ArrayList<>();
        if (audit.getExitValue() != 0) {
            failures.add("audit child exited with " + audit.getExitValue());
        }
        String err = audit.getStderr();
        int writerTrace = err.indexOf("Exception in thread \"" + WRITER_THREAD + "\"");
        if (writerTrace >= 0) {
            failures.add("the policy writer threw at shutdown:\n" + err.substring(writerTrace));
        }

        // 2. Structure.
        String written = Files.readString(policy, StandardCharsets.UTF_8);
        System.out.println("----- written policy -----\n" + written + "\n----- end -----");
        int grants = count(written, "(?m)^grant\\b");
        int closes = count(written, "(?m)^\\};\\s*$");
        if (grants == 0) failures.add("no grant was written");
        if (grants != closes) {
            failures.add(grants + " grant(s) but " + closes + " closing \"};\": a grant is unterminated");
        }
        String quoted = "\"(?:[^\"\\\\]|\\\\.)*\"";            // "..." with escapes
        Pattern complete = Pattern.compile(
                "^\\s*permission\\s+[\\w.$]+\\s+" + quoted + "(?:\\s*,\\s*" + quoted + ")?\\s*;\\s*$");
        for (String line : written.split("\\R")) {
            String t = line.trim();
            if (t.startsWith("permission") && !complete.matcher(line).matches()) {
                failures.add("incomplete permission statement: " + line);
            }
            if (t.startsWith("// not recorded") || t.startsWith("// grant not recorded")) {
                failures.add("the writer could not record: " + t);
            }
        }
        if (!find(written, "(?m)^\\s*permission\\s+java\\.net\\.SocketPermission\\s+\"[^\"]+\"\\s*,\\s*\"[^\"]+\"\\s*;")) {
            failures.add("no complete java.net.SocketPermission statement was written");
        }
        // The awkward property must appear escaped, exactly once per backslash and quote.
        String awkwardEscaped = AWKWARD_PROPERTY.replace("\\", "\\\\").replace("\"", "\\\"");
        if (!written.contains("java.util.PropertyPermission \"" + awkwardEscaped + "\"")) {
            failures.add("PropertyPermission " + AWKWARD_PROPERTY + " not written as \"" + awkwardEscaped + "\"");
        }

        checkLoopbackPorts(written, DEFAULT_RANGE, "default range", failures);

        // 3. Substitution.
        String urlRef = "${" + URL_PROPERTY + "}";
        String pathRef = "${" + PATH_PROPERTY + "}";
        if (!find(written, "(?mi)^grant\\s+codebase\\s+\"" + Pattern.quote(urlRef))) {
            failures.add("the test classes' codeBase was not written as \"" + urlRef + "...\"");
        }
        if (find(written, "(?mi)^grant\\s+codebase\\s+\"[^\"]*" + Pattern.quote(pathRef))) {
            failures.add("a codeBase was rewritten through the path property " + pathRef
                    + " (values must be replaced longest first)");
        }
        if (!find(written, "(?m)java\\.io\\.FilePermission\\s+\"" + Pattern.quote(pathRef))) {
            failures.add("no FilePermission names the classes directory as \"" + pathRef + "...\"");
        }
        String tmpRef = "java.io.FilePermission \"${java.io.tmpdir}${/}-\"";
        if (!written.contains(tmpRef)) {
            failures.add("the temporary file's FilePermission was not written as " + tmpRef);
        }
        String tmpDir = stripSlash(System.getProperty("java.io.tmpdir"));
        // Raw, forward-slashed, separator-substituted, and escaped (backslashes doubled) forms.
        for (String form : new String[] {tmpDir, tmpDir.replace('\\', '/'), tmpDir.replace("\\", "${/}"),
                                         tmpDir.replace("/", "${/}"), tmpDir.replace("\\", "\\\\")}) {
            if (form.length() > 3 && written.contains("FilePermission \"" + form)) {
                failures.add("a FilePermission names the literal temporary directory " + form);
                break;
            }
        }

        // 4. Replay (only meaningful if the file was written completely).
        if (failures.isEmpty()) {
            OutputAnalyzer replay = run(
                    "-Djava.security.manager=default",
                    "-Djava.security.policy==" + policy,
                    "-D" + URL_PROPERTY + "=" + classesUrl,
                    "-D" + PATH_PROPERTY + "=" + classesPath,
                    "-D" + MARKER_PROPERTY + "=present",
                    Child.class.getName(), "replay");
            if (replay.getExitValue() != 0 || !replay.getStdout().contains("marker=present")) {
                failures.add("replay under the written policy failed (exit " + replay.getExitValue()
                        + "); the policy may not parse, a name was read back differently,"
                        + " or the loopback port range does not cover the new ephemeral ports:\n"
                        + replay.getStderr());
            }
        }

        // 5. Malformed range: must fall back to the default, not fail or narrow.
        Path policy2 = Path.of("audit-malformed.policy").toAbsolutePath();
        Files.deleteIfExists(policy2);
        Files.createFile(policy2);
        OutputAnalyzer audit2 = run(
                "-Djava.security.manager=polpAudit",
                "-Djava.security.policy==" + policy2,
                "-DpolpAudit.path.properties=" + paths,
                "-DpolpAudit.ephemeralPorts=49152",
                "-D" + MARKER_PROPERTY + "=present",
                Child.class.getName());
        if (audit2.getExitValue() != 0) {
            failures.add("with -DpolpAudit.ephemeralPorts=49152 the audit child exited with "
                    + audit2.getExitValue() + " (a bad setting must not stop polpAudit):\n" + audit2.getStderr());
        } else {
            String err2 = audit2.getStderr();
            int trace2 = err2.indexOf("Exception in thread \"" + WRITER_THREAD + "\"");
            if (trace2 >= 0) failures.add("malformed range: the policy writer threw:\n" + err2.substring(trace2));
            String written2 = Files.readString(policy2, StandardCharsets.UTF_8);
            System.out.println("----- written policy (malformed range) -----\n" + written2 + "\n----- end -----");
            checkLoopbackPorts(written2, DEFAULT_RANGE, "malformed polpAudit.ephemeralPorts=49152", failures);
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException("SecurityPolicyWriter: " + failures.size() + " failure(s):\n- "
                    + String.join("\n- ", failures));
        }
        System.out.println("PASSED: complete, portable policy written and parsed");
    }

    /**
     * Connect and accept to a loopback ephemeral port written once each as
     * {@code range}; listen on {@code localhost:0} kept; no exact loopback
     * port other than 0 recorded.
     */
    private static void checkLoopbackPorts(String written, String range, String label, List<String> failures) {
        String sp = "(?m)^\\s*permission\\s+java\\.net\\.SocketPermission\\s+\"";
        for (String action : new String[] {"connect,resolve", "accept,resolve"}) {
            int n = count(written, sp + LOOPBACK + ":" + Pattern.quote(range) + "\"\\s*,\\s*\""
                    + Pattern.quote(action) + "\"\\s*;");
            if (n != 1) {
                failures.add(label + ": expected one loopback SocketPermission \":" + range + "\", \""
                        + action + "\", found " + n);
            }
        }
        if (!find(written, sp + "localhost:0\"\\s*,\\s*\"listen,resolve\"")) {
            failures.add(label + ": SocketPermission \"localhost:0\", \"listen,resolve\" was not kept");
        }
        Matcher exact = Pattern.compile(sp + "(" + LOOPBACK + ":(\\d+))\"").matcher(written);
        while (exact.find()) {
            if (!exact.group(2).equals("0")) {
                failures.add(label + ": exact loopback port recorded: " + exact.group(1));
            }
        }
    }

    private static String stripSlash(String s) {
        while (s.length() > 1 && (s.endsWith("/") || s.endsWith("\\"))) s = s.substring(0, s.length() - 1);
        return s;
    }

    private static OutputAnalyzer run(String... command) throws Exception {
        ProcessBuilder pb = ProcessTools.createTestJavaProcessBuilder(command);
        OutputAnalyzer out = new OutputAnalyzer(pb.start());
        System.out.println("----- child: " + String.join(" ", command) + " (exit " + out.getExitValue() + ")");
        System.out.println(out.getStdout());
        System.err.println(out.getStderr());
        return out;
    }

    private static boolean find(String s, String regex) {
        return Pattern.compile(regex).matcher(s).find();
    }

    private static int count(String s, String regex) {
        Matcher m = Pattern.compile(regex).matcher(s);
        int n = 0;
        while (m.find()) n++;
        return n;
    }
}
