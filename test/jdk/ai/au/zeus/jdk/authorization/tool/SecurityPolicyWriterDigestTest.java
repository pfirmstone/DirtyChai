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
 * @summary polpAudit (SecurityPolicyWriter) must record a jar's permissions
 *          under a content-addressed grant.  A class loaded from a jar is
 *          defined in a ProtectionDomain whose CodeSource SecureClassLoader
 *          promotes to a DigestCodeSource; the read of the jar itself is
 *          checked before promotion, from a domain without the digest.  The
 *          writer must keep the two apart: a codeBase-only grant holding the
 *          pre-promotion read, and a codeBase plus {@code digest "SHA-256:..."}
 *          grant holding the jar's other permissions.  Replayed under the
 *          standard SecurityManager, the same jar must be granted those
 *          permissions, and a different jar at the same location must not.
 *          Defends the principle that locations are not trusted: a grant
 *          made for code is bound to its content.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @library /test/lib
 * @build DigestLib
 * @run main/othervm SecurityPolicyWriterDigestTest
 */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jdk.test.lib.process.OutputAnalyzer;
import jdk.test.lib.process.ProcessTools;

/**
 * Steps:
 * <ol>
 * <li><b>Build.</b> {@code digest-lib.jar} is written containing
 *     {@link DigestLib}.</li>
 * <li><b>Audit.</b> {@link Child}, under polpAudit with an empty policy,
 *     loads {@code DigestLib} from the jar through a URLClassLoader whose
 *     parent is the platform loader (so the copy on the test class path is not
 *     used) and calls it.  {@code polpAudit.path.properties} names the jar
 *     and the test classes directory as URL and path properties.</li>
 * <li><b>Grants.</b> The written policy must contain, for
 *     {@code ${JAR_URL}}:
 *     <ul>
 *     <li>a grant with {@code digest "SHA-256:<hex>"}, where {@code <hex>} is
 *         the SHA-256 of the jar file, holding the PropertyPermission for
 *         {@link DigestLib#PROPERTY};</li>
 *     <li>a codeBase-only grant (no digest) holding the FilePermission read
 *         of {@code ${JAR_PATH}}, and not the PropertyPermission: if the
 *         property were granted by location alone, the digest would bind
 *         nothing.</li>
 *     </ul></li>
 * <li><b>Replay, same jar.</b> Under the standard SecurityManager with only
 *     the written policy, the child must load the class and read the
 *     property.</li>
 * <li><b>Replay, different jar.</b> The jar is rebuilt at the same path with an
 *     extra entry, so its digest differs.  The child must not be granted the
 *     property: either the class fails to load (a check held in the digest
 *     grant, such as LoadClassPermission, is denied) or the read is denied.</li>
 * </ol>
 *
 * <p>OBSERVED (2026-10-18, writer keyed on CodeSourceKey): passes.  The
 * audit writes a codeBase-only grant with the jar's read and a codeBase plus
 * digest grant (whole-file SHA-256) with LoadClassPermission and the property;
 * the changed jar is refused at class loading, with LoadClassPermission
 * "ALLOW" denied.  Negative control: with the digest left out
 * of the writer's domain key (the behaviour before CodeSourceKey was shared),
 * step 3 is expected to fail with no digest grant written.
 */
public class SecurityPolicyWriterDigestTest {

    static final String JAR_URL = "ai.test.digest.jar.url";
    static final String JAR_PATH = "ai.test.digest.jar.path";
    static final String CLASSES_URL = "ai.test.digest.classes.url";
    static final String CLASSES_PATH = "ai.test.digest.classes.path";
    static final String WRITER_THREAD = "SecurityPolicyWriter policy creation thread";

    /** Loads DigestLib from the jar given as args[0] and reports what it was allowed. */
    public static class Child {
        public static void main(String[] args) throws Exception {
            URL jar = new File(args[0]).toURI().toURL();
            try (URLClassLoader loader = new URLClassLoader(new URL[] {jar}, ClassLoader.getPlatformClassLoader())) {
                Class<?> lib;
                try {
                    lib = Class.forName("DigestLib", true, loader);
                } catch (SecurityException | ClassNotFoundException e) {
                    System.out.println("CHILD DENIED load: " + e);
                    return;
                }
                if (lib.getClassLoader() != loader) {
                    System.out.println("CHILD WRONG LOADER: " + lib.getClassLoader());
                    return;
                }
                System.out.println("CHILD codeSource=" + lib.getProtectionDomain().getCodeSource().getClass().getName());
                try {
                    Object v = lib.getMethod("run").invoke(null);
                    System.out.println("CHILD GRANTED value=" + v);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    Throwable c = e.getCause();
                    if (c instanceof SecurityException) {
                        System.out.println("CHILD DENIED read: " + c);
                    } else {
                        throw e;
                    }
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        List<String> failures = new ArrayList<>();
        File classes = new File(System.getProperty("test.classes")).getCanonicalFile();
        String classesUrl = stripSlash(classes.toURI().toString());
        String classesPath = classes.getPath();

        // 1. Build.
        File jarFile = new File("digest-lib.jar").getCanonicalFile();
        byte[] libClass = Files.readAllBytes(classes.toPath().resolve("DigestLib.class"));
        writeJar(jarFile, libClass, false);
        String jarUrl = jarFile.toURI().toString();                 // file:/C:/.../digest-lib.jar
        String jarPath = jarFile.getPath();
        String jarDigest = sha256(jarFile);

        Path paths = Path.of("audit-paths.properties").toAbsolutePath();
        Files.writeString(paths,
                JAR_URL + "=" + jarUrl + "\n"
                + JAR_PATH + "=" + jarPath.replace('\\', '/') + "\n"
                + CLASSES_URL + "=" + classesUrl + "\n"
                + CLASSES_PATH + "=" + classesPath.replace('\\', '/') + "\n",
                StandardCharsets.ISO_8859_1);
        Path policy = Path.of("digest-audit.policy").toAbsolutePath();
        Files.deleteIfExists(policy);
        Files.createFile(policy);

        // 2. Audit.
        OutputAnalyzer audit = run(
                "-Djava.security.manager=polpAudit",
                "-Djava.security.policy==" + policy,
                "-DpolpAudit.path.properties=" + paths,
                "-D" + "ai.test.digest.lib.marker" + "=present",
                Child.class.getName(), jarPath);
        if (audit.getExitValue() != 0) failures.add("audit child exited with " + audit.getExitValue());
        int trace = audit.getStderr().indexOf("Exception in thread \"" + WRITER_THREAD + "\"");
        if (trace >= 0) failures.add("the policy writer threw at shutdown:\n" + audit.getStderr().substring(trace));
        if (!audit.getStdout().contains("CHILD GRANTED value=present")) {
            failures.add("under polpAudit the child did not load and run DigestLib from the jar:\n" + audit.getStdout());
        }
        if (!audit.getStdout().contains("codeSource=java.security.DigestCodeSource")) {
            failures.add("DigestLib's CodeSource was not promoted to a DigestCodeSource:\n" + audit.getStdout());
        }

        // 3. Grants.
        String written = Files.readString(policy, StandardCharsets.UTF_8);
        System.out.println("----- written policy -----\n" + written + "\n----- end -----");
        String jarRef = Pattern.quote("${" + JAR_URL + "}");
        String digestGrant = grantBody(written,
                "codebase\\s+\"" + jarRef + "\"\\s*,\\s*digest\\s+\"SHA-256:" + jarDigest + "\"");
        String plainGrant = grantBody(written, "codebase\\s+\"" + jarRef + "\"\\s*(?!,)");
        String propLine = "java.util.PropertyPermission \"" + DigestLib.PROPERTY + "\", \"read\"";
        if (digestGrant == null) {
            Matcher any = Pattern.compile("(?i)digest\\s+\"([^\"]*)\"").matcher(written);
            failures.add("no grant for ${" + JAR_URL + "} with digest \"SHA-256:" + jarDigest + "\""
                    + (any.find() ? " (a digest clause was written: \"" + any.group(1) + "\")" : " (no digest clause at all)"));
        } else if (!digestGrant.contains(propLine)) {
            failures.add("the digest grant does not hold " + propLine);
        }
        if (plainGrant == null) {
            failures.add("no codeBase-only grant for ${" + JAR_URL + "} (the pre-promotion read of the jar)");
        } else {
            if (!plainGrant.contains("java.io.FilePermission \"${" + JAR_PATH + "}\", \"read\"")) {
                failures.add("the codeBase-only grant does not hold FilePermission \"${" + JAR_PATH + "}\", \"read\"");
            }
            if (plainGrant.contains(propLine)) {
                failures.add("the codeBase-only grant holds " + propLine
                        + ": granted by location alone, so the digest binds nothing");
            }
        }

        String[] replayOpts = {
                "-Djava.security.manager=default",
                "-Djava.security.policy==" + policy,
                "-D" + JAR_URL + "=" + jarUrl,
                "-D" + JAR_PATH + "=" + jarPath,
                "-D" + CLASSES_URL + "=" + classesUrl,
                "-D" + CLASSES_PATH + "=" + classesPath,
                "-D" + DigestLib.PROPERTY + "=present",
                Child.class.getName(), jarPath};

        if (failures.isEmpty()) {
            // 4. Replay, same jar.
            OutputAnalyzer same = run(replayOpts);
            if (!same.getStdout().contains("CHILD GRANTED value=present")) {
                failures.add("replay with the audited jar was not granted the property (exit "
                        + same.getExitValue() + "):\n" + same.getStdout() + same.getStderr());
            }

            // 5. Replay, different jar at the same location.
            writeJar(jarFile, libClass, true);
            String changed = sha256(jarFile);
            if (changed.equals(jarDigest)) throw new IllegalStateException("rebuilt jar has the same digest");
            OutputAnalyzer other = run(replayOpts);
            if (other.getStdout().contains("CHILD GRANTED")) {
                failures.add("a different jar (SHA-256:" + changed + ") at the same location was granted the"
                        + " property: the grant is bound to the location, not the content:\n" + other.getStdout());
            } else if (!other.getStdout().contains("CHILD DENIED")) {
                failures.add("replay with the changed jar ended without a result (exit "
                        + other.getExitValue() + "):\n" + other.getStdout() + other.getStderr());
            }
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException("SecurityPolicyWriter digest grants: " + failures.size()
                    + " failure(s):\n- " + String.join("\n- ", failures));
        }
        System.out.println("PASSED: digest-bound grant written; same jar granted, changed jar refused");
    }

    /** The body (between "{" and "};") of the first grant whose header matches headerRegex. */
    private static String grantBody(String policy, String headerRegex) {
        Matcher m = Pattern.compile("(?ims)^grant\\s+" + headerRegex + "[^{]*\\{(.*?)^\\};").matcher(policy);
        return m.find() ? m.group(1) : null;
    }

    private static void writeJar(File jar, byte[] libClass, boolean extra) throws IOException {
        Manifest mf = new Manifest();
        mf.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        try (OutputStream os = Files.newOutputStream(jar.toPath());
             JarOutputStream jos = new JarOutputStream(os, mf)) {
            jos.putNextEntry(new JarEntry("DigestLib.class"));
            jos.write(libClass);
            jos.closeEntry();
            if (extra) {
                jos.putNextEntry(new JarEntry("extra.txt"));
                jos.write("different content".getBytes(StandardCharsets.UTF_8));
                jos.closeEntry();
            }
        }
    }

    private static String sha256(File f) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(f.toPath())));
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
}
