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
 * @summary The limiting domain doPrivileged adds for a caller loaded from a
 *          digest-identified code source is a plain CodeSource, never a
 *          DigestCodeSource, so no code-source based digest grant implies
 *          it, and it keeps the caller's location with the class name
 *          appended to its policy URI.  A dynamic grant made to the
 *          caller's own class loader and verified digest (DigestDomainGrant,
 *          which is how proxies are authorised) does cover the limiting
 *          domain, through the caller's domain the limiting domain records;
 *          it covers only that loader's classes, so another loader that
 *          loaded the same jar gets nothing from it, and an unverified
 *          digest gets nothing at all.
 *          Defends SECURITY_MODEL.md section 15 invariant 8, "A DigestGrant
 *          never implies a domain whose CodeSource is a plain CodeSource",
 *          section 4 guarantee 7, "Content-hash code source integrity",
 *          and section 8.1, "Dynamic grants to proxies".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules java.base/au.zeus.jdk.authorization.policy
 * @run main/othervm -Djava.security.manager=allow LimitedDoPrivilegedDigestSourceTest
 */

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.function.IntPredicate;
import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * The caller is defined under a ProtectionDomain whose code source is a
 * DigestCodeSource.  The test asks the real grant classes whether they imply
 * the limiting domain that doPrivileged built for it, rather than asserting
 * through a model of policy.
 *
 * Two code sources are used.  The first is unverified: its digest was
 * supplied, not computed, so a DigestDomainGrant must never imply it.  The
 * second is verified: its digest was computed from a temporary file, so
 * DigestDomainGrant can match it, and it is used for two loaders to show
 * that a dynamic grant covers one loader's classes only.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: return the caller's own DigestCodeSource as the limiting domain's code
 *     source.
 *     OBSERVED: six checks FAIL - "limiting domain is a plain CodeSource, not
 *     a digest source", "policy URI names the caller's host and jar", "policy
 *     URI ends with the class name", "a hand-written exact grant, without a
 *     default port, implies the limiting domain", "a grant for the bare
 *     location does not imply the limiting domain" and "dynamic grant covers
 *     the limiting domain of its loader's classes".</li>
 * <li>M2: make DigestDomainGrant.implies(ProtectionDomain) test the limiting
 *     domain itself instead of the domain it records as its caller.
 *     OBSERVED: one check FAILS - "dynamic grant covers the limiting domain of
 *     its loader's classes".</li>
 * <li>M3: make DigestDomainGrant ignore the class loader when it matches the
 *     caller's domain.
 *     OBSERVED: two checks FAIL - "dynamic grant does not cover another
 *     loader's classes from the same jar" and "dynamic grant does not cover
 *     another loader's own domain".</li>
 * <li>M4: make DigestDomainGrant accept an unverified digest.
 *     OBSERVED: two checks FAIL - "dynamic grant does not cover an unverified
 *     digest" and its own-domain counterpart.</li>
 * <li>M5: drop the class name from the policy URI, or build it from a different
 *     location than the caller's.
 *     not run on its own; the M1 run exercises the same checks.</li>
 * </ol>
 */
@SuppressWarnings("removal")
public class LimitedDoPrivilegedDigestSourceTest {

    public static final Permission SECRET =
            new RuntimePermission("LimitedDoPrivilegedDigestSourceTest.secret");

    private static final String JAR = "http://example.invalid/limited/proxy.jar";
    private static final String JAR_EXACT =
            "http://example.invalid/limited/proxy.jar/LimitedDoPrivilegedDigestSourceTest";
    private static final String JAR_RECURSIVE = "http://example.invalid/limited/proxy.jar/-";
    private static final String JAR_OTHER_CLASS =
            "http://example.invalid/limited/proxy.jar/SomeOtherClass";
    private static final byte[] DIGEST = new byte[32];

    static volatile DomainIdentity lastLimiter;

    static final class RecordingPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (SECRET.equals(permission) && domain instanceof DomainIdentity) {
                lastLimiter = (DomainIdentity) domain;
            }
            return true;
        }
    }

    /** Calls doPrivileged from a class defined under a digest domain. */
    public static final class Caller implements IntPredicate {
        @Override
        public boolean test(int unused) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                AccessController.checkPermission(SECRET);
                return null;
            });
            return true;
        }
    }

    /**
     * Defines Caller itself under a ProtectionDomain that is set after the
     * loader exists, because the domain names the loader.
     */
    static final class PdLoader extends ClassLoader {
        private final String name;
        volatile ProtectionDomain pd;

        PdLoader(String name) {
            super(LimitedDoPrivilegedDigestSourceTest.class.getClassLoader());
            this.name = name;
        }

        @Override
        protected Class<?> loadClass(String className, boolean resolve)
                throws ClassNotFoundException {
            if (!className.equals(name)) {
                return super.loadClass(className, resolve);
            }
            synchronized (getClassLoadingLock(className)) {
                Class<?> c = findLoadedClass(className);
                if (c == null) {
                    String resource = className.replace('.', '/') + ".class";
                    try (InputStream in = getParent().getResourceAsStream(resource)) {
                        byte[] bytes = in.readAllBytes();
                        c = defineClass(className, bytes, 0, bytes.length, pd);
                    } catch (IOException ex) {
                        throw new ClassNotFoundException(className, ex);
                    }
                }
                return c;
            }
        }
    }

    /** A caller defined under a domain, and the limiting domain it produced. */
    static final class Loaded {
        final Class<?> type;
        final ProtectionDomain domain;
        final DomainIdentity limiter;

        Loaded(Class<?> type, ProtectionDomain domain, DomainIdentity limiter) {
            this.type = type;
            this.domain = domain;
            this.limiter = limiter;
        }
    }

    private static int failures;

    public static void main(String[] args) throws Exception {
        Policy.setPolicy(new RecordingPolicy());
        System.setSecurityManager(new SecurityManager());

        staticGrants();
        dynamicGrants();

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    /** Grants matched by code source: none may imply the limiting domain by digest. */
    private static void staticGrants() throws Exception {
        DigestCodeSource callerSource =
                new DigestCodeSource(JAR, (Certificate[]) null, "SHA-256", DIGEST.clone());
        Loaded loaded = load(callerSource);

        DomainIdentity limiter = loaded.limiter;
        check("limiting domain was observed", limiter != null);
        if (limiter == null || limiter.getCodeSource() == null) {
            check("limiting domain has a code source", false);
            return;
        }
        CodeSource limiterSource = limiter.getCodeSource();
        String uri = String.valueOf(limiterSource.getUriLocation());

        check("limiting domain is a plain CodeSource, not a digest source",
                !(limiterSource instanceof DigestCodeSource));
        // The policy URI may spell the default port out (http://host:80/...),
        // so the location is checked by what it names, and by a grant written
        // without the port, which is how a person would write one.
        check(new StringBuilder("policy URI names the caller's host and jar [")
                .append(uri).append(']').toString(),
                uri.contains("example.invalid") && uri.contains("/limited/proxy.jar/"));
        check("policy URI ends with the class name",
                uri.endsWith("/LimitedDoPrivilegedDigestSourceTest"));
        check("keeps the caller's original location URL",
                callerSource.getLocation().toString()
                        .equals(limiterSource.getLocation().toString()));
        check("records the caller's domain", limiter.getCallerDomain() == loaded.domain);

        Principal[] noPrincipals = new Principal[0];
        PermissionGrant digestGrant = PermissionGrantBuilder.newBuilder()
                .uri(JAR).digest("SHA-256", DIGEST.clone())
                .permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.DIGEST).build();
        check("a digest grant does not imply the limiting domain",
                !digestGrant.implies(limiterSource, noPrincipals));
        check("a digest grant does not imply the limiting domain as a domain",
                !digestGrant.implies(limiter));

        PermissionGrant exact = PermissionGrantBuilder.newBuilder()
                .uri(uri).permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.URI).build();
        check("a grant for the exact per-class URI implies the limiting domain",
                exact.implies(limiterSource, noPrincipals));

        PermissionGrant handWritten = PermissionGrantBuilder.newBuilder()
                .uri(JAR_EXACT).permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.URI).build();
        check("a hand-written exact grant, without a default port, implies the limiting domain",
                handWritten.implies(limiterSource, noPrincipals));

        PermissionGrant recursive = PermissionGrantBuilder.newBuilder()
                .uri(JAR_RECURSIVE).permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.URI).build();
        check("a recursive grant on the caller's location implies the limiting domain",
                recursive.implies(limiterSource, noPrincipals));

        PermissionGrant jarOnly = PermissionGrantBuilder.newBuilder()
                .uri(JAR).permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.URI).build();
        check("a grant for the bare location does not imply the limiting domain",
                !jarOnly.implies(limiterSource, noPrincipals));

        PermissionGrant otherClass = PermissionGrantBuilder.newBuilder()
                .uri(JAR_OTHER_CLASS).permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.URI).build();
        check("a grant for another class does not imply the limiting domain",
                !otherClass.implies(limiterSource, noPrincipals));
    }

    /** Dynamic grants to a loader and verified digest, as proxies receive. */
    private static void dynamicGrants() throws Exception {
        Path jar = Files.createTempFile("limited-digest", ".jar");
        jar.toFile().deleteOnExit();
        Files.write(jar, new byte[] {1, 2, 3, 4, 5, 6, 7, 8});
        Certificate[] noCerts = null;
        DigestCodeSource verified = new DigestCodeSource(
                new CodeSource(jar.toUri().toURL(), noCerts), "SHA-256");
        check("the computed digest is verified", !verified.unverified());

        Loaded a = load(verified);
        Loaded b = load(verified);
        check("two loaders defined distinct classes", a.type != b.type);
        if (a.limiter == null || b.limiter == null) {
            check("limiting domains were observed", false);
            return;
        }

        PermissionGrant forA = dynamicGrant(a.type, verified);
        check("dynamic grant is well formed: covers its caller's own domain",
                forA.implies(a.domain));
        check("dynamic grant covers the limiting domain of its loader's classes",
                forA.implies(a.limiter));
        check("dynamic grant does not cover another loader's classes from the same jar",
                !forA.implies(b.limiter));
        check("dynamic grant does not cover another loader's own domain",
                !forA.implies(b.domain));

        // An unverified digest is never covered, even by a grant naming it.
        DigestCodeSource unverified =
                new DigestCodeSource(JAR, noCerts, "SHA-256", DIGEST.clone());
        Loaded c = load(unverified);
        if (c.limiter == null) {
            check("limiting domain was observed for the unverified digest", false);
            return;
        }
        PermissionGrant forC = dynamicGrant(c.type, unverified);
        check("dynamic grant does not cover an unverified digest",
                !forC.implies(c.limiter));
        check("dynamic grant does not cover an unverified digest's own domain",
                !forC.implies(c.domain));
    }

    private static PermissionGrant dynamicGrant(Class<?> type, DigestCodeSource source) {
        return PermissionGrantBuilder.newBuilder()
                .clazz(type)
                .codeSources(source)
                .permissions(new Permission[] {SECRET})
                .context(PermissionGrantBuilder.DIGEST_DOMAIN).build();
    }

    /** Defines Caller under a domain over the source and runs it once. */
    private static Loaded load(CodeSource source) throws Exception {
        Permissions all = new Permissions();
        all.add(new AllPermission());
        String name = Caller.class.getName();
        PdLoader loader = new PdLoader(name);
        ProtectionDomain pd = new ProtectionDomain(source, all, loader, null);
        loader.pd = pd;
        Class<?> c = loader.loadClass(name);
        lastLimiter = null;
        ((IntPredicate) c.getDeclaredConstructor().newInstance()).test(0);
        return new Loaded(c, pd, lastLimiter);
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}
