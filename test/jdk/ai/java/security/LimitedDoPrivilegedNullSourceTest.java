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
 * @summary When the limiting domain cannot be given a code source, because
 *          the caller has no code source or its code source has no location,
 *          doPrivileged must fail closed: the limiting domain has no code
 *          source, so it can match no policy grant, and the privileged block
 *          is denied rather than run unlimited or run with a synthesised
 *          identity.  A caller with a usable code source in the same
 *          circumstances is allowed, so the denial is attributable to the
 *          missing code source.
 *          Defends SECURITY_MODEL.md section 4 guarantee 1, "Fail-secure
 *          defaults", section 15 invariant 5, "Validation failures must
 *          remain fail-secure", and the section 7 rule that a limiting
 *          domain whose code source cannot be built "cannot match any
 *          grant".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow LimitedDoPrivilegedNullSourceTest
 */

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.Permissions;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.function.IntPredicate;

/**
 * The caller class is defined by a class loader under a ProtectionDomain the
 * test chooses.  That domain holds AllPermission statically, so it never
 * denies anything itself: the limiting domain is the only thing that can.
 *
 * The policy models HC-5: a limiting domain grants SECRET only if it has a
 * code source with a location, because a domain with no code source can
 * match no grant.  The test also checks the property the policy relies on,
 * that the limiting domain really has no code source in the failing cases.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: when the caller's code source has no location, build a code source
 *     from a made-up location instead of returning null.
 *     OBSERVED: two checks FAIL - "no location: limiting domain has no code
 *     source" and "no location: denied".</li>
 * <li>M2: when the caller has no code source, build one from a made-up
 *     location instead of returning null.
 *     OBSERVED: two checks FAIL - "no code source: limiting domain has no code
 *     source" and "no code source: denied".</li>
 * <li>M3: make the control case return a null code source.
 *     not run.  It would show that the denials above are not simply the
 *     policy refusing every limiting domain.</li>
 * </ol>
 */
@SuppressWarnings("removal")
public class LimitedDoPrivilegedNullSourceTest {

    public static final Permission SECRET =
            new RuntimePermission("LimitedDoPrivilegedNullSourceTest.secret");

    static volatile DomainIdentity lastLimiter;

    static final class Hc5Policy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (!SECRET.equals(permission)) {
                return true;
            }
            if (domain instanceof DomainIdentity) {
                lastLimiter = (DomainIdentity) domain;
                CodeSource cs = domain.getCodeSource();
                return cs != null && cs.getUriLocation() != null;
            }
            return true;
        }
    }

    /** Calls doPrivileged and reports whether the check inside it passed. */
    public static final class Caller implements IntPredicate {
        @Override
        public boolean test(int unused) {
            try {
                AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                    AccessController.checkPermission(SECRET);
                    return null;
                });
                return true;
            } catch (AccessControlException ex) {
                return false;
            }
        }
    }

    /** Defines Caller itself under a chosen ProtectionDomain. */
    static final class PdLoader extends ClassLoader {
        private final String name;
        private final ProtectionDomain pd;

        PdLoader(String name, ProtectionDomain pd) {
            super(LimitedDoPrivilegedNullSourceTest.class.getClassLoader());
            this.name = name;
            this.pd = pd;
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

    private static int failures;

    public static void main(String[] args) throws Exception {
        Policy.setPolicy(new Hc5Policy());
        System.setSecurityManager(new SecurityManager());

        Certificate[] noCerts = null;
        // A code source with no location.
        run("no location", new ProtectionDomain(
                new CodeSource(null, noCerts), allPermissions()), false);
        // No code source at all.
        run("no code source", new ProtectionDomain(null, allPermissions()), false);
        // Control: an ordinary code source with a location.
        run("control", new ProtectionDomain(
                new CodeSource(new URL("file:/limited-null-source-control/"), noCerts),
                allPermissions()), true);

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    private static void run(String label, ProtectionDomain callerDomain,
            boolean expectAllowed) throws Exception {
        String name = Caller.class.getName();
        Class<?> c = new PdLoader(name, callerDomain).loadClass(name);
        check(join(label, ": caller really has the chosen domain"),
                c.getProtectionDomain() == callerDomain);
        IntPredicate caller = (IntPredicate) c.getDeclaredConstructor().newInstance();

        lastLimiter = null;
        boolean allowed = caller.test(0);
        DomainIdentity limiter = lastLimiter;

        check(join(label, ": limiting domain was consulted"), limiter != null);
        if (limiter != null) {
            boolean hasSource = limiter.getCodeSource() != null;
            check(join(label, expectAllowed
                            ? ": limiting domain has a code source"
                            : ": limiting domain has no code source"),
                    hasSource == expectAllowed);
        }
        check(join(label, expectAllowed ? ": allowed" : ": denied"),
                allowed == expectAllowed);
    }

    private static Permissions allPermissions() {
        Permissions perms = new Permissions();
        perms.add(new AllPermission());
        return perms;
    }

    private static String join(String a, String b) {
        return new StringBuilder(a).append(b).toString();
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}
