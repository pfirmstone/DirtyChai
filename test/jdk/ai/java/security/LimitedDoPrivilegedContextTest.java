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
 * @summary The limiting domain doPrivileged adds only ever narrows
 *          authority.  A supplied AccessControlContext that lacks a
 *          permission still lacks it inside the privileged block, however
 *          generous the caller's own limiting domain is; a caller whose own
 *          domain lacks a permission cannot gain it by listing it as an
 *          explicit permission; and a supplied context that does hold the
 *          permission still works, so the narrowing is by intersection and
 *          not by replacement.
 *          Defends SECURITY_MODEL.md section 15 invariant 3, "Privileged
 *          execution must remain caller-sensitive and context-bounded",
 *          section 4 guarantee 2, "Least privilege", and section 7,
 *          "Effective permissions are constrained by the active
 *          AccessControlContext".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow LimitedDoPrivilegedContextTest
 */

import java.io.IOException;
import java.io.InputStream;
import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.Permissions;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.util.function.Supplier;

/**
 * Policy grants SECRET to every domain except the restricted one, so a
 * limiting domain is never what denies it.  The restricted domain has a
 * permission set without SECRET and is denied SECRET by policy too, so only
 * code running under it, or a context captured under it, lacks SECRET.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: when a context is supplied, use only the limiting domain and drop the
 *     supplied context.
 *     OBSERVED: six checks FAIL - every "restricted context still denies"
 *     check.  The "granted context allowed" controls still pass.</li>
 * <li>M2: when the caller lists explicit permissions, run with those permissions
 *     and the limiting domain only, without the caller's own domain.
 *     not run.</li>
 * <li>M3: build the limiting domain as a static domain with an empty permission
 *     set, so it denies everything regardless of policy.
 *     not run.  It would make the "granted context allowed" controls fail.</li>
 * </ol>
 */
@SuppressWarnings("removal")
public class LimitedDoPrivilegedContextTest {

    public static final Permission SECRET =
            new RuntimePermission("LimitedDoPrivilegedContextTest.secret");

    /** The domain that must not hold SECRET; set once, before the policy is used. */
    static volatile ProtectionDomain restrictedDomain;

    /**
     * Grants everything to everything except SECRET to the restricted
     * domain.  A ProtectionDomain here consults policy even when it was
     * given static permissions, so the restricted domain has to be denied
     * by policy as well as by its own permission set.
     */
    static final class GrantingPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            return !(SECRET.equals(permission) && domain == restrictedDomain);
        }
    }

    /** Captures the context of the stack it is called on. */
    public static final class Capture implements Supplier<AccessControlContext> {
        @Override
        public AccessControlContext get() {
            return AccessController.getContext();
        }
    }

    /** Uses a supplied context, with and without explicit permissions. */
    public static final class ContextCaller {
        public boolean run(int form, AccessControlContext context) throws Exception {
            PrivilegedAction<Void> action = () -> {
                AccessController.checkPermission(SECRET);
                return null;
            };
            PrivilegedExceptionAction<Void> exceptionAction = () -> {
                AccessController.checkPermission(SECRET);
                return null;
            };
            Permission[] listed = { SECRET };
            try {
                switch (form) {
                    case 0:
                        AccessController.doPrivileged(action, context);
                        break;
                    case 1:
                        AccessController.doPrivileged(action, context, listed);
                        break;
                    case 2:
                        AccessController.doPrivilegedWithCombiner(action, context, listed);
                        break;
                    case 3:
                        AccessController.doPrivileged(exceptionAction, context);
                        break;
                    case 4:
                        AccessController.doPrivileged(exceptionAction, context, listed);
                        break;
                    default:
                        AccessController.doPrivilegedWithCombiner(
                                exceptionAction, context, listed);
                        break;
                }
                return true;
            } catch (AccessControlException ex) {
                return false;
            }
        }
    }

    /**
     * Lists SECRET as an explicit permission while running under a domain
     * that does not hold it.
     */
    public static final class RestrictedCaller {
        public boolean run(int form) throws Exception {
            PrivilegedAction<Void> action = () -> {
                AccessController.checkPermission(SECRET);
                return null;
            };
            PrivilegedExceptionAction<Void> exceptionAction = () -> {
                AccessController.checkPermission(SECRET);
                return null;
            };
            Permission[] listed = { SECRET };
            try {
                switch (form) {
                    case 0:
                        AccessController.doPrivileged(action, (AccessControlContext) null, listed);
                        break;
                    case 1:
                        AccessController.doPrivilegedWithCombiner(action,
                                AccessController.getContext(), listed);
                        break;
                    case 2:
                        AccessController.doPrivileged(exceptionAction,
                                (AccessControlContext) null, listed);
                        break;
                    default:
                        AccessController.doPrivilegedWithCombiner(exceptionAction,
                                AccessController.getContext(), listed);
                        break;
                }
                return true;
            } catch (AccessControlException ex) {
                return false;
            }
        }
    }

    /** Defines one named class itself, under a chosen ProtectionDomain. */
    static final class PdLoader extends ClassLoader {
        private final String name;
        private final ProtectionDomain pd;

        PdLoader(String name, ProtectionDomain pd) {
            super(LimitedDoPrivilegedContextTest.class.getClassLoader());
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

    private static final String[] CONTEXT_FORMS = {
        "doPrivileged(action, context)",
        "doPrivileged(action, context, SECRET)",
        "doPrivilegedWithCombiner(action, context, SECRET)",
        "doPrivileged(exceptionAction, context)",
        "doPrivileged(exceptionAction, context, SECRET)",
        "doPrivilegedWithCombiner(exceptionAction, context, SECRET)",
    };

    private static final String[] RESTRICTED_FORMS = {
        "doPrivileged(action, null, SECRET)",
        "doPrivilegedWithCombiner(action, context, SECRET)",
        "doPrivileged(exceptionAction, null, SECRET)",
        "doPrivilegedWithCombiner(exceptionAction, context, SECRET)",
    };

    private static int failures;

    public static void main(String[] args) throws Exception {
        Policy.setPolicy(new GrantingPolicy());
        System.setSecurityManager(new SecurityManager());

        // A static domain that holds an unrelated permission but not SECRET.
        Permissions unrelated = new Permissions();
        unrelated.add(new RuntimePermission("LimitedDoPrivilegedContextTest.unrelated"));
        ProtectionDomain restricted = new ProtectionDomain(null, unrelated);
        restrictedDomain = restricted;

        // A context captured under the restricted domain, and one captured
        // by this class alone.
        String captureName = Capture.class.getName();
        Class<?> captureClass = new PdLoader(captureName, restricted).loadClass(captureName);
        @SuppressWarnings("unchecked")
        Supplier<AccessControlContext> capture =
                (Supplier<AccessControlContext>) captureClass.getDeclaredConstructor().newInstance();
        AccessControlContext restrictedContext = capture.get();
        AccessControlContext grantedContext = new Capture().get();

        check("restricted context really lacks SECRET", !holdsSecret(restrictedContext));
        check("granted context really holds SECRET", holdsSecret(grantedContext));

        ContextCaller caller = new ContextCaller();
        for (int form = 0; form < CONTEXT_FORMS.length; form++) {
            check(label("restricted context still denies: ", CONTEXT_FORMS[form]),
                    !caller.run(form, restrictedContext));
            check(label("granted context allowed: ", CONTEXT_FORMS[form]),
                    caller.run(form, grantedContext));
        }

        String restrictedName = RestrictedCaller.class.getName();
        Class<?> restrictedClass =
                new PdLoader(restrictedName, restricted).loadClass(restrictedName);
        Object restrictedCaller = restrictedClass.getDeclaredConstructor().newInstance();
        java.lang.reflect.Method run = restrictedClass.getMethod("run", int.class);
        for (int form = 0; form < RESTRICTED_FORMS.length; form++) {
            boolean allowed = (Boolean) run.invoke(restrictedCaller, form);
            check(label("restricted caller cannot gain SECRET: ", RESTRICTED_FORMS[form]),
                    !allowed);
        }

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    /** Whether a context permits SECRET, checked without doPrivileged. */
    private static boolean holdsSecret(AccessControlContext context) {
        try {
            context.checkPermission(SECRET);
            return true;
        } catch (AccessControlException ex) {
            return false;
        }
    }

    private static String label(String prefix, String form) {
        return new StringBuilder(prefix).append(form).toString();
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}
