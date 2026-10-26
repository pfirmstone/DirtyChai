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
 * @summary Every form of AccessController.doPrivileged and
 *          doPrivilegedWithCombiner is bounded by a limiting domain derived
 *          from the calling class, so a privileged block can use only what
 *          policy grants to that class's own code source.  A sibling class
 *          from the same code source, and an inner, anonymous or lambda class
 *          of the sibling, gets no authority from another class's grant.
 *          Defends SECURITY_MODEL.md section 15 invariant 3, "Privileged
 *          execution must remain caller-sensitive and context-bounded",
 *          section 4 guarantee 2, "Least privilege", and section 7,
 *          "Effective permissions are constrained by the active
 *          AccessControlContext and policy grants".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow LimitedDoPrivilegedBoundTest
 */

import java.security.AccessControlContext;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.ProtectionDomain;
import java.util.concurrent.Callable;
import java.util.function.IntPredicate;

/**
 * The test models a polpAudit floor: the policy grants SECRET to the
 * per-class limiting domain of BoundGranted and to no other class.  Every
 * other domain, including the test's own protection domain, is granted
 * SECRET, so a denial can only come from the limiting domain.
 *
 * BoundGranted and BoundOther are identical top-level classes in one code
 * source.  They must be separate top-level classes: the limiting domain is
 * named after the top-level class, so nested classes would share an
 * identity.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: remove the limited(...) call from the one-argument
 *     doPrivileged(PrivilegedAction).
 *     OBSERVED: four checks FAIL - "other denied: doPrivileged(action)", and
 *     "other denied" for the inner class, lambda body and anonymous class
 *     forms, which also use the one-argument form.</li>
 * <li>M2: remove the limited(...) call from the two-argument
 *     doPrivileged(action, context) overloads.
 *     OBSERVED: four checks FAIL - "other denied" for the (action, null),
 *     (action, context), (exceptionAction, null) and (exceptionAction,
 *     context) forms.</li>
 * <li>M3: stop stripping the part of the class name from the first '$'.
 *     OBSERVED: two checks FAIL - "granted allowed: inner class" and "granted
 *     allowed: anonymous class".  The lambda-body form does not fail: a
 *     lambda body is compiled into a method of the enclosing class, so the
 *     caller is the top-level class itself.</li>
 * <li>M4: drop the class name from the policy URI, so every class in a code
 *     source has one identity.
 *     OBSERVED: 15 "granted allowed" checks FAIL, because policy can no
 *     longer tell BoundGranted from BoundOther.  The "other denied" checks
 *     cannot detect this, since both classes are then denied.</li>
 * </ol>
 */
@SuppressWarnings("removal")
public class LimitedDoPrivilegedBoundTest {

    static final Permission SECRET =
            new RuntimePermission("LimitedDoPrivilegedBoundTest.secret");

    /** Index of the control form that never calls doPrivileged. */
    static final int PLAIN = 15;

    static final String[] FORMS = {
        "doPrivileged(action)",
        "doPrivileged(action, null)",
        "doPrivileged(action, context)",
        "doPrivileged(exceptionAction)",
        "doPrivileged(exceptionAction, null)",
        "doPrivileged(exceptionAction, context)",
        "doPrivileged(action, context, no permissions)",
        "doPrivileged(exceptionAction, context, no permissions)",
        "doPrivilegedWithCombiner(action)",
        "doPrivilegedWithCombiner(exceptionAction)",
        "doPrivilegedWithCombiner(action, context, no permissions)",
        "doPrivilegedWithCombiner(exceptionAction, context, no permissions)",
        "inner class",
        "lambda body",
        "anonymous class",
        "no doPrivileged",
    };

    /**
     * Grants SECRET to the limiting domain of BoundGranted only.  Every
     * other permission, and SECRET for every domain that is not a limiting
     * domain, is granted, so the limiting domain is the only thing that can
     * deny SECRET.
     */
    static final class FloorPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (!SECRET.equals(permission)) {
                return true;
            }
            if (domain instanceof DomainIdentity) {
                CodeSource cs = domain.getCodeSource();
                Object uri = cs != null ? cs.getUriLocation() : null;
                return uri != null && uri.toString().endsWith("/BoundGranted");
            }
            return true;
        }
    }

    private static int failures;

    public static void main(String[] args) {
        Policy.setPolicy(new FloorPolicy());
        System.setSecurityManager(new SecurityManager());

        IntPredicate granted = new BoundGranted();
        IntPredicate other = new BoundOther();

        // Controls: without doPrivileged the limiting domain is not involved,
        // so both classes must be allowed.  This attributes every later
        // denial to the limiting domain and nothing else.
        check("control: Granted allowed with no doPrivileged", granted.test(PLAIN));
        check("control: Other allowed with no doPrivileged", other.test(PLAIN));

        for (int form = 0; form < PLAIN; form++) {
            check(label("granted allowed: ", FORMS[form]), granted.test(form));
            check(label("other denied: ", FORMS[form]), !other.test(form));
        }

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    private static String label(String prefix, String form) {
        return new StringBuilder(prefix).append(form).toString();
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}

/**
 * The class whose limiting domain policy grants SECRET to.  Each form of
 * doPrivileged is made from this class, or from a class nested in it.
 */
@SuppressWarnings("removal")
final class BoundGranted implements IntPredicate {

    @Override
    public boolean test(int form) {
        try {
            run(form);
            return true;
        } catch (AccessControlException ex) {
            return false;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static void run(int form) throws Exception {
        final Permission secret = LimitedDoPrivilegedBoundTest.SECRET;
        PrivilegedAction<Void> action = () -> {
            AccessController.checkPermission(secret);
            return null;
        };
        PrivilegedExceptionAction<Void> exceptionAction = () -> {
            AccessController.checkPermission(secret);
            return null;
        };
        AccessControlContext context = AccessController.getContext();
        Permission[] none = new Permission[0];
        switch (form) {
            case 0:
                AccessController.doPrivileged(action);
                break;
            case 1:
                AccessController.doPrivileged(action, (AccessControlContext) null);
                break;
            case 2:
                AccessController.doPrivileged(action, context);
                break;
            case 3:
                AccessController.doPrivileged(exceptionAction);
                break;
            case 4:
                AccessController.doPrivileged(exceptionAction, (AccessControlContext) null);
                break;
            case 5:
                AccessController.doPrivileged(exceptionAction, context);
                break;
            case 6:
                AccessController.doPrivileged(action, context, none);
                break;
            case 7:
                AccessController.doPrivileged(exceptionAction, context, none);
                break;
            case 8:
                AccessController.doPrivilegedWithCombiner(action);
                break;
            case 9:
                AccessController.doPrivilegedWithCombiner(exceptionAction);
                break;
            case 10:
                AccessController.doPrivilegedWithCombiner(action, context, none);
                break;
            case 11:
                AccessController.doPrivilegedWithCombiner(exceptionAction, context, none);
                break;
            case 12:
                new Inner().go(action);
                break;
            case 13:
                Callable<Void> viaLambda = () -> AccessController.doPrivileged(action);
                viaLambda.call();
                break;
            case 14:
                Callable<Void> viaAnonymous = new Callable<Void>() {
                    @Override
                    public Void call() {
                        return AccessController.doPrivileged(action);
                    }
                };
                viaAnonymous.call();
                break;
            default:
                AccessController.checkPermission(secret);
                break;
        }
    }

    /** doPrivileged is called from a nested class of the top-level class. */
    static final class Inner {
        void go(PrivilegedAction<Void> action) {
            AccessController.doPrivileged(action);
        }
    }
}

/** Identical to BoundGranted, but policy grants nothing to its limiting domain. */
@SuppressWarnings("removal")
final class BoundOther implements IntPredicate {

    @Override
    public boolean test(int form) {
        try {
            run(form);
            return true;
        } catch (AccessControlException ex) {
            return false;
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private static void run(int form) throws Exception {
        final Permission secret = LimitedDoPrivilegedBoundTest.SECRET;
        PrivilegedAction<Void> action = () -> {
            AccessController.checkPermission(secret);
            return null;
        };
        PrivilegedExceptionAction<Void> exceptionAction = () -> {
            AccessController.checkPermission(secret);
            return null;
        };
        AccessControlContext context = AccessController.getContext();
        Permission[] none = new Permission[0];
        switch (form) {
            case 0:
                AccessController.doPrivileged(action);
                break;
            case 1:
                AccessController.doPrivileged(action, (AccessControlContext) null);
                break;
            case 2:
                AccessController.doPrivileged(action, context);
                break;
            case 3:
                AccessController.doPrivileged(exceptionAction);
                break;
            case 4:
                AccessController.doPrivileged(exceptionAction, (AccessControlContext) null);
                break;
            case 5:
                AccessController.doPrivileged(exceptionAction, context);
                break;
            case 6:
                AccessController.doPrivileged(action, context, none);
                break;
            case 7:
                AccessController.doPrivileged(exceptionAction, context, none);
                break;
            case 8:
                AccessController.doPrivilegedWithCombiner(action);
                break;
            case 9:
                AccessController.doPrivilegedWithCombiner(exceptionAction);
                break;
            case 10:
                AccessController.doPrivilegedWithCombiner(action, context, none);
                break;
            case 11:
                AccessController.doPrivilegedWithCombiner(exceptionAction, context, none);
                break;
            case 12:
                new Inner().go(action);
                break;
            case 13:
                Callable<Void> viaLambda = () -> AccessController.doPrivileged(action);
                viaLambda.call();
                break;
            case 14:
                Callable<Void> viaAnonymous = new Callable<Void>() {
                    @Override
                    public Void call() {
                        return AccessController.doPrivileged(action);
                    }
                };
                viaAnonymous.call();
                break;
            default:
                AccessController.checkPermission(secret);
                break;
        }
    }

    /** doPrivileged is called from a nested class of the top-level class. */
    static final class Inner {
        void go(PrivilegedAction<Void> action) {
            AccessController.doPrivileged(action);
        }
    }
}
