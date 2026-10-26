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
 * @summary The limiting domain that doPrivileged adds names exactly the
 *          calling class: its policy URI is the caller's code source
 *          location followed by the top-level class name, it keeps the
 *          caller's original location URL, it is a plain CodeSource, and two
 *          classes that share one ProtectionDomain are never given each
 *          other's limiting domain, however many there are and wherever they
 *          fall in the identity cache.  A limiting domain that named the
 *          wrong class would apply another class's policy grants.
 *          Defends SECURITY_MODEL.md section 15 invariant 3, "Privileged
 *          execution must remain caller-sensitive and context-bounded",
 *          section 4 guarantee 2, "Least privilege", and guarantee 6,
 *          "URI-validated code source matching".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm -Djava.security.manager=allow LimitedDoPrivilegedIdentityTest
 */

import java.lang.classfile.ClassFile;
import java.lang.constant.ClassDesc;
import java.lang.constant.ConstantDescs;
import java.lang.constant.MethodTypeDesc;
import java.lang.invoke.MethodHandles;
import java.security.AccessController;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.DomainIdentity;
import java.security.Permission;
import java.security.Policy;
import java.security.PrivilegedAction;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

/**
 * The policy records every limiting domain it is asked about for PROBE and
 * grants everything, so the test sees what AccessController built rather than
 * what policy decided.
 *
 * The collision scenario defines many hidden classes in this class's
 * ProtectionDomain.  They share one domain, so an identity cache that
 * matched on the domain, rather than on the class, would hand one class
 * another's limiting domain as soon as two of them landed in the same slot
 * pair.  With thousands of classes in a table of a few thousand slots that
 * is a near certainty, so the scenario does not depend on a lucky hash.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: in lookup(Class), accept a cached identity when its getCallerDomain()
 *     equals the caller's ProtectionDomain, instead of when it was built for the
 *     same Class.
 *     OBSERVED: two checks FAIL - "collision: every limiting domain names its
 *     own class" and "collision: every class has a distinct policy URI".</li>
 * <li>M2: build the Uri without the class name.
 *     OBSERVED: six checks FAIL - "policy URI ends with the class name",
 *     "policy URI of the sibling ends with its own class name", "siblings in
 *     one code source get different policy URIs", "doPrivileged in a lambda
 *     body is named after the enclosing class", and the two "collision" checks above.</li>
 * <li>M3: append "/" unconditionally to a location that already ends in "/", as
 *     a directory code source does.
 *     OBSERVED: one check FAILS - "no empty path segment in the policy URI".</li>
 * <li>M4: pass a new URL built from the per-class string, instead of the
 *     caller's location, to the CodeSource constructor.
 *     not run.</li>
 * </ol>
 */
@SuppressWarnings("removal")
public class LimitedDoPrivilegedIdentityTest {

    public static final Permission PROBE =
            new RuntimePermission("LimitedDoPrivilegedIdentityTest.probe");

    /** More than the identity cache has slots, to guarantee slot sharing. */
    private static final int GENERATED = 6000;

    static final List<DomainIdentity> SEEN = new CopyOnWriteArrayList<>();

    static final class RecordingPolicy extends Policy {
        @Override
        public boolean implies(ProtectionDomain domain, Permission permission) {
            if (PROBE.equals(permission) && domain instanceof DomainIdentity) {
                SEEN.add((DomainIdentity) domain);
            }
            return true;
        }
    }

    private static int failures;

    /** Called by the generated classes from inside their privileged action. */
    public static void probe() {
        AccessController.checkPermission(PROBE);
    }

    public static void main(String[] args) throws Exception {
        Policy.setPolicy(new RecordingPolicy());
        System.setSecurityManager(new SecurityManager());

        CodeSource here = LimitedDoPrivilegedIdentityTest.class
                .getProtectionDomain().getCodeSource();

        siblingsAndShape(here);
        collisions();

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    /** Shape of the limiting domain, and sibling classes in one code source. */
    private static void siblingsAndShape(CodeSource here) {
        DomainIdentity a = limiterOf(new IdentityA());
        DomainIdentity b = limiterOf(new IdentityB());
        check("limiting domain observed for IdentityA", a != null);
        check("limiting domain observed for IdentityB", b != null);
        if (a == null || b == null) {
            return;
        }
        CodeSource aSource = a.getCodeSource();
        CodeSource bSource = b.getCodeSource();
        check("limiting domain has a code source", aSource != null && bSource != null);
        if (aSource == null || bSource == null) {
            return;
        }
        String aUri = String.valueOf(aSource.getUriLocation());
        String bUri = String.valueOf(bSource.getUriLocation());

        check("policy URI ends with the class name", aUri.endsWith("/IdentityA"));
        check("policy URI of the sibling ends with its own class name",
                bUri.endsWith("/IdentityB"));
        check("siblings in one code source get different policy URIs",
                !aUri.equals(bUri));
        check("siblings in one code source get different limiting domains",
                !a.equals(b));
        check("no empty path segment in the policy URI", !hasEmptySegment(aUri));
        check("keeps the caller's original location URL",
                here.getLocation().toString().equals(aSource.getLocation().toString()));
        check("limiting domain is a plain CodeSource, not a digest source",
                !(aSource instanceof DigestCodeSource));
        check("limiting domain records the caller's domain",
                a.getCallerDomain() == IdentityA.class.getProtectionDomain());

        DomainIdentity again = limiterOf(new IdentityA());
        check("same class twice gives equal limiting domains",
                again != null && a.equals(again));
        check("same class twice gives equal hash codes",
                again != null && a.hashCode() == again.hashCode());

        // Inner, anonymous and lambda code is named after the top-level
        // class, so it matches the grant the top-level class has.
        DomainIdentity viaLambda = limiterOf(new IdentityLambda());
        check("doPrivileged in a lambda body is named after the enclosing class",
                viaLambda != null && viaLambda.getCodeSource() != null
                && String.valueOf(viaLambda.getCodeSource().getUriLocation())
                        .endsWith("/IdentityLambda"));
    }

    /** Many classes in one ProtectionDomain: none may get another's domain. */
    private static void collisions() throws Exception {
        MethodHandles.Lookup lookup = MethodHandles.lookup();
        List<Supplier<?>> callers = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (int i = 0; i < GENERATED; i++) {
            String name = new StringBuilder("LimitedGen").append(i).toString();
            Class<?> c = lookup.defineHiddenClass(generate(name), true).lookupClass();
            callers.add((Supplier<?>) c.getDeclaredConstructor().newInstance());
            names.add(name);
        }

        // Keep every limiting domain strongly reachable: the identity cache
        // holds them weakly, and a cleared slot cannot collide.
        List<DomainIdentity> retained = new ArrayList<>();
        Set<String> distinct = new HashSet<>();
        int wrong = 0;
        int missing = 0;
        for (int i = 0; i < GENERATED; i++) {
            DomainIdentity d = limiterOf(callers.get(i));
            if (d == null || d.getCodeSource() == null) {
                missing++;
                retained.add(null);
                continue;
            }
            retained.add(d);
            String uri = String.valueOf(d.getCodeSource().getUriLocation());
            distinct.add(uri);
            String marker = new StringBuilder("/").append(names.get(i)).append('/').toString();
            if (!uri.contains(marker)) {
                wrong++;
            }
        }
        check("collision: a limiting domain was observed for every class", missing == 0);
        check("collision: every limiting domain names its own class", wrong == 0);
        check("collision: every class has a distinct policy URI",
                distinct.size() == GENERATED);

        int changed = 0;
        for (int i = 0; i < GENERATED; i++) {
            DomainIdentity first = retained.get(i);
            DomainIdentity second = limiterOf(callers.get(i));
            if (first == null || second == null || !first.equals(second)) {
                changed++;
            }
        }
        check("collision: second pass returns the first pass's domain", changed == 0);
    }

    /**
     * Runs the caller and returns the limiting domain the policy was asked
     * about, or null if there was none.  Every sighting during one call must
     * be the same domain.
     */
    private static DomainIdentity limiterOf(Object caller) {
        SEEN.clear();
        if (caller instanceof Runnable r) {
            r.run();
        } else {
            ((Supplier<?>) caller).get();
        }
        List<DomainIdentity> seen = new ArrayList<>(SEEN);
        if (seen.isEmpty()) {
            return null;
        }
        DomainIdentity first = seen.get(0);
        for (DomainIdentity d : seen) {
            if (!first.equals(d)) {
                return null;
            }
        }
        return first;
    }

    /** True if the path of the URI has an empty segment such as "a//b". */
    private static boolean hasEmptySegment(String uri) {
        int colon = uri.indexOf(':');
        String rest = colon >= 0 ? uri.substring(colon + 1) : uri;
        int i = 0;
        while (i < rest.length() && rest.charAt(i) == '/') {
            i++;
        }
        return rest.substring(i).contains("//");
    }

    /**
     * Generates a public final class implementing Supplier and
     * PrivilegedAction.  get() calls AccessController.doPrivileged(this);
     * run() calls probe().
     */
    private static byte[] generate(String name) {
        ClassDesc self = ClassDesc.of(name);
        ClassDesc supplier = ClassDesc.of("java.util.function.Supplier");
        ClassDesc action = ClassDesc.of("java.security.PrivilegedAction");
        ClassDesc controller = ClassDesc.of("java.security.AccessController");
        ClassDesc test = ClassDesc.of("LimitedDoPrivilegedIdentityTest");
        MethodTypeDesc returnsObject = MethodTypeDesc.of(ConstantDescs.CD_Object);
        return ClassFile.of().build(self, cb -> {
            cb.withFlags(ClassFile.ACC_PUBLIC | ClassFile.ACC_FINAL | ClassFile.ACC_SUPER);
            cb.withSuperclass(ConstantDescs.CD_Object);
            cb.withInterfaceSymbols(supplier, action);
            cb.withMethodBody(ConstantDescs.INIT_NAME, ConstantDescs.MTD_void,
                    ClassFile.ACC_PUBLIC, c -> c
                            .aload(0)
                            .invokespecial(ConstantDescs.CD_Object,
                                    ConstantDescs.INIT_NAME, ConstantDescs.MTD_void)
                            .return_());
            cb.withMethodBody("get", returnsObject, ClassFile.ACC_PUBLIC, c -> c
                    .aload(0)
                    .invokestatic(controller, "doPrivileged",
                            MethodTypeDesc.of(ConstantDescs.CD_Object, action))
                    .areturn());
            cb.withMethodBody("run", returnsObject, ClassFile.ACC_PUBLIC, c -> c
                    .invokestatic(test, "probe", ConstantDescs.MTD_void)
                    .aconst_null()
                    .areturn());
        });
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}

/** A top-level class that calls doPrivileged directly. */
@SuppressWarnings("removal")
final class IdentityA implements Runnable {
    @Override
    public void run() {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            LimitedDoPrivilegedIdentityTest.probe();
            return null;
        });
    }
}

/** A sibling of IdentityA in the same code source. */
@SuppressWarnings("removal")
final class IdentityB implements Runnable {
    @Override
    public void run() {
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            LimitedDoPrivilegedIdentityTest.probe();
            return null;
        });
    }
}

/** doPrivileged is called from a lambda, so the caller is a hidden class. */
@SuppressWarnings("removal")
final class IdentityLambda implements Runnable {
    @Override
    public void run() {
        Runnable inner = () -> AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            LimitedDoPrivilegedIdentityTest.probe();
            return null;
        });
        inner.run();
    }
}
