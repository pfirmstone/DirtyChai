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
 * @summary UnresolvedPrincipal.implies must require BOTH its class and its
 *          name to match.  The class must match exactly: "*" is NOT a class
 *          wildcard (operator decision 2026-11-01: only the name may be a
 *          wildcard), so a definition whose class is "*" implies no real
 *          principal.  The name may be "*", which matches any name of that
 *          exact class.  PrincipalGrant uses implies to decide whether a
 *          policy "principal" entry is satisfied by a domain's principals,
 *          so an implication that is too wide makes a grant that names one
 *          principal fire for every principal.  The invariant is the
 *          conjunctive principal matching of SECURITY_MODEL.md section 10.1
 *          ("a multi-principal policy grant fires only when every listed
 *          principal is co-present"): each listed principal must itself be
 *          matched exactly in class, and in name unless the name is "*".
 *          The first version of this test (2026-11-01) allowed a wildcard
 *          class and failed on the defect where implies() parsed its
 *          condition as wildcardClass || (class matches && name matches),
 *          which made "principal * CN=alice" match every principal.  The
 *          maintainer fixed it by removing the class wildcard; this version
 *          states that contract.
 * @modules java.base/org.apache.river.api.security
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main UnresolvedPrincipalImpliesTest
 */

import java.security.Principal;
import javax.security.auth.x500.X500Principal;
import org.apache.river.api.security.UnresolvedPrincipal;

/**
 * Cases are written from the documented contract of
 * UnresolvedPrincipal.implies (as amended 2026-11-01): "Returns true if ...
 * the fully qualified name of class of passed Principal is equal to the class name value of this
 * definition and the name of passed Principal is equal to the name value of
 * this definition, or if this definition allows any name."  The class is
 * always compared exactly; only the name has a wildcard.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation is applied to UnresolvedPrincipal.implies in a scratch copy
 * (compiled and loaded with --patch-module java.base=..., the source tree is
 * not touched), the test is run, and the failing checks are recorded.
 * <ol>
 * <li>M0: the code before the maintainer's fix (trunk 91737c79880: class
 *     "*" treated as a class wildcard, and the condition parsed as
 *     wildcardClass || (classMatch &amp;&amp; nameMatch)).
 *     EXPECTED: the "class '*'" checks fail (that code implies principals
 *     for them).
 *     OBSERVED (2026-11-01, pre-fix source from git HEAD, compiled into a
 *     scratch --patch-module): 6 checks failed, all the "class '*'" ones.</li>
 * <li>M1: the maintainer's fix as in the working tree on 2026-11-01
 *     (klass.equals(class) &amp;&amp; (wildcardName || nameMatch)).
 *     EXPECTED: every check passes.
 *     OBSERVED: PASSED, both against a --patch-module copy of the working
 *     tree source and against the rebuilt image.</li>
 * <li>M2: an exact class implies every name.
 *     EXPECTED: "exact class, other name: does NOT imply" fails.
 *     OBSERVED: that check and "null name: does NOT imply a principal with a
 *     name" failed, 2 checks.</li>
 * <li>M3: an exact name implies every class.
 *     EXPECTED: "exact class, same name, other class: does NOT imply" fails.
 *     OBSERVED: "exact class, same name, other class", "class name is not
 *     matched as a prefix" and the two "class '*', name alice: does NOT
 *     imply ... alice" checks failed, 4 checks.</li>
 * </ol>
 */
public class UnresolvedPrincipalImpliesTest {

    private static int failures;

    /** A principal class that is not X500Principal, with a settable name. */
    private static final class Other implements Principal {
        private final String name;
        Other(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public String toString() { return "Other(" + name + ")"; }
    }

    public static void main(String[] args) {
        String x500 = X500Principal.class.getName();
        String other = Other.class.getName();
        Principal alice = new X500Principal("CN=alice");
        Principal bob = new X500Principal("CN=bob");
        Principal otherAlice = new Other("CN=alice");
        Principal otherBob = new Other("CN=bob");

        // "*" is not a class wildcard: a definition whose class is "*" implies
        // no real principal, whatever its name (fail closed).
        UnresolvedPrincipal anyAny = new UnresolvedPrincipal("*", "*");
        check("class '*', name '*': does NOT imply an X500 principal", !anyAny.implies(alice));
        check("class '*', name '*': does NOT imply another class", !anyAny.implies(otherBob));
        check("class '*', name '*': does not imply null", !anyAny.implies((Principal) null));

        UnresolvedPrincipal anyAlice = new UnresolvedPrincipal("*", "CN=alice");
        check("class '*', name alice: does NOT imply X500 alice", !anyAlice.implies(alice));
        check("class '*', name alice: does NOT imply Other alice", !anyAlice.implies(otherAlice));
        check("class '*', name alice: does NOT imply X500 bob", !anyAlice.implies(bob));
        check("class '*', name alice: does NOT imply Other bob", !anyAlice.implies(otherBob));
        check("class '*', name alice: does not imply null", !anyAlice.implies((Principal) null));

        // Exact class, wildcard name: the class must still match.
        UnresolvedPrincipal x500Any = new UnresolvedPrincipal(x500, "*");
        check("X500 class, wildcard name: implies alice", x500Any.implies(alice));
        check("X500 class, wildcard name: implies bob", x500Any.implies(bob));
        check("X500 class, wildcard name: does NOT imply another class", !x500Any.implies(otherAlice));

        // Exact class, exact name: both must match.
        UnresolvedPrincipal x500Alice = new UnresolvedPrincipal(x500, "CN=alice");
        check("exact class and name: implies the same principal", x500Alice.implies(alice));
        check("exact class, other name: does NOT imply", !x500Alice.implies(bob));
        check("exact class, same name, other class: does NOT imply", !x500Alice.implies(otherAlice));
        check("exact class, other name, other class: does NOT imply", !x500Alice.implies(otherBob));

        // A null name in the definition matches only a principal whose name is null.
        UnresolvedPrincipal nullName = new UnresolvedPrincipal(other, null);
        check("null name: implies a principal with a null name", nullName.implies(new Other(null)));
        check("null name: does NOT imply a principal with a name", !nullName.implies(otherAlice));

        // The class name is compared exactly, not as a prefix or by inheritance.
        UnresolvedPrincipal prefix = new UnresolvedPrincipal("javax.security.auth.x500", "CN=alice");
        check("class name is not matched as a prefix", !prefix.implies(alice));

        if (failures > 0) {
            throw new RuntimeException(failures + " check(s) failed, see output");
        }
        System.out.println("PASSED");
    }

    private static void check(String what, boolean ok) {
        if (!ok) {
            failures++;
            System.out.println("FAIL: " + what);
        }
    }
}
