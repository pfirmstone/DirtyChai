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
 * @summary DomainIdentity compares its principals as a set: the same
 *          principals in any order, or with duplicates, give equal domains
 *          with equal hash codes, and later changes to the caller's principal
 *          array do not affect the domain.  DomainIdentity equality decides
 *          whether a rebuilt AccessControlContext matches a cached one, so
 *          equal domains must hash equally and keep doing so; see
 *          SECURITY_MODEL.md section 11.6.4, "AccessControlContext.
 *          checkPermission(...) evaluates against the encapsulated context".
 *          Principals are matched as a set by policy (section 10.1,
 *          conjunctive multi-principal grants), so principal order and
 *          duplicates carry no authority and must not distinguish domains.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main DomainIdentityPrincipalSetTest
 */

import java.net.URL;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import javax.security.auth.x500.X500Principal;

/**
 * DomainIdentity's equality is part of the AccessControlContext cache key.
 * If two domains are equal but hash differently, rebuilt contexts miss the
 * cache; if they are unequal only because their principals arrive in a
 * different order, the cache fills with duplicate contexts.
 *
 * The hash code is computed once, at construction.  If the domain keeps a
 * view of the caller's array instead of a copy, a later write to that array
 * changes equals without changing hashCode, so the domain silently stops
 * matching itself in hashed collections.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation below is applied to the 4-argument DomainIdentity
 * constructor, the test is run, and the failing checks are recorded.
 * OBSERVED entries must be filled in from an actual run before this test is
 * merged; until then this test has not been demonstrated load-bearing.
 * <ol>
 * <li>M1: hash the principal array in argument order
 *     (Arrays.deepHashCode(principals)) while equals compares a set, as on
 *     trunk b138bbd1.
 *     EXPECTED: the "reversed order", "duplicate principal" and
 *     "duplicate principal, mixed order" checks fail.
 *     OBSERVED: not yet recorded.</li>
 * <li>M2: hold the principals as an ordered List (order-sensitive equals and
 *     hashCode).
 *     EXPECTED: the "reversed order", "duplicate principal" and
 *     "duplicate principal, mixed order" checks fail.
 *     OBSERVED: not yet recorded.</li>
 * <li>M3: hold Arrays.asList(principals), a view of the caller's array,
 *     rather than a copy.
 *     EXPECTED: "caller array change: still equals a domain built from
 *     [a, b]" and "caller array change: does not equal a domain built from
 *     [a, c]" fail.
 *     OBSERVED: not yet recorded.</li>
 * </ol>
 */
public class DomainIdentityPrincipalSetTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        CodeSource cs = new CodeSource(
                new URL("file:/DomainIdentityPrincipalSetTest/"), (Certificate[]) null);
        Principal a = new X500Principal("CN=Alice, O=DomainIdentityPrincipalSetTest");
        Principal b = new X500Principal("CN=Bob, O=DomainIdentityPrincipalSetTest");
        Principal c = new X500Principal("CN=Carol, O=DomainIdentityPrincipalSetTest");

        assertSameDomain("same order", domain(cs, a, b), domain(cs, a, b));
        assertSameDomain("reversed order", domain(cs, a, b), domain(cs, b, a));
        assertSameDomain("duplicate principal", domain(cs, a, a), domain(cs, a));
        assertSameDomain("duplicate principal, mixed order",
                domain(cs, a, b, a), domain(cs, b, a));
        assertSameDomain("null principals",
                domain(cs, (Principal[]) null), domain(cs, (Principal[]) null));
        assertSameDomain("empty principals", domain(cs), domain(cs));

        // Different principal sets must stay different.
        ProtectionDomain onlyA = domain(cs, a);
        ProtectionDomain ab = domain(cs, a, b);
        check("different principal sets: domains are unequal",
                !onlyA.equals(ab) && !ab.equals(onlyA));

        // The domain must not alias the caller's array.
        Principal[] callerArray = { a, b };
        ProtectionDomain fromArray = new DomainIdentity(cs, null, null, callerArray);
        int hashBefore = fromArray.hashCode();
        callerArray[1] = c;
        check("caller array change: hashCode is unchanged",
                fromArray.hashCode() == hashBefore);
        check("caller array change: still equals a domain built from [a, b]",
                fromArray.equals(ab) && ab.equals(fromArray));
        check("caller array change: does not equal a domain built from [a, c]",
                !fromArray.equals(domain(cs, a, c)));

        if (failures > 0) {
            throw new RuntimeException(failures + " check(s) failed, see output");
        }
        System.out.println("PASSED");
    }

    private static ProtectionDomain domain(CodeSource cs, Principal... principals) {
        return new DomainIdentity(cs, null, null, principals);
    }

    private static void assertSameDomain(String what,
                                         ProtectionDomain x,
                                         ProtectionDomain y) {
        check(what + ": equals is symmetric and true",
                x.equals(y) && y.equals(x));
        check(what + ": hashCode is equal",
                x.hashCode() == y.hashCode());
    }

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok      " : "FAILED  ") + what);
        if (!ok) failures++;
    }
}
