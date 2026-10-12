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
 * @summary DomainIdentity treats its principals as an ordered sequence, keeps
 *          hashCode consistent with equals, and is not affected by later
 *          changes to the caller's principal array.  Equal domains must hash
 *          equally and keep doing so, because DomainIdentity equality decides
 *          whether a rebuilt AccessControlContext matches a cached one; see
 *          SECURITY_MODEL.md section 11.6.4, "AccessControlContext.
 *          checkPermission(...) evaluates against the encapsulated context".
 *          Principal order being significant (SPIFFE principal position
 *          carries meaning) is stated by the Project Lead but is NOT yet
 *          stated in SECURITY_MODEL.md; it must be added there before merge.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main DomainIdentityPrincipalOrderTest
 */

import java.net.URL;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import javax.security.auth.x500.X500Principal;

/**
 * DomainIdentity's equality is part of the AccessControlContext cache key:
 * domains that are equal must also have equal hash codes, or rebuilt
 * contexts miss the cache.  Principal order is significant, because the
 * position of a SPIFFE principal in the sequence carries meaning, so the
 * same principals in a different order are a different domain.
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
 * <li>M1: hold the principals in a HashSet or LinkedHashSet (order-blind
 *     equals and hashCode), as on trunk b138bbd1.
 *     EXPECTED: "reversed order: domains are unequal" fails.
 *     OBSERVED: not yet recorded.</li>
 * <li>M2: hold Arrays.asList(principals), a view of the caller's array,
 *     rather than a copy.
 *     EXPECTED: "caller array change: still equals a domain built from
 *     [a, b]" and "caller array change: does not equal a domain built from
 *     [a, c]" fail.
 *     OBSERVED: not yet recorded.</li>
 * </ol>
 */
public class DomainIdentityPrincipalOrderTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        CodeSource cs = new CodeSource(
                new URL("file:/DomainIdentityPrincipalOrderTest/"), (Certificate[]) null);
        Principal a = new X500Principal("CN=Alice, O=DomainIdentityPrincipalOrderTest");
        Principal b = new X500Principal("CN=Bob, O=DomainIdentityPrincipalOrderTest");
        Principal c = new X500Principal("CN=Carol, O=DomainIdentityPrincipalOrderTest");

        // Same sequence: equal, with equal hash codes.
        ProtectionDomain ab1 = domain(cs, a, b);
        ProtectionDomain ab2 = domain(cs, a, b);
        check("same order: equals is symmetric and true",
                ab1.equals(ab2) && ab2.equals(ab1));
        check("same order: hashCode is equal",
                ab1.hashCode() == ab2.hashCode());

        // Same principals, different order: a different domain.
        ProtectionDomain ba = domain(cs, b, a);
        check("reversed order: domains are unequal",
                !ab1.equals(ba) && !ba.equals(ab1));

        // Different principal sequences stay different.
        ProtectionDomain onlyA = domain(cs, a);
        check("different principals: domains are unequal",
                !onlyA.equals(ab1) && !ab1.equals(onlyA));

        // No principals: rebuilt domains must equal each other.
        check("null principals: rebuilt domains are equal, equal hash",
                domain(cs, (Principal[]) null).equals(domain(cs, (Principal[]) null))
                        && domain(cs, (Principal[]) null).hashCode()
                           == domain(cs, (Principal[]) null).hashCode());
        check("empty principals: rebuilt domains are equal, equal hash",
                domain(cs).equals(domain(cs))
                        && domain(cs).hashCode() == domain(cs).hashCode());

        // The domain must not alias the caller's array.
        Principal[] callerArray = { a, b };
        ProtectionDomain fromArray = new DomainIdentity(cs, null, null, callerArray);
        int hashBefore = fromArray.hashCode();
        callerArray[1] = c;
        check("caller array change: hashCode is unchanged",
                fromArray.hashCode() == hashBefore);
        check("caller array change: still equals a domain built from [a, b]",
                fromArray.equals(ab1) && ab1.equals(fromArray));
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

    private static void check(String what, boolean ok) {
        System.out.println((ok ? "ok      " : "FAILED  ") + what);
        if (!ok) failures++;
    }
}
