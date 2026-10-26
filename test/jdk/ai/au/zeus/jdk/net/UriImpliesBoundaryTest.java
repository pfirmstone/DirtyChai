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
 * @summary A wildcard grant ("/-", "/*" or ";-") matches only what lies under
 *          its own path, not any path that merely begins with the same
 *          characters.  A grant for the directory file:/d/ must not match
 *          file:/dd/Foo, a grant for the module jrt:/java.base/ must not
 *          match the module java.base.extra, and a grant for the digest
 *          sha1=ab must not match the digest sha1=abc.  A prefix match
 *          without a path boundary over-grants to a different directory,
 *          module, jar or digest.
 *          Defends SECURITY_MODEL.md section 4 guarantee 2, "Least
 *          privilege", guarantee 6, "URI-validated code source matching",
 *          and section 15 invariant 4, "Policy evaluation must remain
 *          deny-by-default".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules java.base/au.zeus.jdk.net
 * @run main UriImpliesBoundaryTest
 */

import au.zeus.jdk.net.Uri;

/**
 * The standard CodeSource rule for "/-" is that the grant covers the
 * directory and everything below it.  In Uri.implies the wildcard suffix
 * that is removed before the prefix comparison includes the separator, so
 * the comparison no longer ends at a path boundary and "file:/d/-" matches
 * "file:/dd/Foo".  Coarse transition grants such as "jrt:/java.base/-" and
 * per-class grants for digest-qualified locations are affected in the same
 * way.
 *
 * <p>This test states the intended behaviour and is expected to FAIL on a
 * tree that has the prefix defect.  That failure is the demonstration that
 * the test is load-bearing (AI_POLICY.md 5.3): it is run against the
 * unmodified Uri.implies.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * <ol>
 * <li>M0 (the tree as found): Uri.implies removes two characters ("/-")
 *     from the grant path and compares with startsWith.
 *     OBSERVED, running this test's class against the Uri.java source of
 *     the commit under test, compiled with a JDK 25 javac and run from the
 *     classpath (not inside the DirtyChai JDK): five checks FAIL -
 *     "recursive grant does not match a sibling directory with the same
 *     prefix", "recursive module grant does not match a module with the
 *     same prefix", "recursive jar grant does not match a jar with the same
 *     prefix", "grant for a truncated digest does not match a longer
 *     digest" and "semicolon wildcard does not match a different jar with
 *     the same prefix".  The "/*" check and the four controls pass.</li>
 * <li>M1: after the prefix comparison, require that the next character of
 *     the implied path is the path separator ("/" for "/-", ";" for ";-"),
 *     or that the paths are equal.
 *     OBSERVED, on a scratch copy of Uri.java outside the source tree: all
 *     ten checks pass, and UriImpliesPerClassTest still passes.</li>
 * </ol>
 */
public class UriImpliesBoundaryTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        expect("recursive grant does not match a sibling directory with the same prefix",
                "file:/d/-", "file:/dd/Foo", false);
        expect("one-level wildcard does not match a sibling directory with the same prefix",
                "file:/d/*", "file:/dd/Foo", false);
        expect("recursive module grant does not match a module with the same prefix",
                "jrt:/java.base/-", "jrt:/java.base.extra/java.lang.Object", false);
        expect("recursive jar grant does not match a jar with the same prefix",
                "file:/lib/x.jar/-", "file:/lib/x.jar.evil/Foo", false);
        expect("grant for a truncated digest does not match a longer digest",
                "httpmd://h/x.jar;sha1=ab/-", "httpmd://h/x.jar;sha1=abc/pkg.Foo", false);
        expect("semicolon wildcard does not match a different jar with the same prefix",
                "httpmd://h/x.jar;-", "httpmd://h/x.jar.evil;sha1=abc/pkg.Foo", false);

        // Controls: the boundary rule must not remove what is intended.
        expect("control: recursive grant still matches a class below it",
                "file:/d/-", "file:/d/Foo", true);
        expect("control: recursive grant still matches a deeper class",
                "file:/d/-", "file:/d/sub/Foo", true);
        expect("control: module grant still matches a class in the module",
                "jrt:/java.base/-", "jrt:/java.base/java.lang.Object", true);
        expect("control: semicolon wildcard still matches any digest of the jar",
                "httpmd://h/x.jar;-", "httpmd://h/x.jar;sha1=abc/pkg.Foo", true);

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    private static void expect(String what, String grant, String implied,
            boolean expected) throws Exception {
        boolean got = Uri.parseAndCreate(grant).implies(Uri.parseAndCreate(implied));
        check(new StringBuilder(what).append(" [").append(grant).append(" -> ")
                .append(implied).append(']').toString(), got == expected);
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}
