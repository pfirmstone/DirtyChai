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
 * @summary A grant URI matches the per-class URI that doPrivileged builds
 *          for a caller (the caller's code source location with the class
 *          name appended) exactly as the code source rules say it should:
 *          a grant naming the exact per-class URI matches that class and
 *          no other; a recursive grant on the location or module matches
 *          every class under it; a one-level wildcard matches its own
 *          level only; a directory or jar location on its own matches no
 *          class; and for digest-qualified httpmd locations, a grant for the
 *          digest matches only classes of that digest, while the ";-" form
 *          deliberately matches any digest of the named jar.  Escaped and
 *          unescaped spellings of one location are the same URI.
 *          Defends SECURITY_MODEL.md section 4 guarantee 6, "URI-validated
 *          code source matching", and the section 7 statement that grants
 *          meant for limited-privilege blocks must match the per-class
 *          URI.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules java.base/au.zeus.jdk.net
 * @run main UriImpliesPerClassTest
 */

import au.zeus.jdk.net.Uri;

/**
 * The per-class URI is the policy identity of a limiting domain, so how
 * grants match it decides what polpAudit's per-class floors and the coarse
 * transition grants (jrt:/module/-) actually grant.  These cases are the
 * intended matching rules; the path-boundary rule, which the current
 * implementation does not meet, is in UriImpliesBoundaryTest.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation is applied to Uri.implies, the test is run, and the failing
 * checks are recorded.  OBSERVED entries must be filled in from an actual
 * run before this test is merged; until then this test has not been
 * demonstrated load-bearing.
 * <ol>
 * <li>M1: treat a location that does not end in a wildcard as a prefix.
 *     OBSERVED, on a scratch copy of Uri.java outside the source tree, run
 *     from the classpath with a JDK 25 java (not inside the DirtyChai JDK):
 *     four checks FAIL - "directory matches no class", "bare location
 *     matches no class", "module grant does not match another class" and
 *     "digest location on its own matches no class".</li>
 * <li>M2: make "/*" behave as "/-".
 *     OBSERVED, same method: "one-level wildcard does not match a deeper
 *     class" FAILS and no other check does.</li>
 * <li>M3: make ";-" require the same digest.
 *     EXPECTED: "semicolon wildcard matches any digest" fails.
 *     OBSERVED: not yet recorded.</li>
 * <li>M4: ignore the digest in the path when matching.
 *     EXPECTED: "grant for another digest does not match" fails.
 *     OBSERVED: not yet recorded.</li>
 * </ol>
 */
public class UriImpliesPerClassTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        // Directory code source, the case for classes loaded from a
        // classpath directory.
        expect("exact grant matches its own class",
                "file:/d/Foo", "file:/d/Foo", true);
        expect("exact grant does not match another class",
                "file:/d/Foo", "file:/d/Bar", false);
        expect("recursive grant matches a class in the directory",
                "file:/d/-", "file:/d/Foo", true);
        expect("recursive grant matches a class in a subdirectory",
                "file:/d/-", "file:/d/sub/Foo", true);
        expect("one-level wildcard matches a class in the directory",
                "file:/d/*", "file:/d/Foo", true);
        expect("one-level wildcard does not match a deeper class",
                "file:/d/*", "file:/d/sub/Foo", false);
        expect("directory matches no class",
                "file:/d/", "file:/d/Foo", false);

        // Jar code source.
        expect("bare location matches no class",
                "file:/lib/x.jar", "file:/lib/x.jar/Foo", false);
        expect("recursive grant on a jar matches a class in it",
                "file:/lib/x.jar/-", "file:/lib/x.jar/Foo", true);

        // Named module in the runtime image.
        expect("module grant matches the exact class",
                "jrt:/java.base/java.lang.Object", "jrt:/java.base/java.lang.Object", true);
        expect("module grant does not match another class",
                "jrt:/java.base/java.lang.Object", "jrt:/java.base/java.lang.Objects", false);
        expect("recursive module grant matches a class in the module",
                "jrt:/java.base/-", "jrt:/java.base/java.lang.Object", true);
        expect("module grant for another module does not match",
                "jrt:/java.sql/-", "jrt:/java.base/java.lang.Object", false);

        // Digest-qualified httpmd locations: the digest is part of the path.
        String perClass = "httpmd://h/x.jar;sha1=abc/pkg.Foo";
        expect("grant for the digest matches a class of that digest",
                "httpmd://h/x.jar;sha1=abc/-", perClass, true);
        expect("grant for another digest does not match",
                "httpmd://h/x.jar;sha1=def/-", perClass, false);
        expect("semicolon wildcard matches any digest",
                "httpmd://h/x.jar;-", perClass, true);
        expect("semicolon wildcard for another jar does not match",
                "httpmd://h/y.jar;-", perClass, false);
        expect("digest location on its own matches no class",
                "httpmd://h/x.jar;sha1=abc", perClass, false);
        expect("exact per-class grant matches",
                perClass, perClass, true);

        // Spelling of one location.
        check("escaped and unescaped spellings are one URI",
                Uri.parseAndCreate("file:/a b/x.jar")
                        .equals(Uri.parseAndCreate("file:/a%20b/x.jar")));
        expect("a grant on the escaped spelling matches the unescaped class",
                "file:/a%20b/-", "file:/a b/Foo", true);

        // A null implied URI is never implied.
        check("null is never implied",
                !Uri.parseAndCreate("file:/d/-").implies(null));

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
