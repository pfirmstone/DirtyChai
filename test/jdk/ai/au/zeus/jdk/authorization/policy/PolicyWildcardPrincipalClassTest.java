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
 * @summary A policy file whose "principal" entry has a wildcard CLASS
 *          ("principal * *", "principal * \"CN=alice\"") must be refused
 *          with a syntax error that says a wildcard is not allowed, instead
 *          of loading as a grant that silently matches nothing.  Only the
 *          principal NAME may be "*", and only with an explicit class.  A
 *          class wildcard matched every principal, which a deployer cannot
 *          scope, and polpAudit records the actual principal class, so a
 *          generated policy never needs it (operator decision 2026-11-01).
 *          The invariant is the conjunctive principal matching of
 *          SECURITY_MODEL.md section 10.1: each listed principal must be
 *          matched exactly in class.  Failing at parse time follows the
 *          fail-secure rule of the same document (a validation failure
 *          yields no privilege), and a dead grant that the author believes
 *          is live is a misconfiguration that is only found in production.
 *          This test fails on a tree whose scanner accepts a class wildcard,
 *          and on one that refuses it with the generic "Expected syntax"
 *          message that does not mention the wildcard.
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules java.base/au.zeus.jdk.authorization.policy
 * @run main/othervm PolicyWildcardPrincipalClassTest
 */

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collection;
import java.util.Properties;

import au.zeus.jdk.authorization.policy.DefaultPolicyParser;
import org.apache.river.api.security.PermissionGrant;

/**
 * Drives the public entry point DefaultPolicyParser.parse(URL, Properties)
 * with policy text written to a temporary file; the scanner is package-private
 * and is reached only through the parser.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * Each mutation is applied to a scratch copy of DefaultPolicyScanner and
 * Messages (compiled with --patch-module java.base=..., the source tree is
 * not touched), the test is run, and the failing checks are recorded.
 * <ol>
 * <li>M0: the scanner as committed before the fix (trunk 91737c79880 plus
 *     the maintainer's UnresolvedPrincipal change): a class wildcard is
 *     accepted.
 *     EXPECTED: the three "must be refused" checks fail.
 *     OBSERVED (2026-11-01, scratch --patch-module copy of the scanner from
 *     git HEAD): exactly those three checks failed, "3 check(s) failed".</li>
 * <li>M1: the fix with the generic message "Expected syntax is : principal
 *     [class_name] ...", which does not mention the wildcard.
 *     EXPECTED: the three message checks fail.
 *     OBSERVED: the three message checks failed, "3 check(s) failed"; the
 *     image built at 19:16 on 2026-11-01, which still carries the generic
 *     message, gives the same result.</li>
 * <li>M2: the fix as in the working tree on 2026-11-01 (message
 *     security.92, "Wildcard not allowed. ...").
 *     EXPECTED: every check passes.
 *     OBSERVED: PASSED (scratch --patch-module copy of the working-tree
 *     DefaultPolicyScanner and Messages).</li>
 * <li>M3: the scanner refuses every "*" token in the principal entry,
 *     including the name.
 *     EXPECTED: "exact class with a wildcard name still loads" fails.
 *     OBSERVED: "exact class with a wildcard name still loads one grant"
 *     failed, "1 check(s) failed".</li>
 * </ol>
 */
public class PolicyWildcardPrincipalClassTest {

    private static int failures;

    private static final String PERMISSION =
            " { permission java.util.PropertyPermission \"x\", \"read\"; };";

    public static void main(String[] args) throws Exception {
        refused("principal * *", "grant principal * *" + PERMISSION);
        refused("principal * \"CN=alice\"",
                "grant principal * \"CN=alice\"" + PERMISSION);
        refused("wildcard class as the second principal",
                "grant principal javax.security.auth.x500.X500Principal \"CN=a\","
                + " principal * *" + PERMISSION);

        // Only the name may be a wildcard, with an explicit class.
        loads("exact class with a wildcard name still loads one grant",
                "grant principal javax.security.auth.x500.X500Principal *" + PERMISSION);
        loads("exact class and exact name still load one grant",
                "grant principal javax.security.auth.x500.X500Principal \"CN=alice\""
                + PERMISSION);

        if (failures > 0) {
            throw new RuntimeException(failures + " check(s) failed, see output");
        }
        System.out.println("PASSED");
    }

    private static void loads(String what, String policy) {
        try {
            check(what, parse(policy).size() == 1);
        } catch (Exception e) {
            check(what + ", but parsing failed: " + e.getMessage(), false);
        }
    }

    private static void refused(String what, String policy) throws Exception {
        try {
            Collection<PermissionGrant> grants = parse(policy);
            check(what + ": must be refused, but loaded " + grants.size() + " grant(s)", false);
        } catch (Exception e) {
            String m = String.valueOf(e.getMessage());
            check(what + ": the error must say a wildcard is not allowed, but was: " + m,
                    m.toLowerCase().contains("wildcard"));
        }
    }

    private static Collection<PermissionGrant> parse(String policy) throws Exception {
        File f = File.createTempFile("wildcard-principal", ".policy");
        try {
            Files.write(f.toPath(), policy.getBytes(StandardCharsets.UTF_8));
            return new DefaultPolicyParser().parse(f.toURI().toURL(), new Properties());
        } finally {
            f.delete();
        }
    }

    private static void check(String what, boolean ok) {
        if (!ok) {
            failures++;
            System.out.println("FAIL: " + what);
        }
    }
}
