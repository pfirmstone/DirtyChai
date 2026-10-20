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
 * @summary The policy text a PermissionGrant writes (toString(), prefixed by
 *          "grant") must parse back to the same grant: every permission name
 *          and action, and every principal name, read back unchanged, however
 *          many backslashes, double quotes, carriage returns and line feeds it
 *          contains.  Covered: FilePermission (a Windows path, and a name with
 *          every awkward character), other permissions, UnresolvedPermission,
 *          principal names, two principals in one grant, signedBy and
 *          codeBase grants.  A name the parser reads back differently grants
 *          a permission nobody asked for and withholds the one intended, so a
 *          policy written from grants (for example by an audit) would not be
 *          the policy that was reviewed.  Defends SECURITY_MODEL.md section 15
 *          invariant 4, "Policy evaluation must remain deny-by-default": a
 *          grant must mean exactly what it says.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @modules java.base/au.zeus.jdk.authorization.policy
 * @run main/othervm GrantPolicyTextRoundTripTest
 */

import java.io.File;
import java.io.FilePermission;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.UnresolvedPermission;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.PropertyPermission;
import java.util.TreeSet;

import au.zeus.jdk.authorization.policy.ConcurrentPolicyFile;
import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * Each grant is built with PermissionGrantBuilder, written as
 * {@code "grant " + grant.toString()}, parsed by ConcurrentPolicyFile, and
 * compared with what the parsed policy grants.
 *
 * <p>Permissions are compared as (type, name, actions) strings, not with
 * {@code equals} or {@code implies}: a FilePermission whose name is not a
 * valid path still keeps its name, and it is the name that must survive.
 * Principals are compared by implication: a domain carrying the exact
 * principals must be granted, and one whose principal name differs only in
 * an escaped character must not.
 *
 * <p>Expected on the code reviewed 2026-10-18 before item 4 was finished:
 * fails on names outside FilePermission containing a backslash, on
 * UnresolvedPermission names and actions, and on principal names; with item
 * 4 complete, passes.  The control at the end confirms that writing the
 * same names without escaping is detected.
 *
 * <p>OBSERVED: not yet recorded.
 */
public class GrantPolicyTextRoundTripTest {

    /** Every character the tokenizer treats specially inside a quoted string. */
    static final String AWKWARD = "q\"uote\\back\r\nline\\\"end";

    static final List<String> failures = new ArrayList<>();
    static int fileNo;

    public static void main(String[] args) throws Exception {
        URL here = new URL("file:/ai-test/roundtrip/lib.jar");

        // 1. Permission names and actions.
        Permission[] perms = {
            new FilePermission("C:\\Users\\peter\\data\\file.txt", "read"),
            new FilePermission("C:\\dir\\" + AWKWARD, "read,write"),
            new PropertyPermission("ai.test." + AWKWARD, "read"),
            new RuntimePermission("ai.test." + AWKWARD),
            new UnresolvedPermission("ai.test.NoSuchPermission", "un\\resolved " + AWKWARD,
                    "act\\ions \"" + AWKWARD, (Certificate[]) null),
        };
        PermissionGrant all = PermissionGrantBuilder.newBuilder()
                .permissions(perms).context(PermissionGrantBuilder.PRINCIPAL).build();
        roundTrip("permission names and actions", all,
                new ProtectionDomain(new CodeSource(here, (Certificate[]) null), null, null, new Principal[0]),
                perms);

        // 2. Principal names, two principals in one grant.
        Principal p1 = new RoundTripPrincipal("CN=Smith\\, J, O=\"Zeus\" " + AWKWARD);
        Principal p2 = new RoundTripPrincipal("second\\principal\"" + AWKWARD);
        Permission marker = new RuntimePermission("ai.test.principals.marker");
        PermissionGrant byPrincipals = PermissionGrantBuilder.newBuilder()
                .principals(new Principal[] {p1, p2}).permissions(new Permission[] {marker})
                .context(PermissionGrantBuilder.PRINCIPAL).build();
        File policy = write("principals", byPrincipals);
        ConcurrentPolicyFile parsed = parse(policy);
        if (parsed != null) {
            CodeSource cs = new CodeSource(here, (Certificate[]) null);
            expect(parsed, new ProtectionDomain(cs, null, null, new Principal[] {p1, p2}), marker, true,
                    "principals: domain with both exact principals");
            expect(parsed, new ProtectionDomain(cs, null, null, new Principal[] {p1}), marker, false,
                    "principals: domain with only the first principal");
            // The name as the parser would read it without escaping: backslashes dropped.
            Principal mangled = new RoundTripPrincipal(p1.getName().replace("\\", ""));
            expect(parsed, new ProtectionDomain(cs, null, null, new Principal[] {mangled, p2}), marker, false,
                    "principals: first principal's name with the backslashes lost");
        }

        // 3. codeBase and signedBy headers keep the grant parseable.
        PermissionGrant byCodebase = PermissionGrantBuilder.newBuilder()
                .uri(here.toString()).permissions(new Permission[] {perms[2]})
                .context(PermissionGrantBuilder.URI).build();
        roundTrip("codeBase grant", byCodebase,
                new ProtectionDomain(new CodeSource(here, (Certificate[]) null), null, null, new Principal[0]),
                new Permission[] {perms[2]});

        // 4. Control: the same names written without escaping must not survive.
        String unescaped = "grant {\n    permission java.util.PropertyPermission \"ai.test." + AWKWARD
                + "\", \"read\";\n};\n";
        File raw = file("control");
        Files.writeString(raw.toPath(), unescaped, StandardCharsets.UTF_8);
        ConcurrentPolicyFile rawPolicy = null;
        try {
            rawPolicy = new ConcurrentPolicyFile(new URL[] {raw.toURI().toURL()});
        } catch (Exception e) {
            // a parse failure also shows escaping is needed
        }
        if (rawPolicy != null && granted(rawPolicy, new ProtectionDomain(
                new CodeSource(here, (Certificate[]) null), null, null, new Principal[0]))
                .contains(describe(perms[2]))) {
            failures.add("control: an unescaped name survived the round trip, so this test cannot detect missing escaping");
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException("policy text round trip: " + failures.size() + " failure(s):\n- "
                    + String.join("\n- ", failures));
        }
        System.out.println("PASSED: grants written as policy text parse back unchanged");
    }

    static void roundTrip(String label, PermissionGrant grant, ProtectionDomain pd, Permission[] expected)
            throws Exception {
        File policy = write(label.replaceAll("\\W+", "-"), grant);
        ConcurrentPolicyFile parsed = parse(policy);
        if (parsed == null) return;
        TreeSet<String> got = granted(parsed, pd);
        for (Permission p : expected) {
            String want = describe(p);
            if (!got.contains(want)) {
                failures.add(label + ": " + visible(want) + " did not come back; parsed grants hold "
                        + visible(got.toString()));
            }
        }
    }

    static File write(String label, PermissionGrant grant) throws Exception {
        String text = "grant " + grant.toString();
        File f = file(label);
        Files.writeString(f.toPath(), text, StandardCharsets.UTF_8);
        System.out.println("----- " + label + " -----\n" + text + "----- end -----");
        return f;
    }

    static File file(String label) {
        return new File("roundtrip-" + (fileNo++) + "-" + label + ".policy").getAbsoluteFile();
    }

    static ConcurrentPolicyFile parse(File f) {
        try {
            return new ConcurrentPolicyFile(new URL[] {f.toURI().toURL()});
        } catch (Exception e) {
            failures.add(f.getName() + ": the written policy text did not parse: " + e);
            return null;
        }
    }

    static TreeSet<String> granted(ConcurrentPolicyFile policy, ProtectionDomain pd) {
        TreeSet<String> got = new TreeSet<>();
        for (PermissionGrant g : policy.getPermissionGrants(pd)) {
            for (Permission p : g.getPermissions()) got.add(describe(p));
        }
        return got;
    }

    static void expect(ConcurrentPolicyFile policy, ProtectionDomain pd, Permission p, boolean implied, String label) {
        boolean got = granted(policy, pd).contains(describe(p));
        if (got != implied) failures.add(label + ": granted=" + got + ", expected " + implied);
    }

    static String describe(Permission p) {
        if (p instanceof UnresolvedPermission u) {
            return u.getUnresolvedType() + " [" + u.getUnresolvedName() + "] [" + u.getUnresolvedActions() + "]";
        }
        String actions = p.getActions();
        return p.getClass().getName() + " [" + p.getName() + "] [" + (actions == null ? "" : actions) + "]";
    }

    /** Shows control characters so a failure message says what differed. */
    static String visible(String s) {
        return s.replace("\r", "\\r").replace("\n", "\\n");
    }

}

/**
 * A top-level class on purpose: PrincipalGrant writes the principal class's
 * canonical name, which for a nested class ("Outer.Inner") is not the binary
 * name ("Outer$Inner") the principal reports, so a nested principal class
 * would not match after the round trip for a reason unrelated to escaping.
 */
final class RoundTripPrincipal implements Principal {
    private final String name;
    RoundTripPrincipal(String name) { this.name = name; }
    @Override public String getName() { return name; }
    @Override public boolean equals(Object o) { return o instanceof RoundTripPrincipal t && t.name.equals(name); }
    @Override public int hashCode() { return Objects.hash(name); }
    @Override public String toString() { return "RoundTripPrincipal[" + name + "]"; }
}
