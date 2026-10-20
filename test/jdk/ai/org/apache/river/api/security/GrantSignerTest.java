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
 * @summary A grant that names signers must apply only to code signed by them.
 *          Checked for every grant kind that carries certificates: signedBy
 *          alone (CertificateGrant), codeBase plus signedBy (URIGrant), and
 *          digest plus signedBy (DigestGrant), through the public
 *          PermissionGrantBuilder API, and for a policy file whose signedBy
 *          alias is not in the keystore.  Unsigned code, code signed by
 *          someone else, and a null CodeSource must not be implied, without
 *          throwing; a grant with no signers must still imply unsigned code;
 *          a digest grant must ignore the location but not the signers.
 *          Defends the principle that a signedBy constraint is part of the
 *          identity the grant is made to: dropping it widens the grant to
 *          anyone who can present the location or the content.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @library /test/lib
 * @modules java.base/au.zeus.jdk.authorization.policy
 * @run main/othervm GrantSignerTest
 */

import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.KeyStore;
import java.security.Permission;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.PropertyPermission;

import au.zeus.jdk.authorization.policy.ConcurrentPolicyFile;
import jdk.test.lib.SecurityTools;
import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * <p>Two self-signed certificates, alice and bob, are generated with keytool
 * into a JKS keystore (JKS so the policy parser can read the certificates
 * without a password).
 *
 * <p>Expected on the code reviewed on 2026-10-18 (impliesSigners added to
 * CertificateGrant and DigestGrant only): the URIGrant cases fail, because
 * URIGrant.implies(CodeSource, Principal[]) matches the location alone and
 * URIGrant.implies(ClassLoader, Principal[]) returns true for an empty
 * location whatever the signers.
 *
 * <p>OBSERVED 2026-10-18, against an image whose URIGrant predated the fix:
 * 5 failures, exactly the URIGrant cases above (codeBase + signedBy alice
 * implied unsigned and bob-signed code; implies(ClassLoader) true with
 * signedBy). The CertificateGrant, DigestGrant and unresolved-alias cases
 * passed. After rebuilding with URIGrant calling impliesSigners and
 * returning false from implies(ClassLoader) when it has certificates:
 * passed.
 */
public class GrantSignerTest {

    static final String HERE = "file:/ai-test/signer/lib.jar";
    static final String ELSEWHERE = "file:/ai-test/moved/lib.jar";
    static final byte[] DIGEST = HexFormat.of().parseHex(
            "e9014d28d14a23318909c0957b3be984f9ae496b80af1ae3a973436dcbde772b");
    static final byte[] OTHER_DIGEST = HexFormat.of().parseHex(
            "0000000000000000000000000000000000000000000000000000000000000001");
    static final Permission PERM = new PropertyPermission("ai.test.signer", "read");

    static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        File ks = new File("signers.jks");
        ks.delete();
        for (String alias : new String[] {"alice", "bob"}) {
            SecurityTools.keytool("-genkeypair -keystore " + ks.getPath() + " -storetype JKS"
                    + " -storepass changeit -keypass changeit -alias " + alias
                    + " -dname CN=" + alias + " -keyalg EC -validity 2")
                    .shouldHaveExitValue(0);
        }
        KeyStore store = KeyStore.getInstance(ks, "changeit".toCharArray());
        Certificate[] alice = {store.getCertificate("alice")};
        Certificate[] bob = {store.getCertificate("bob")};

        builderGrants(alice, bob);
        unresolvedAlias(ks, alice);

        if (!failures.isEmpty()) {
            throw new RuntimeException("signer checks: " + failures.size() + " failure(s):\n- "
                    + String.join("\n- ", failures));
        }
        System.out.println("PASSED: signers are enforced by every grant kind");
    }

    // --- PermissionGrantBuilder grants ------------------------------------

    static void builderGrants(Certificate[] alice, Certificate[] bob) throws Exception {
        CodeSource unsigned = new CodeSource(new URL(HERE), (Certificate[]) null);
        CodeSource byAlice = new CodeSource(new URL(HERE), alice);
        CodeSource byBob = new CodeSource(new URL(HERE), bob);

        // signedBy only: CertificateGrant
        PermissionGrant certs = PermissionGrantBuilder.newBuilder()
                .certificates(alice, new String[] {"alice"})
                .permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.CODESOURCE_CERTS).build();
        expect("signedBy alice", certs, byAlice, true);
        expect("signedBy alice", certs, unsigned, false);
        expect("signedBy alice", certs, byBob, false);
        expect("signedBy alice", certs, null, false);
        expectClassLoader("signedBy alice", certs, false);

        // codeBase + signedBy: URIGrant
        PermissionGrant uri = PermissionGrantBuilder.newBuilder()
                .uri(HERE).certificates(alice, new String[] {"alice"})
                .permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.URI).build();
        expect("codeBase + signedBy alice", uri, byAlice, true);
        expect("codeBase + signedBy alice", uri, unsigned, false);
        expect("codeBase + signedBy alice", uri, byBob, false);
        expect("codeBase + signedBy alice", uri, null, false);

        // signedBy with an empty location: URIGrant must not imply a class loader
        PermissionGrant uriNoLocation = PermissionGrantBuilder.newBuilder()
                .certificates(alice, new String[] {"alice"})
                .permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.URI).build();
        expectClassLoader("URIGrant, no codeBase, signedBy alice", uriNoLocation, false);

        // codeBase only: still implies unsigned code at that location
        PermissionGrant uriUnsigned = PermissionGrantBuilder.newBuilder()
                .uri(HERE).permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.URI).build();
        expect("codeBase only", uriUnsigned, unsigned, true);

        // digest + signedBy: DigestGrant
        DigestCodeSource dAlice = new DigestCodeSource(HERE, alice, "SHA-256", DIGEST.clone());
        DigestCodeSource dUnsigned = new DigestCodeSource(HERE, (Certificate[]) null, "SHA-256", DIGEST.clone());
        DigestCodeSource dBob = new DigestCodeSource(HERE, bob, "SHA-256", DIGEST.clone());
        DigestCodeSource dAliceMoved = new DigestCodeSource(ELSEWHERE, alice, "SHA-256", DIGEST.clone());
        DigestCodeSource dAliceOther = new DigestCodeSource(HERE, alice, "SHA-256", OTHER_DIGEST.clone());
        PermissionGrant digest = PermissionGrantBuilder.newBuilder()
                .uri(HERE).certificates(alice, new String[] {"alice"})
                .digest("SHA-256", DIGEST.clone())
                .permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.DIGEST).build();
        expect("digest + signedBy alice", digest, dAlice, true);
        expect("digest + signedBy alice", digest, dUnsigned, false);
        expect("digest + signedBy alice", digest, dBob, false);
        expect("digest + signedBy alice (moved: location ignored)", digest, dAliceMoved, true);
        expect("digest + signedBy alice (different content)", digest, dAliceOther, false);
        expect("digest + signedBy alice (plain CodeSource)", digest, byAlice, false);
        expect("digest + signedBy alice", digest, null, false);

        // digest only: still implies unsigned code with that content
        PermissionGrant digestUnsigned = PermissionGrantBuilder.newBuilder()
                .uri(HERE).digest("SHA-256", DIGEST.clone())
                .permissions(new Permission[] {PERM})
                .context(PermissionGrantBuilder.DIGEST).build();
        expect("digest only", digestUnsigned, dUnsigned, true);
    }

    static void expect(String grant, PermissionGrant g, CodeSource cs, boolean implied) {
        String who = cs == null ? "null CodeSource"
                : (cs instanceof DigestCodeSource ? "DigestCodeSource " : "CodeSource ")
                  + cs.getLocation() + signers(cs);
        try {
            boolean got = g.implies(cs, new Principal[0]);
            if (got != implied) {
                failures.add(grant + ": implies(" + who + ") = " + got + ", expected " + implied);
            }
            if (cs != null) {
                boolean viaDomain = g.implies(new ProtectionDomain(cs, null));
                if (viaDomain != implied) {
                    failures.add(grant + ": implies(ProtectionDomain(" + who + ")) = " + viaDomain
                            + ", expected " + implied);
                }
            }
        } catch (RuntimeException e) {
            failures.add(grant + ": implies(" + who + ") threw " + e);
        }
    }

    static void expectClassLoader(String grant, PermissionGrant g, boolean implied) {
        try {
            boolean got = g.implies(GrantSignerTest.class.getClassLoader(), new Principal[0]);
            if (got != implied) {
                failures.add(grant + ": implies(ClassLoader) = " + got + ", expected " + implied
                        + " (a class loader carries no signers)");
            }
        } catch (RuntimeException e) {
            failures.add(grant + ": implies(ClassLoader) threw " + e);
        }
    }

    static String signers(CodeSource cs) {
        Certificate[] c = cs.getCertificates();
        if (c == null || c.length == 0) return " (unsigned)";
        String s = c[0].toString();
        int cn = s.indexOf("CN=");
        return " (signed " + (cn >= 0 ? s.substring(cn, Math.min(s.length(), s.indexOf(',', cn) > 0 ? s.indexOf(',', cn) : cn + 8)) : "?") + ")";
    }

    // --- policy file with an unresolved alias -----------------------------

    static void unresolvedAlias(File ks, Certificate[] alice) throws Exception {
        File policyFile = new File("signers.policy");
        String ksUrl = ks.getCanonicalFile().toURI().toString();
        Files.writeString(policyFile.toPath(),
                "keystore \"" + ksUrl + "\", \"JKS\";\n"
                + "grant signedBy \"nosuch\" {\n"
                + "    permission java.util.PropertyPermission \"ai.test.signer.unresolved\", \"read\";\n"
                + "};\n"
                + "grant signedBy \"alice\" {\n"
                + "    permission java.util.PropertyPermission \"ai.test.signer.alice\", \"read\";\n"
                + "};\n",
                StandardCharsets.UTF_8);
        Policy policy;
        try {
            policy = new ConcurrentPolicyFile(new URL[] {policyFile.getCanonicalFile().toURI().toURL()});
        } catch (Exception e) {
            failures.add("policy with an unresolved signedBy alias failed to load: " + e);
            return;
        }
        Permission unresolved = new PropertyPermission("ai.test.signer.unresolved", "read");
        Permission aliceOnly = new PropertyPermission("ai.test.signer.alice", "read");
        ProtectionDomain unsignedPd = new ProtectionDomain(new CodeSource(new URL(HERE), (Certificate[]) null), null);
        ProtectionDomain alicePd = new ProtectionDomain(new CodeSource(new URL(HERE), alice), null);
        policyExpect(policy, unsignedPd, unresolved, false, "unresolved alias, unsigned code");
        policyExpect(policy, alicePd, unresolved, false, "unresolved alias, code signed by alice");
        policyExpect(policy, unsignedPd, aliceOnly, false, "signedBy alice, unsigned code");
        // Control: the keystore was read, so a resolved alias does grant.
        policyExpect(policy, alicePd, aliceOnly, true, "signedBy alice, code signed by alice");
    }

    static void policyExpect(Policy policy, ProtectionDomain pd, Permission p, boolean implied, String label) {
        try {
            boolean got = policy.implies(pd, p);
            if (got != implied) {
                failures.add("policy file, " + label + ": implies(" + p + ") = " + got + ", expected " + implied
                        + (got && !implied && label.startsWith("unresolved")
                           ? " (an unresolved signedBy alias must grant nothing, not everything)" : ""));
            }
        } catch (RuntimeException e) {
            failures.add("policy file, " + label + ": implies threw " + e);
        }
    }
}
