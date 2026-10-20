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
 * @summary A PROTECTIONDOMAIN dynamic grant applies to a domain rebuilt by a
 *          combiner (same loader, new principals) only when the rebuilt
 *          domain's code source has the anchor's identity: Uri, signers and
 *          digest, the identity SecureClassLoader keys its domains by
 *          (CodeSourceKey).  A rebuilt domain with different content (digest),
 *          a plain code source where the anchor had a digest or the reverse,
 *          or signers where the anchor was unsigned, is not implied; equal
 *          code sources, including locations that differ only in escaping,
 *          are.  Defends SECURITY_MODEL.md "Dynamic grants to proxies": the
 *          grant is made to the code that was verified, so it must not
 *          extend to other code that happens to share the loader and
 *          location.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main/othervm ProtectionDomainGrantIdentityTest
 */

import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.Permission;
import java.security.Permissions;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * Item 6 of "DirtyChai - changes required by the PermissionGrant SOW":
 * ProtectionDomainGrant.impliesCodeSource compares code-source identity as
 * Uri + signers + digest (CodeSourceKey) instead of URL.toURI() and
 * Arrays.equals on the certificates only when the anchor has some.
 *
 * <p>Each case defines a class in a fresh loader with a chosen anchor code
 * source, grants to that class with the PROTECTIONDOMAIN context, and asks
 * whether a domain of the same loader, rebuilt with a principal (as
 * SubjectDomainCombiner does) and a given code source, is implied.  The
 * rebuilt domain is never the anchor instance, so the decision is made by
 * the loader and code-source comparison, not by the reference fast path.
 * The grant requires no principals.
 *
 * <p>Controls, run every time: a domain rebuilt with the anchor's own
 * CodeSource instance must be implied (otherwise the rebuilt-domain path is
 * not being reached at all), and a domain of a different loader with an
 * equal code source must not be.
 *
 * <p>Expected on the code reviewed on 2026-10-18 (impliesCodeSource via
 * URL.toURI(), digest ignored, signers compared only when the anchor has
 * some): 5 failures, the cases marked "item 6" below; the others pass.
 *
 * <p>OBSERVED: not yet recorded.
 */
public class ProtectionDomainGrantIdentityTest {

    static final String HERE = "file:/ai-test/pdgrant/lib.jar";
    static final String ELSEWHERE = "file:/ai-test/pdgrant/moved.jar";
    static final String SPACED = "file:/ai-test/pd grant/lib.jar";
    static final String ESCAPED = "file:/ai-test/pd%20grant/lib.jar";
    static final byte[] DIGEST = HexFormat.of().parseHex(
            "e9014d28d14a23318909c0957b3be984f9ae496b80af1ae3a973436dcbde772b");
    static final byte[] OTHER_DIGEST = HexFormat.of().parseHex(
            "0000000000000000000000000000000000000000000000000000000000000001");
    static final Permission PERM = new RuntimePermission("ai.pdgrant.identity");
    static final Principal[] NONE = new Principal[0];
    static final Principal REBUILT = new TestPrincipal("rebuilt");
    static final Certificate[] ALICE = {new FakeCertificate("alice")};
    static final Certificate[] BOB = {new FakeCertificate("bob")};

    static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        // Controls.
        try (Anchor a = new Anchor(plain(HERE))) {
            expect("control: rebuilt with the anchor's own CodeSource instance",
                    a, rebuilt(a, a.cs), true);
            try (Anchor other = new Anchor(plain(HERE))) {
                expect("control: different loader, equal CodeSource", a,
                        new ProtectionDomain(plain(HERE), null, other, new Principal[] {REBUILT}), false);
            }
        }

        // Equal identity: implied.
        try (Anchor a = new Anchor(plain(HERE))) {
            expect("plain, equal CodeSource (distinct instance)", a, rebuilt(a, plain(HERE)), true);
        }
        try (Anchor a = new Anchor(digest(HERE, null, DIGEST))) {
            expect("digest, equal DigestCodeSource (distinct instance)", a,
                    rebuilt(a, digest(HERE, null, DIGEST)), true);
        }
        try (Anchor a = new Anchor(signed(HERE, ALICE))) {
            expect("signed alice, equal signers (distinct array)", a,
                    rebuilt(a, signed(HERE, new Certificate[] {new FakeCertificate("alice")})), true);
        }
        try (Anchor a = new Anchor(plain(SPACED))) {
            expect("item 6: location differing only in escaping (Uri normalisation)", a,
                    rebuilt(a, plain(ESCAPED)), true);
        }

        // Different identity, already refused before item 6.
        try (Anchor a = new Anchor(plain(HERE))) {
            expect("different location", a, rebuilt(a, plain(ELSEWHERE)), false);
        }
        try (Anchor a = new Anchor(signed(HERE, ALICE))) {
            expect("anchor signed alice, rebuilt signed bob", a, rebuilt(a, signed(HERE, BOB)), false);
            expect("anchor signed alice, rebuilt unsigned", a, rebuilt(a, plain(HERE)), false);
        }
        try (Anchor a = new Anchor(digest(HERE, null, DIGEST))) {
            expect("digest, same content at a different location", a,
                    rebuilt(a, digest(ELSEWHERE, null, DIGEST)), false);
        }

        // Different identity, refused only after item 6.
        try (Anchor a = new Anchor(digest(HERE, null, DIGEST))) {
            expect("item 6: digest, different content at the same location", a,
                    rebuilt(a, digest(HERE, null, OTHER_DIGEST)), false);
            expect("item 6: anchor digest, rebuilt plain CodeSource", a, rebuilt(a, plain(HERE)), false);
        }
        try (Anchor a = new Anchor(plain(HERE))) {
            expect("item 6: anchor plain, rebuilt DigestCodeSource", a,
                    rebuilt(a, digest(HERE, null, DIGEST)), false);
            expect("item 6: anchor unsigned, rebuilt signed alice", a, rebuilt(a, signed(HERE, ALICE)), false);
        }

        if (!failures.isEmpty()) {
            throw new RuntimeException("ProtectionDomainGrant identity: " + failures.size() + " failure(s):\n- "
                    + String.join("\n- ", failures));
        }
        System.out.println("PASSED: rebuilt domains are matched by Uri + signers + digest");
    }

    // ---- helpers -------------------------------------------------------------

    static void expect(String what, Anchor a, ProtectionDomain candidate, boolean expected) {
        if (candidate == a.domain) throw new IllegalStateException(what + ": candidate is the anchor");
        try {
            boolean got = a.grant.implies(candidate);
            if (got != expected) {
                failures.add(what + ": implied=" + got + ", expected " + expected
                        + " (anchor " + describe(a.cs) + ", rebuilt " + describe(candidate.getCodeSource()) + ")");
            }
        } catch (RuntimeException e) {
            failures.add(what + ": implies threw " + e);
        }
    }

    static ProtectionDomain rebuilt(Anchor a, CodeSource cs) {
        return new ProtectionDomain(cs, null, a, new Principal[] {REBUILT});
    }

    static CodeSource plain(String url) throws Exception {
        return new CodeSource(new URL(url), (Certificate[]) null);
    }

    static CodeSource signed(String url, Certificate[] certs) throws Exception {
        return new CodeSource(new URL(url), certs);
    }

    static CodeSource digest(String url, Certificate[] certs, byte[] d) throws Exception {
        return new DigestCodeSource(url, certs, "SHA-256", d.clone());
    }

    static String describe(CodeSource cs) {
        if (cs == null) return "null";
        Certificate[] c = cs.getCertificates();
        return (cs instanceof DigestCodeSource ? "digest " : "plain ") + cs.getLocation()
                + (c == null || c.length == 0 ? " unsigned" : " signed " + c[0]);
    }

    /**
     * A loader holding one class, defined with the anchor code source; the
     * grant is made to that class.  The loader keeps the class, and so the
     * anchor domain the grant weakly references, reachable.
     */
    static final class Anchor extends ClassLoader implements AutoCloseable {
        final CodeSource cs;
        final Class<?> clazz;
        final ProtectionDomain domain;
        final PermissionGrant grant;

        Anchor(CodeSource cs) throws Exception {
            super(ClassLoader.getPlatformClassLoader());
            this.cs = cs;
            byte[] b;
            String res = Target.class.getName().replace('.', '/') + ".class";
            try (InputStream in = ProtectionDomainGrantIdentityTest.class.getClassLoader()
                    .getResourceAsStream(res)) {
                b = in.readAllBytes();
            }
            clazz = defineClass(Target.class.getName(), b, 0, b.length,
                    new ProtectionDomain(cs, new Permissions(), this, null));
            domain = clazz.getProtectionDomain();
            if (domain.getClassLoader() != this || domain.getCodeSource() != cs) {
                throw new IllegalStateException("anchor domain not as defined: " + domain);
            }
            grant = PermissionGrantBuilder.newBuilder()
                    .principals(NONE).permissions(new Permission[] {PERM})
                    .context(PermissionGrantBuilder.PROTECTIONDOMAIN).clazz(clazz).build();
            if (!grant.implies(domain)) {
                throw new IllegalStateException("grant does not imply its own anchor domain: " + grant);
            }
        }

        @Override
        public void close() {
        }
    }

    /** The class each Anchor defines; never used through the test's own loader. */
    static final class Target {
    }

    static final class TestPrincipal implements Principal {
        private final String name;
        TestPrincipal(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public boolean equals(Object o) { return o instanceof TestPrincipal t && t.name.equals(name); }
        @Override public int hashCode() { return Objects.hash(name); }
        @Override public String toString() { return "TestPrincipal[" + name + "]"; }
    }

    /** Certificate.equals compares encodings, so two instances with one id are equal. */
    static final class FakeCertificate extends Certificate {
        private static final long serialVersionUID = 1L;
        private final String id;
        FakeCertificate(String id) {
            super("fake");
            this.id = id;
        }
        @Override public byte[] getEncoded() { return id.getBytes(StandardCharsets.UTF_8); }
        @Override public void verify(PublicKey key) { }
        @Override public void verify(PublicKey key, String sigProvider) { }
        @Override public String toString() { return "FakeCertificate[" + id + "]"; }
        @Override public PublicKey getPublicKey() { return null; }
    }
}
