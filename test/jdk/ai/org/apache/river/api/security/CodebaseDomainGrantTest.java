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
 * @summary A dynamic grant built with PermissionGrantBuilder.CODEBASE_DOMAIN
 *          applies to each ProtectionDomain of the codebase of the granted
 *          class's loader, including domains created after the grant, and to
 *          no other domain: not to a domain the same loader defines from a
 *          location outside its codebase, not to a second loader over
 *          identical jars, and not to a class loader alone.  Domains rebuilt
 *          by a combiner are covered; principals are honoured; a grant
 *          anchored on a java.lang.reflect.Proxy class uses the loader of the
 *          class, not of its shared domain; a loader that is not a
 *          URLClassLoader limits the grant to the anchor's own domain; a
 *          deserialised grant is void.  Defends SECURITY_MODEL.md's least
 *          privilege guarantee for dynamic grants to verified proxies: the
 *          grant covers the code that was verified (the loader's codebase),
 *          not everything the loader may define.
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @build codebasegrant.ProxyA codebasegrant.ProxyB codebasegrant.Outside codebasegrant.IfaceA
 * @run main/othervm CodebaseDomainGrantTest
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.CodeSource;
import java.security.Permission;
import java.security.Permissions;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.river.api.security.PermissionGrant;
import org.apache.river.api.security.PermissionGrantBuilder;

/**
 * Behavioural reference: JGDMS {@code CodebaseDomainGrantTest} (branch
 * claude/sow-permissiongrant-domain-grants) and items 7, 8 and 13a of
 * "DirtyChai - changes required by the PermissionGrant SOW".  The
 * DynamicPolicyProvider (getGrants) cases of that test are JGDMS-only and
 * are not repeated here.
 *
 * <p>Codebase identity is by location only: a domain at a codebase location
 * with different signers is implied (item 7 rule 2, decision 13a: no
 * pinning).  Item 11 of that document says the opposite in one bullet; item
 * 7 and 13a are the later decision.
 *
 * <p><b>Load-bearing controls, run every time.</b>  The multi-jar checks are
 * run against three grant kinds: the CODEBASE_DOMAIN grant must pass all of
 * them; a CLASSLOADER grant (the old semantics) must fail the "outside the
 * codebase" check; a PROTECTIONDOMAIN grant (the anchor's domain only) must
 * fail the "jar B" checks.  If either control passes, the checks no longer
 * distinguish the required semantics and the test fails.
 *
 * <p>CODEBASE_DOMAIN is read by reflection so the test compiles before the
 * constant exists; its value must be 7, the same as JGDMS's, because it is a
 * compile-time constant inlined into JGDMS bytecode.
 *
 * <p>OBSERVED: not yet recorded.  Expected on trunk af6bc5479 (before items
 * 7 and 8): fails, CODEBASE_DOMAIN absent.
 */
public class CodebaseDomainGrantTest {

    static final Principal[] NONE = new Principal[0];
    static final Permission PERM = new RuntimePermission("ai.codebase.domain.grant");
    static final List<String> failures = new ArrayList<>();

    static File dir;
    static URL jarA, jarB, jarOutside, jarIface;

    public static void main(String[] args) throws Exception {
        Integer codebaseDomain = codebaseDomainConstant();
        if (codebaseDomain == null) {
            throw new RuntimeException("PermissionGrantBuilder.CODEBASE_DOMAIN is absent (items 7 and 8 not implemented)");
        }
        if (codebaseDomain != 7) {
            failures.add("CODEBASE_DOMAIN = " + codebaseDomain + ", must be 7 (JGDMS inlines the value)");
        }
        dir = Files.createTempDirectory(new File(".").toPath(), "codebase-domain").toFile();
        jarA = jar("a.jar", codebasegrant.ProxyA.class);
        jarB = jar("b.jar", codebasegrant.ProxyB.class);
        jarOutside = jar("outside.jar", codebasegrant.Outside.class);
        jarIface = jar("iface.jar", codebasegrant.IfaceA.class);

        // The required semantics, and the two controls.
        List<String> codebase = multiJar(c -> grantTo(c, codebaseDomain));
        for (String f : codebase) failures.add("CODEBASE_DOMAIN: " + f);
        List<String> byLoader = multiJar(c -> grantTo(c, PermissionGrantBuilder.CLASSLOADER));
        if (byLoader.stream().noneMatch(f -> f.startsWith("outside the codebase"))) {
            failures.add("control: a CLASSLOADER grant passed the 'outside the codebase' check,"
                    + " so the check does not distinguish codebase scope from loader scope: " + byLoader);
        }
        List<String> byDomain = multiJar(c -> grantTo(c, PermissionGrantBuilder.PROTECTIONDOMAIN));
        if (byDomain.stream().noneMatch(f -> f.startsWith("jar B"))) {
            failures.add("control: a PROTECTIONDOMAIN grant passed the 'jar B' checks,"
                    + " so they do not distinguish codebase scope from the anchor's domain: " + byDomain);
        }

        signersAtACodebaseLocationNotPinned(codebaseDomain);
        principalsHonoured(codebaseDomain);
        notImpliedByLoaderOrCodeSource(codebaseDomain);
        otherLoaderFallsBackToAnchorDomain(codebaseDomain);
        anchorWithoutLocation(codebaseDomain);
        proxyClassAnchor(codebaseDomain);
        voidAfterSerialization(codebaseDomain);
        nullClassAppliesToAllDomains(codebaseDomain);

        if (!failures.isEmpty()) {
            throw new RuntimeException("CodebaseDomainGrant: " + failures.size() + " failure(s):\n- "
                    + String.join("\n- ", failures));
        }
        System.out.println("PASSED: dynamic grants are scoped to the codebase's domains");
    }

    // ---- multi-jar codebase (T4) -------------------------------------------

    /** Returns the checks the grant made by {@code make} fails, each prefixed by its name. */
    static List<String> multiJar(Function<Class<?>, PermissionGrant> make) throws Exception {
        List<String> f = new ArrayList<>();
        try (Loader loader = new Loader(new URL[] {jarA, jarB})) {
            Class<?> a = loader.loadClass("codebasegrant.ProxyA");
            if (a.getClassLoader() != loader) throw new IllegalStateException("ProxyA not isolated");
            PermissionGrant g = make.apply(a);

            check(f, "jar A", g.implies(a.getProtectionDomain()), true);
            // B's first class is loaded after the grant: its domain did not exist when granted.
            Class<?> b = loader.loadClass("codebasegrant.ProxyB");
            if (b.getProtectionDomain() == a.getProtectionDomain()) throw new IllegalStateException("one domain for two jars");
            check(f, "jar B, first loaded after the grant", g.implies(b.getProtectionDomain()), true);
            ProtectionDomain notYetLoaded = new ProtectionDomain(
                    new CodeSource(jarB, (Certificate[]) null), null, loader, NONE);
            check(f, "jar B, a domain at B's location", g.implies(notYetLoaded), true);

            Class<?> out = loader.define(codebasegrant.Outside.class, jarOutside, null);
            if (out.getClassLoader() != loader) throw new IllegalStateException("Outside not in loader");
            check(f, "outside the codebase, same loader", g.implies(out.getProtectionDomain()), false);

            try (Loader other = new Loader(new URL[] {jarA, jarB})) {
                check(f, "second loader, identical jar A",
                        g.implies(other.loadClass("codebasegrant.ProxyA").getProtectionDomain()), false);
                check(f, "second loader, identical jar B",
                        g.implies(other.loadClass("codebasegrant.ProxyB").getProtectionDomain()), false);
            }

            Principal p = new TestPrincipal("rebuilt");
            ProtectionDomain pa = a.getProtectionDomain();
            check(f, "jar A rebuilt by a combiner", g.implies(new ProtectionDomain(pa.getCodeSource(),
                    pa.getPermissions(), pa.getClassLoader(), new Principal[] {p})), true);
            ProtectionDomain pb = b.getProtectionDomain();
            check(f, "jar B rebuilt by a combiner", g.implies(new ProtectionDomain(pb.getCodeSource(),
                    pb.getPermissions(), pb.getClassLoader(), new Principal[] {p})), true);
        }
        return f;
    }

    // ---- further cases -------------------------------------------------------

    /** A jar can yield several domains (one per signer set); none may make another unreachable. */
    static void signersAtACodebaseLocationNotPinned(int cd) throws Exception {
        try (Loader loader = new Loader(new URL[] {jarA, jarB})) {
            Class<?> a = loader.loadClass("codebasegrant.ProxyA");
            PermissionGrant g = grantTo(a, cd);
            Certificate signer = new FakeCertificate("other");
            ProtectionDomain signedB = new ProtectionDomain(
                    new CodeSource(jarB, new Certificate[] {signer}), null, loader, NONE);
            check(failures, "signed domain at a codebase location", g.implies(signedB), true);
            Class<?> b = loader.loadClass("codebasegrant.ProxyB");
            check(failures, "unsigned domain at the same location, checked second",
                    g.implies(b.getProtectionDomain()), true);
            ProtectionDomain elsewhere = new ProtectionDomain(
                    new CodeSource(jarOutside, new Certificate[] {signer}), null, loader, NONE);
            check(failures, "location outside the codebase, whatever the signers", g.implies(elsewhere), false);
        }
    }

    static void principalsHonoured(int cd) throws Exception {
        try (Loader loader = new Loader(new URL[] {jarA, jarB})) {
            Class<?> a = loader.loadClass("codebasegrant.ProxyA");
            Principal required = new TestPrincipal("required");
            PermissionGrant g = grantTo(a, cd, required);
            ProtectionDomain pa = a.getProtectionDomain();
            check(failures, "principal required, domain has none", g.implies(pa), false);
            check(failures, "principal required, domain has it", g.implies(new ProtectionDomain(
                    pa.getCodeSource(), null, loader, new Principal[] {required})), true);
        }
    }

    static void notImpliedByLoaderOrCodeSource(int cd) throws Exception {
        try (Loader loader = new Loader(new URL[] {jarA, jarB})) {
            Class<?> a = loader.loadClass("codebasegrant.ProxyA");
            PermissionGrant g = grantTo(a, cd);
            check(failures, "implies(ClassLoader) alone", g.implies(loader, NONE), false);
            check(failures, "implies(CodeSource) alone (a dynamic grant applies to domains)",
                    g.implies(a.getProtectionDomain().getCodeSource(), NONE), false);
        }
    }

    static void otherLoaderFallsBackToAnchorDomain(int cd) throws Exception {
        try (NotUrlLoader l = new NotUrlLoader()) {
            Class<?> a = l.define(codebasegrant.ProxyA.class, jarA);
            Class<?> b = l.define(codebasegrant.ProxyB.class, jarB);
            PermissionGrant g = grantTo(a, cd);
            check(failures, "non-URLClassLoader: anchor domain", g.implies(a.getProtectionDomain()), true);
            check(failures, "non-URLClassLoader: another domain of the same loader",
                    g.implies(b.getProtectionDomain()), false);
        }
    }

    static void anchorWithoutLocation(int cd) throws Exception {
        try (NotUrlLoader l = new NotUrlLoader()) {
            Class<?> a = l.define(codebasegrant.ProxyA.class, null);
            PermissionGrant g = grantTo(a, cd);
            ProtectionDomain pa = a.getProtectionDomain();
            check(failures, "anchor whose CodeSource has no location", g.implies(pa), true);
            check(failures, "anchor without location, rebuilt by a combiner",
                    g.implies(new ProtectionDomain(pa.getCodeSource(), null, l, NONE)), true);
        }
    }

    /** Security.grant is usually given proxy.getClass(); a Proxy class has a shared domain. */
    static void proxyClassAnchor(int cd) throws Exception {
        try (Loader l = new Loader(new URL[] {jarA, jarB, jarIface})) {
            Class<?> iface = l.loadClass("codebasegrant.IfaceA");
            Object proxy = Proxy.newProxyInstance(l, new Class<?>[] {iface}, (p, m, args) -> null);
            Class<?> proxyClass = proxy.getClass();
            ClassLoader pdLoader = proxyClass.getProtectionDomain() == null ? null
                    : proxyClass.getProtectionDomain().getClassLoader();
            System.out.println("# proxy class loader " + proxyClass.getClassLoader()
                    + ", its domain's loader " + pdLoader);
            PermissionGrant g = grantTo(proxyClass, cd);
            check(failures, "proxy anchor: jar A",
                    g.implies(l.loadClass("codebasegrant.ProxyA").getProtectionDomain()), true);
            check(failures, "proxy anchor: jar B",
                    g.implies(l.loadClass("codebasegrant.ProxyB").getProtectionDomain()), true);
            check(failures, "proxy anchor: interface jar", g.implies(iface.getProtectionDomain()), true);
            check(failures, "proxy anchor: location outside the codebase", g.implies(new ProtectionDomain(
                    new CodeSource(jarOutside, (Certificate[]) null), null, l, NONE)), false);
            try (Loader other = new Loader(new URL[] {jarA})) {
                check(failures, "proxy anchor: second loader",
                        g.implies(other.loadClass("codebasegrant.ProxyA").getProtectionDomain()), false);
            }
        }
    }

    static void voidAfterSerialization(int cd) throws Exception {
        try (Loader loader = new Loader(new URL[] {jarA, jarB})) {
            Class<?> a = loader.loadClass("codebasegrant.ProxyA");
            PermissionGrant g = grantTo(a, cd);
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            try (ObjectOutputStream oo = new ObjectOutputStream(bo)) {
                oo.writeObject(g);
            }
            Object o;
            try (ObjectInputStream oi = new ObjectInputStream(new ByteArrayInputStream(bo.toByteArray()))) {
                o = oi.readObject();
            }
            if (!(o instanceof PermissionGrant pg)) {
                failures.add("deserialised grant is not a PermissionGrant: " + o);
                return;
            }
            check(failures, "deserialised grant is void", pg.isVoid(), true);
            check(failures, "deserialised grant implies jar A", pg.implies(a.getProtectionDomain()), false);
        } catch (java.io.NotSerializableException e) {
            failures.add("grant could not be serialised through its builder: " + e);
        }
    }

    static void nullClassAppliesToAllDomains(int cd) {
        PermissionGrant g = PermissionGrantBuilder.newBuilder()
                .principals(NONE).permissions(new Permission[] {PERM}).context(cd).build();
        check(failures, "no class given: applies to all domains",
                g.implies(CodebaseDomainGrantTest.class.getProtectionDomain()), true);
    }

    // ---- helpers -------------------------------------------------------------

    static PermissionGrant grantTo(Class<?> c, int context, Principal... pals) {
        return PermissionGrantBuilder.newBuilder()
                .principals(pals).permissions(new Permission[] {PERM})
                .context(context).clazz(c).build();
    }

    static void check(List<String> f, String what, boolean got, boolean expected) {
        if (got != expected) f.add(what + ": implied=" + got + ", expected " + expected);
    }

    static Integer codebaseDomainConstant() {
        try {
            Field fld = PermissionGrantBuilder.class.getField("CODEBASE_DOMAIN");
            return fld.getInt(null);
        } catch (NoSuchFieldException e) {
            return null;
        } catch (IllegalAccessException e) {
            throw new IllegalStateException(e);
        }
    }

    static URL jar(String name, Class<?> c) throws Exception {
        File f = new File(dir, name);
        String res = c.getName().replace('.', '/') + ".class";
        try (JarOutputStream out = new JarOutputStream(new FileOutputStream(f))) {
            out.putNextEntry(new JarEntry(res));
            out.write(bytes(c));
            out.closeEntry();
        }
        return f.toURI().toURL();
    }

    static byte[] bytes(Class<?> c) throws Exception {
        try (InputStream in = CodebaseDomainGrantTest.class.getClassLoader()
                .getResourceAsStream(c.getName().replace('.', '/') + ".class")) {
            return in.readAllBytes();
        }
    }

    /** A URLClassLoader isolated from the test classes that can also define from elsewhere. */
    static final class Loader extends URLClassLoader {
        Loader(URL[] urls) {
            super(urls, ClassLoader.getPlatformClassLoader());
        }

        Class<?> define(Class<?> c, URL location, Certificate[] signers) throws Exception {
            byte[] b = bytes(c);
            return defineClass(c.getName(), b, 0, b.length,
                    new ProtectionDomain(new CodeSource(location, signers), new Permissions(), this, null));
        }
    }

    /** Not a URLClassLoader: the grant cannot learn a codebase from it. */
    static final class NotUrlLoader extends ClassLoader implements AutoCloseable {
        NotUrlLoader() {
            super(ClassLoader.getPlatformClassLoader());
        }

        Class<?> define(Class<?> c, URL location) throws Exception {
            byte[] b = bytes(c);
            return defineClass(c.getName(), b, 0, b.length, new ProtectionDomain(
                    new CodeSource(location, (Certificate[]) null), new Permissions(), this, null));
        }

        @Override
        public void close() {
        }
    }

    static final class TestPrincipal implements Principal {
        private final String name;
        TestPrincipal(String name) { this.name = name; }
        @Override public String getName() { return name; }
        @Override public boolean equals(Object o) { return o instanceof TestPrincipal t && t.name.equals(name); }
        @Override public int hashCode() { return Objects.hash(name); }
        @Override public String toString() { return "TestPrincipal[" + name + "]"; }
    }

    static final class FakeCertificate extends Certificate {
        private static final long serialVersionUID = 1L;
        private final byte[] encoded;
        FakeCertificate(String id) {
            super("fake");
            encoded = id.getBytes(StandardCharsets.UTF_8);
        }
        @Override public byte[] getEncoded() { return encoded.clone(); }
        @Override public void verify(PublicKey key) { }
        @Override public void verify(PublicKey key, String sigProvider) { }
        @Override public String toString() { return "FakeCertificate"; }
        @Override public PublicKey getPublicKey() { return null; }
    }
}
