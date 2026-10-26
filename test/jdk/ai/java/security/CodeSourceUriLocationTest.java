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
 * @summary CodeSource and DomainIdentity compare by RFC 3986 URI, without
 *          name service lookups, and keep doing so across serialization.
 *          Two code sources with the same location are equal and hash
 *          alike; different locations are unequal; a code source with no
 *          location has no URI and is equal only to another without one; a
 *          code source that is serialized and read back has its URI
 *          rebuilt, so it still equals the original and a deserialized
 *          code source is never silently equal to every other deserialized
 *          one.  A domain built from a code source with no location is
 *          valid and compares like any other.
 *          Defends SECURITY_MODEL.md section 4 guarantee 6, "URI-validated
 *          code source matching", and section 15 invariant 5, "Validation
 *          failures must remain fail-secure".
 * @author Claude Sonnet 5.5 (claude-sonnet-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 * @run main CodeSourceUriLocationTest
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.DomainIdentity;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;

/**
 * CodeSource.equals and hashCode compare the RFC 3986 URI, not the URL, so
 * that comparing code sources never resolves host names.  If the URI is not
 * set, because a constructor failed to build it or because deserialization
 * did not rebuild it, every code source without a URI compares equal to every
 * other, whatever its URL.  Equal grants and cache hits would then be
 * handed to code from the wrong place.
 *
 * <h2>Negative controls (AI_POLICY.md 5.3)</h2>
 * A mutation marked OBSERVED was applied to a copy of the named class, loaded
 * with --patch-module over the built tierAI JDK, and the test was run; the
 * source tree was not modified.  A mutation marked "not run" has not been
 * applied, and nothing is claimed for it.
 *
 * <ol>
 * <li>M1: remove the lines in readObject that rebuild locationUri.
 *     OBSERVED: five checks FAIL - "serialization: URI is rebuilt", "round trip
 *     is equal", "round trip hashes alike", "different locations stay
 *     unequal" and "no location is unequal to a location".</li>
 * <li>M2: in DomainIdentity.UriCodeSource, throw when the URI is null.
 *     OBSERVED: one check FAILS - "domain: no-location code source is
 *     accepted".</li>
 * <li>M3: leave locationUri null in the constructors.
 *     attempted and unusable: the JDK itself fails to load its main class, so
 *     there is no test result to record.</li>
 * <li>M4: compare only the URI path in equals.
 *     not run.</li>
 * </ol>
 */
public class CodeSourceUriLocationTest {

    private static int failures;

    public static void main(String[] args) throws Exception {
        Certificate[] noCerts = null;
        CodeSigner[] noSigners = null;

        URL one = new URL("file:/CodeSourceUriLocationTest/one.jar");
        URL oneAgain = new URL("file:/CodeSourceUriLocationTest/one.jar");
        URL two = new URL("file:/CodeSourceUriLocationTest/two.jar");
        URL hostA = new URL("http://a.invalid/CodeSourceUriLocationTest/x.jar");
        URL hostB = new URL("http://b.invalid/CodeSourceUriLocationTest/x.jar");

        CodeSource csOne = new CodeSource(one, noCerts);
        CodeSource csOneAgain = new CodeSource(oneAgain, noCerts);
        CodeSource csTwo = new CodeSource(two, noCerts);
        CodeSource csNone = new CodeSource(null, noCerts);
        CodeSource csNoneAgain = new CodeSource(null, noCerts);

        check("URI is set for a code source with a location",
                csOne.getUriLocation() != null);
        check("URI is null for a code source with no location",
                csNone.getUriLocation() == null);
        check("location URL is kept unchanged",
                csOne.getLocation().toString().equals(one.toString()));

        check("same location is equal", csOne.equals(csOneAgain));
        check("same location hashes alike", csOne.hashCode() == csOneAgain.hashCode());
        check("different locations are unequal", !csOne.equals(csTwo));
        check("different hosts are unequal", !new CodeSource(hostA, noCerts)
                .equals(new CodeSource(hostB, noCerts)));
        check("no location is equal to no location", csNone.equals(csNoneAgain));
        check("no location is unequal to a location", !csNone.equals(csOne));
        check("a location is unequal to no location", !csOne.equals(csNone));

        CodeSource signersOne = new CodeSource(one, noSigners);
        CodeSource signersTwo = new CodeSource(two, noSigners);
        check("signers constructor: URI is set", signersOne.getUriLocation() != null);
        check("signers constructor: same location is equal",
                signersOne.equals(new CodeSource(oneAgain, noSigners)));
        check("signers constructor: different locations are unequal",
                !signersOne.equals(signersTwo));

        // Serialization must rebuild the URI.
        CodeSource back = roundTrip(csOne);
        check("serialization: URI is rebuilt", back.getUriLocation() != null);
        check("serialization: round trip is equal", csOne.equals(back));
        check("serialization: round trip hashes alike",
                csOne.hashCode() == back.hashCode());
        check("serialization: location survives",
                back.getLocation() != null
                && back.getLocation().toString().equals(one.toString()));
        check("serialization: different locations stay unequal",
                !roundTrip(csOne).equals(roundTrip(csTwo)));
        CodeSource noneBack = roundTrip(csNone);
        check("serialization: no location stays no location",
                noneBack.getLocation() == null && noneBack.getUriLocation() == null);
        check("serialization: no location is unequal to a location",
                !noneBack.equals(back));

        // DomainIdentity compares through the same URIs.
        ProtectionDomain d1 = new DomainIdentity(csOne, new Permissions());
        ProtectionDomain d1Again = new DomainIdentity(csOneAgain, new Permissions());
        ProtectionDomain d2 = new DomainIdentity(csTwo, new Permissions());
        check("domain: same location is equal", d1.equals(d1Again));
        check("domain: same location hashes alike", d1.hashCode() == d1Again.hashCode());
        check("domain: different locations are unequal", !d1.equals(d2));

        ProtectionDomain none = null;
        ProtectionDomain noneAgain = null;
        try {
            none = new DomainIdentity(csNone, new Permissions());
            noneAgain = new DomainIdentity(csNoneAgain, new Permissions());
        } catch (RuntimeException ex) {
            System.out.println(new StringBuilder("exception: ").append(ex));
        }
        check("domain: no-location code source is accepted",
                none != null && noneAgain != null);
        if (none != null && noneAgain != null) {
            check("domain: no-location domains are equal", none.equals(noneAgain));
            check("domain: no-location domains hash alike",
                    none.hashCode() == noneAgain.hashCode());
            check("domain: no-location domain is unequal to a location domain",
                    !none.equals(d1));
        }

        check("domain: a public-constructor domain has no caller domain",
                ((DomainIdentity) d1).getCallerDomain() == null);

        if (failures > 0) {
            throw new RuntimeException(new StringBuilder().append(failures)
                    .append(" check(s) failed, see output").toString());
        }
        System.out.println("PASSED");
    }

    private static CodeSource roundTrip(CodeSource cs) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(cs);
        }
        try (ObjectInputStream in =
                new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return (CodeSource) in.readObject();
        }
    }

    private static void check(String what, boolean ok) {
        System.out.println(new StringBuilder(ok ? "ok      " : "FAILED  ").append(what));
        if (!ok) failures++;
    }
}
