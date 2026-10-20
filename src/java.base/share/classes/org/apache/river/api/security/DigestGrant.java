/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.river.api.security;

import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Arrays;

/**
 * A {@link PermissionGrant} that matches only {@link ProtectionDomain}s whose
 * {@link CodeSource} is a {@link DigestCodeSource} with an identical content
 * digest.  Any domain backed by a plain {@link CodeSource} — even one with the
 * same URL — is not implied, enforcing fail-secure behaviour.
 *
 * <p>Serialization uses the same proxy pattern as all other grant
 * implementations: {@link #writeReplace()} delegates to
 * {@link #getBuilderTemplate()}, and {@link #readObject} throws
 * {@link InvalidObjectException}.
 *
 * <p><b>Operator note — fail-closed on a non-DirtyChai JVM.</b> This grant
 * depends on {@link DigestCodeSource}, which exists only on a DirtyChai
 * (or otherwise digest-aware) JVM. On a stock JVM that class is absent, so no
 * {@link ProtectionDomain} can ever present a {@link DigestCodeSource} and
 * every {@code DigestGrant} consequently implies nothing (fail-secure: the
 * permissions it would have conferred simply never apply). This is by design,
 * but it is a configuration footgun: an empty "no digest-matched grants apply"
 * result on the wrong JVM should not be misread as a broken policy. If digest
 * enforcement is expected but no digest grants are taking effect, verify the
 * runtime is a digest-aware JVM before suspecting the policy itself.
 *
 * @author Peter Firmstone
 * @since 27
 */
@SuppressWarnings("serial")
class DigestGrant extends URIGrant {

    private static final long serialVersionUID = 1L;

    private final String digestAlgorithm;
    private final byte[] digest;         // immutable defensive copy
    private final int hashCode;

    DigestGrant(String[] uri, String digestAlgorithm, byte[] digest,
                Certificate[] certs, String[] aliases,
                Principal[] pals, Permission[] perms) {
        super(uri, certs, aliases, pals, perms);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest != null ? digest.clone() : null;
        int h = super.hashCode();
        h = 31 * h + (digestAlgorithm != null ? digestAlgorithm.hashCode() : 0);
        h = 31 * h + Arrays.hashCode(this.digest);
        this.hashCode = h;
    }

    // -----------------------------------------------------------------------
    // Object identity
    // -----------------------------------------------------------------------

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof DigestGrant)) return false;
        if (o.hashCode() != hashCode) return false;
        DigestGrant other = (DigestGrant) o;
        if (!super.equals(o)) return false;
        if (!stringsEqual(digestAlgorithm, other.digestAlgorithm)) return false;
        return Arrays.equals(digest, other.digest);
    }

    // -----------------------------------------------------------------------
    // Implication
    // -----------------------------------------------------------------------

    /**
     * Returns {@code true} only when {@code pd}'s {@link CodeSource} is a
     * {@link DigestCodeSource} with matching algorithm and digest bytes, and
     * when all inherited principal and certificate checks also pass.
     */
    @Override
    public boolean implies(ProtectionDomain pd) {
        if (pd == null) return false;
        CodeSource cs = pd.getCodeSource();
        Principal[] pals = getPrincipals(pd);
        return implies(cs, pals);
    }

    /**
     * Returns {@code false} for any plain {@link ClassLoader} argument;
     * the digest of loaded code is indeterminate without a {@link CodeSource}.
     */
    @Override
    public boolean implies(ClassLoader cl, Principal[] p) {
        return false;   // indeterminate — same as CertificateGrant
    }

    /**
     * Core implication logic.
     *
     * <ol>
     * <li>Principal check (delegated to super).
     * <li>{@code codeSource} must be a {@link DigestCodeSource} — plain
     *     {@link CodeSource} instances are never implied, even with the same URL.
     * <li>Algorithm names must match (case-sensitive).
     * <li>Digest bytes must be equal ({@link Arrays#equals}).
     * <li>Certificate check delegated to {@code super.implies(CodeSource, Principal[])}.
     * </ol>
     */
    @Override
    public boolean implies(CodeSource codeSource, Principal[] p) {
        if (!implies(p)) return false; // Ignore URL, it doesn't define identity.
        if (codeSource instanceof DigestCodeSource dcs) {
            if (dcs.unverified() == true) return false; // DigestCodeSource must be verified.)
            if (!stringsEqual(digestAlgorithm, dcs.getDigestAlgorithm())) return false;
            if (!Arrays.equals(digest, dcs.getDigest())) return false;
            return impliesSigners(codeSource);
        }
        return false;
    }

    @Override
    public boolean impliesEquivalent(PermissionGrant grant) {
        if (!(grant instanceof DigestGrant other)) return false;
        if (!super.impliesEquivalent(grant)) return false;
        if (!stringsEqual(digestAlgorithm, other.digestAlgorithm)) return false;
        return Arrays.equals(digest, other.digest);
    }

    // -----------------------------------------------------------------------
    // Serialization — proxy pattern
    // -----------------------------------------------------------------------

    @Override
    public PermissionGrantBuilder getBuilderTemplate() {
        PermissionGrantBuilder pgb = super.getBuilderTemplate();
        return pgb.digest(digestAlgorithm, digest)
                  .context(PermissionGrantBuilder.DIGEST);
    }

    private Object writeReplace() {
        return getBuilderTemplate();
    }

    private void readObject(ObjectInputStream stream)
            throws InvalidObjectException {
        throw new InvalidObjectException("PermissionGrantBuilder required");
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private static boolean stringsEqual(String a, String b) {
        return a == b || (a != null && a.equals(b));
    }
}