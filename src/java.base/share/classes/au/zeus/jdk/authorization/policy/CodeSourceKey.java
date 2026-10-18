/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package au.zeus.jdk.authorization.policy;


import au.zeus.jdk.net.Uri;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.security.DigestCodeSource;
import java.util.Arrays;
import java.util.Objects;


/**
 * A key for a CodeSource, used to identify
 * CodeSource objects in a Map.  The key is based on the CodeSource's
 * location URL and its certificates.  DigestCodeSource objects are also
 * distinguished by their digest algorithm and digest value.
 */
public class CodeSourceKey {
        
        private final Uri uri;
        private final java.security.cert.Certificate [] certs;
         // Populated only when the incoming CodeSource is a DigestCodeSource.
        private final String digestAlgorithm;
        private final byte[] digest;
        private final int hashCode;
        final CodeSource cs; // package-private: used by resetArchivedStates
        
        /**
        * Constructs a new CodeSourceKey for the given CodeSource.
         *
         * @param cs the CodeSource to create a key for
         * @throws URISyntaxException if the CodeSource's location URL is not a valid URI
         */
        public CodeSourceKey(CodeSource cs) throws URISyntaxException {
            this.cs = cs;
            certs = cs.getCertificates();
            this.uri = cs.getLocation() != null ? Uri.urlToUri(cs.getLocation()) : null;
            if (cs instanceof DigestCodeSource dcs) {
                this.digestAlgorithm = dcs.getDigestAlgorithm();
                this.digest = dcs.getDigest();   // defensive copy already made by getDigest()
            } else {
                this.digestAlgorithm = null;
                this.digest = null;
            }
            int hash = 7;
            hash = 23 * hash + (uri != null ? uri.hashCode() :0);
            hash = 23 * hash + (certs != null ? Arrays.hashCode(certs) : 0);
            hash = 23 * hash + (digestAlgorithm != null ? digestAlgorithm.hashCode() : 0);
            hash = 23 * hash + Arrays.hashCode(digest);
            hashCode = hash; // 7 if everything is null;
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof CodeSourceKey that)) return false;
            // URI equality (RFC 3986, no DNS): handles null on both sides.
            if (uri == null ? that.uri != null : !uri.equals(that.uri)) return false;
            // Certificate equality.
            if (!Arrays.equals(certs, that.certs)) return false;
            // Digest equality: a plain-CS key (null digest) is NOT equal to a
            // DigestCS key (non-null digest) — they represent different identities.
            if (digestAlgorithm == null ? that.digestAlgorithm != null
                                        : !digestAlgorithm.equals(that.digestAlgorithm)) return false;
            return Arrays.equals(digest, that.digest);
        }

        /**
         * Returns the CodeSource associated with this key.
         *
         * @return the CodeSource associated with this key
         */
        public CodeSource getCodeSource() {
            return cs;
        }

        /**
         * Returns the URI associated with this key.
         *
         * @return the URI associated with this key
         */
        public Uri getUri() {
            return uri;
        }

        /**
         * Returns the certificates associated with this key.    
         * Note this method returns a reference to the internal
         * array of certificates, so the caller should not modify 
         * the returned array.
         *
         * @return the certificates associated with this key
         */
        public java.security.cert.Certificate[] getCertificates() {
            return certs;
        }
    }