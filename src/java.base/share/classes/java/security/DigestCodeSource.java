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
package java.security;

import au.zeus.jdk.net.Uri;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.OutputStream;
import java.net.CacheRequest;
import java.net.CacheResponse;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ResponseCache;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.lang.module.ModuleFinder;
import java.lang.module.ModuleReader;
import java.lang.module.ModuleReference;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Stream;
import sun.net.util.URLUtil;
import sun.security.provider.InternalDigests;
import jdk.internal.misc.VM;

/**
 * Non Standard API.
 *
 * A {@link CodeSource} that additionally identifies a code artifact by its
 * content digest, enabling DNS-free, content-addressed equality checks.
 *
 * <p>
 * Equality and hashing use the RFC 3986 URI form of the location (avoiding DNS
 * lookups), the certificates, the digest algorithm name, and the digest bytes.
 * {@link #getDigest()} always returns a defensive copy.
 *
 * <p>
 * Serialization uses {@link Externalizable} with a stable binary layout
 * containing only primitives, {@code String}s, and byte arrays, compatible with
 * {@code @AtomicSerial} in JGDMS. Standard Java {@code Serializable} object
 * graphs are never written to the stream.
 *
 * @author Peter Firmstone
 */
public final class DigestCodeSource extends CodeSource implements Externalizable {

    @java.io.Serial
    private static final long serialVersionUID = 1L;

    /**
     * Written before every nullable field to signal presence or absence.
     */
    private static final byte FIELD_NULL = 0;
    private static final byte FIELD_PRESENT = 1;

    // DOS-defence limits applied during readExternal and computeDigest.
    /**
     * Maximum number of certificates in a single DigestCodeSource stream.
     */
    private static final int MAX_CERT_COUNT = 100;

    /**
     * Maximum encoded size of a single certificate (DER bytes). X.509
     * end-entity certificates are typically 1–4 KiB; 64 KiB is generous.
     */
    private static final int MAX_CERT_BYTES = 64 * 1024;

    /**
     * Maximum digest length in bytes. SHA-512 produces 64 bytes; 512 bytes is a
     * very conservative ceiling that accommodates any foreseeable algorithm.
     */
    private static final int MAX_DIGEST_BYTES = 512;

    /**
     * Maximum bytes consumed when computing a digest from a URL stream.
     * Protects against infinite / very large HTTP responses. Default: 512 MiB.
     * Callers that need a different limit should compute the digest themselves
     * and use the pre-computed-digest constructor.
     */
    static final long MAX_STREAM_BYTES = 512L * 1024 * 1024;

    private static final String[] ALLOWED = new String[]{
        "SHA-256", "SHA-384", "SHA-512",
        "SHA-512/256", "SHA3-256", "SHA3-384", "SHA3-512"
    };

    private static String checkAlgorithm(String digestAlgorithm) {
        if (digestAlgorithm == null) {
            throw new NullPointerException("Digest Algorithm cannot be null");
        }
        for (int i = 0, l = ALLOWED.length; i < l; i++) {
            if (ALLOWED[i].equals(digestAlgorithm)) {
                return ALLOWED[i];
            }
        }
        throw new IllegalArgumentException("Insecure or unknown digest algorithm: " + digestAlgorithm);
    }

    // Instance fields — all transient; the full stream is owned by
    // writeExternal / readExternal.
    private transient String digestAlgorithm;
    private transient byte[] digest;
    private transient Uri uri;           // RFC 3986 form; avoids DNS in equals/hashCode
    private transient int cachedHashCode;
    private transient boolean unverified = false;
    /**
     * Cached defensive copy of the certificate array returned by
     * {@link #getCertificates()}.  {@code getCertificates()} allocates a new
     * array on every call; caching the result here avoids repeated allocation
     * in the hot paths of {@link #equals} and {@link #computeHashCode}.
     *
     * <p>Populated lazily on the first call to {@link #cachedCerts()}.
     * {@code null} means "not yet computed", not "no certificates".
     */
    private volatile transient Certificate[] cachedCerts;

    // -----------------------------------------------------------------------
    // Layer 1 — Network cache: JarResponseCache + ResponseCache.setDefault()
    //
    // JarResponseCache stores full response bodies (JAR bytes) keyed by URI
    // string.  Any URLConnection caller that uses setUseCaches(true) — inside
    // or outside DigestCodeSource — will be served from this cache, avoiding
    // redundant network traffic across the whole JVM process.
    //
    // Layer 2 — Security guard: digestCache
    //
    // digestCache records the first-trusted digest for each (URI, algorithm)
    // pair.  Every subsequent computation — whether served by JarResponseCache
    // or a fresh network download after cache eviction — is compared against
    // this record.  A mismatch means the artifact has changed and the load is
    // rejected with SecurityException (fail-secure).
    // -----------------------------------------------------------------------

    /**
     * A JVM-wide {@link ResponseCache} implementation that stores complete
     * HTTP(S) and {@code file:} response bodies in memory, keyed by URI string.
     *
     * <p>
     * Only HTTP 200 (OK) responses are stored; all other status codes are
     * passed through without caching.  Non-HTTP connections (e.g. {@code file:})
     * are always cached because they carry no status code.
     *
     * <p>
     * The response body is captured by the {@link CacheRequest} returned from
     * {@link #put}: the JDK HTTP client writes the response bytes to the
     * {@link OutputStream} supplied by {@link CacheRequest#getBody()} and
     * closes it when the transfer is complete.  Closing the stream commits the
     * entry to the store.
     *
     * <p>
     * The store is unbounded but lives only for the JVM lifetime, which is
     * appropriate for code-source artifacts that are loaded once (or a small
     * number of times) per process.
     */
    private static final class JarResponseCache extends ResponseCache {

        /**
         * Immutable snapshot of a single cached HTTP response.
         */
        private static final class Entry {
            /** Full response body. */
            final byte[] body;
            /** Unmodifiable copy of the original response headers. */
            final Map<String, List<String>> headers;

            Entry(byte[] body, Map<String, List<String>> headers) {
                this.body = body;
                Map<String, List<String>> copy = new HashMap<>(headers);
                copy.replaceAll((k, v) -> v == null ? List.of() : List.copyOf(v));
                this.headers = Collections.unmodifiableMap(copy);
            }
        }

        /** URI-string → cached response entry. */
        private final ConcurrentMap<String, Entry> store = new ConcurrentHashMap<>();

        /**
         * Returns a {@link CacheResponse} for {@code uri} if one has been
         * stored, or {@code null} to indicate a cache miss (triggering a
         * normal network fetch by the HTTP client).
         */
        @Override
        public CacheResponse get(URI uri, String rqstMethod,
                Map<String, List<String>> rqstHeaders) throws IOException {
            Entry entry = store.get(uri.toString());
            if (entry == null) {
                return null;    // cache miss — let the HTTP client fetch
            }
            final Entry e = entry;
            return new CacheResponse() {
                @Override
                public Map<String, List<String>> getHeaders() {
                    return e.headers;
                }
                @Override
                public InputStream getBody() {
                    return new ByteArrayInputStream(e.body);
                }
            };
        }

        /**
         * Returns a {@link CacheRequest} that captures the response body as
         * the HTTP client streams it, committing the entry to the store when
         * the stream is closed.
         *
         * <p>
         * Returns {@code null} (do not cache) for any HTTP response whose
         * status code is not 200 OK.
         */
        @Override
        public CacheRequest put(URI uri, URLConnection conn) throws IOException {
            // Skip non-success HTTP responses.
            if (conn instanceof HttpURLConnection http) {
                try {
                    if (http.getResponseCode() != HttpURLConnection.HTTP_OK) {
                        return null;
                    }
                } catch (IOException ex) {
                    return null;
                }
            }
            Map<String, List<String>> responseHeaders = conn.getHeaderFields();
            return new CacheRequest() {
                private final ByteArrayOutputStream baos =
                    new ByteArrayOutputStream(65536);
                private volatile boolean aborted = false;

                /**
                 * Returns an {@link OutputStream} to which the HTTP client
                 * writes the response body.  Closing the stream (after a
                 * complete, non-aborted transfer) commits the entry.
                 */
                @Override
                public OutputStream getBody() {
                    return new OutputStream() {
                        @Override
                        public void write(int b) {
                            baos.write(b);
                        }
                        @Override
                        public void write(byte[] b, int off, int len) {
                            baos.write(b, off, len);
                        }
                        @Override
                        public void close() {
                            if (!aborted) {
                                store.put(uri.toString(),
                                    new Entry(baos.toByteArray(), responseHeaders));
                            }
                        }
                    };
                }

                @Override
                public void abort() {
                    aborted = true;
                }
            };
        }

        /**
         * Removes any cached response for {@code uri}, forcing the next
         * access to perform a fresh network fetch.
         *
         * @param uri the URI whose entry should be evicted
         */
        void invalidate(URI uri) {
            store.remove(uri.toString());
        }
    }

    /** Singleton response cache installed as the JVM-wide default. */
    private static final JarResponseCache JAR_CACHE = new JarResponseCache();

    static {
        // ResponseCache.setDefault() requires NetPermission("setResponseCache").
        // DigestCodeSource is a privileged JDK class (java.security package), so
        // the call is made inside doPrivileged to assert that privilege explicitly.
        // Without this, the static initialiser throws SecurityException under a
        // SecurityManager that has not granted the permission to application code,
        // which would cause a NoClassDefFoundError on every subsequent use of this
        // class — self-defeating in the very environment it is designed for.
        @SuppressWarnings("removal")
        var unused = AccessController.doPrivileged(
            (PrivilegedAction<Void>) () -> {
                ResponseCache.setDefault(JAR_CACHE);
                return null;
            }
        );
    }

    // -----------------------------------------------------------------------
    // Layer 2 — digest security guard
    // -----------------------------------------------------------------------

    /**
     * Composite cache key: (URI, algorithm).
     *
     * <p>Two keys are equal when both their {@link Uri} and algorithm string
     * are equal, ensuring that different algorithms for the same URI produce
     * independent cache entries.
     */
    private static final class DigestCacheKey {
        private final Uri uri;
        private final String algorithm;
        private final int hashCode;

        DigestCacheKey(Uri uri, String algorithm) {
            this.uri = uri;
            this.algorithm = algorithm;
            this.hashCode = Objects.hash(uri, algorithm);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof DigestCacheKey that)) return false;
            return Objects.equals(uri, that.uri)
                    && Objects.equals(algorithm, that.algorithm);
        }
    }

    /**
     * Records the first-trusted digest for each (URI, algorithm) pair.
     *
     * <p>Values are kept alive for the JVM lifetime (strong references) so
     * that a GC-triggered eviction cannot silently re-establish trust for a
     * URI whose artifact has changed.  The number of distinct code-source URLs
     * in a JVM process is small, so unbounded growth is not a practical
     * concern.
     */
    private static final ConcurrentMap<DigestCacheKey, byte[]> digestCache =
        new ConcurrentHashMap<>();

    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /**
     * No-arg constructor required by {@link Externalizable}. All fields are
     * populated by {@link #readExternal}.
     */
    public DigestCodeSource() {
        super(null, (Certificate[]) null);
    }

    /**
     * Creates a {@code DigestCodeSource} from a URL string, downloading the
     * artifact and computing its digest.
     *
     * @param url the code location as a string (may be {@code null})
     * @param certs the certificates (may be {@code null})
     * @param digestAlgorithm the hash algorithm, e.g. {@code "SHA-256"}
     * @throws URISyntaxException if {@code url} is not a valid URI
     * @throws MalformedURLException if the URI cannot be converted to a URL
     * @throws IOException if the artifact cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    public DigestCodeSource(String url, Certificate[] certs, String digestAlgorithm)
            throws URISyntaxException, MalformedURLException,
            IOException, NoSuchAlgorithmException {
        this(parseUri(url), certs, digestAlgorithm);
    }

    /**
     * Creates a {@code DigestCodeSource} from a URL string, downloading the
     * artifact and computing its digest.
     *
     * @param url the code location as a string (may be {@code null})
     * @param signers the code signers (may be {@code null})
     * @param digestAlgorithm the hash algorithm, e.g. {@code "SHA-256"}
     * @throws URISyntaxException if {@code url} is not a valid URI
     * @throws MalformedURLException if the URI cannot be converted to a URL
     * @throws IOException if the artifact cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     */
    public DigestCodeSource(String url, CodeSigner[] signers, String digestAlgorithm)
            throws URISyntaxException, MalformedURLException,
            IOException, NoSuchAlgorithmException {
        this(parseUri(url), signers, digestAlgorithm);
    }

    /**
     * Promotes a plain {@link CodeSource} to a {@code DigestCodeSource},
     * attaching a pre-computed digest. Used by SecureClassLoader.
     *
     * @param cs the source to promote (must not be {@code null})
     * @param digestAlgorithm the hash algorithm name
     * @throws IllegalArgumentException if {@code cs.getLocation()} is {@code null};
     *         a {@code DigestCodeSource} requires a non-null location to
     *         download and hash the artifact.
     * @throws IOException if a connection cannot be established.
     * @throws NoSuchAlgorithmException if the provider isn't available.
     * @throws URISyntaxException if the CodeSource URL is not RFC 3986 compliant.
     */
    public DigestCodeSource(CodeSource cs,
            String digestAlgorithm) throws IOException, NoSuchAlgorithmException, URISyntaxException {
        this(cs, requireLocation(cs), digestAlgorithm);
    }

    /** Shim that receives the already-validated location so it is only resolved once. */
    private DigestCodeSource(CodeSource cs, URL loc, String digestAlgorithm)
            throws IOException, NoSuchAlgorithmException, URISyntaxException {
        this(loc, Uri.urlToUri(loc), cs.getCertificates(), digestAlgorithm);
    }

    /**
     * Guards against a {@code null} location in the CodeSource-promotion
     * constructor.  Returns {@code cs.getLocation()} when non-null.
     *
     * @throws IllegalArgumentException if {@code cs.getLocation()} is {@code null}
     */
    private static URL requireLocation(CodeSource cs) {
        URL loc = cs.getLocation();
        if (loc == null) {
            throw new IllegalArgumentException(
                    "Cannot promote a CodeSource with a null location to a"
                    + " DigestCodeSource: no URL to download and hash");
        }
        return loc;
    }

    // Package-private auto-compute helpers used in Phase 2 of SecureClassLoader.
    DigestCodeSource(Uri uri, Certificate[] certs, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(uriToUrl(uri), uri, certs, digestAlgorithm);
    }

    DigestCodeSource(Uri uri, CodeSigner[] signers, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(uriToUrl(uri), uri, signers, digestAlgorithm);
    }

    private DigestCodeSource(URL url, Uri uri, CodeSigner[] signers, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(url, uri, signers, checkAlgorithm(digestAlgorithm), computeDigest(uri, url, digestAlgorithm));
    }

    private DigestCodeSource(URL url, Uri uri, Certificate[] certs, String digestAlgorithm)
            throws MalformedURLException, IOException, NoSuchAlgorithmException {
        this(url, uri, certs, checkAlgorithm(digestAlgorithm), computeDigest(uri, url, digestAlgorithm));
    }
    
    /**
     * This constructor creates an unchecked DigestCodeSource.
     * 
     * @param uri The Uri normalized from.
     * @param certs Certificates the CodeSource is signed by.
     * @param digestAlgorithm the digest algorithm, eg SHA-256
     * @param digest The digest bytes.
     * @throws MalformedURLException The the uri string is malformed.
     * @throws URISyntaxException if the uri string is not RFC3986 compliant.
     */
    public DigestCodeSource(String uri, Certificate[] certs, String digestAlgorithm, byte[] digest) throws MalformedURLException, URISyntaxException{
        this(parseUri(uri), certs, digestAlgorithm, digest);
        
    }
    
    private DigestCodeSource(Uri uri, Certificate[] certs, String digestAlgorithm, byte[] digest) throws MalformedURLException{
        this(uriToUrl(uri), uri, certs, checkAlgorithm(digestAlgorithm), digest);
        unverified = true;
    }

    private DigestCodeSource(URL url, Uri uri, Certificate[] certs, String digestAlgorithm, byte[] digest)
            throws MalformedURLException {
        super(url, certs);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;   // already a fresh array from computeDigest
        this.uri = uri;
        this.cachedHashCode = computeHashCode();
    }

    private DigestCodeSource(URL url, Uri uri, CodeSigner[] signers,
            String digestAlgorithm, byte[] digest)
            throws MalformedURLException {
        super(url, signers);
        this.digestAlgorithm = digestAlgorithm;
        this.digest = digest;
        this.uri = uri;
        this.cachedHashCode = computeHashCode();
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Performs a clone for defensive copying following unmarshaling.
     *
     * @return clone of this DigestCodeSource.
     */
    @Override
    public DigestCodeSource clone() {
        DigestCodeSource result = null;
        try {
            result = (DigestCodeSource) super.clone();
            result.digest = digest == null ? null : digest.clone();
        } catch (CloneNotSupportedException ex) {
        } // ignore.
        return result;
    }

    /**
     * Returns the digest algorithm name, e.g. {@code "SHA-256"}, or
     * {@code null}.
     *
     * @return the digest algorithm name, e.g. {@code "SHA-256"}, or
     * {@code null}.
     */
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    /**
     * Returns a defensive copy of the content digest, or {@code null} if none
     * was provided.
     *
     * @return a defensive copy of the content digest, or {@code null} if none
     * was provided.
     */
    public byte[] getDigest() {
        return digest != null ? digest.clone() : null;
    }

    @Override
    public int hashCode() {
        return cachedHashCode;
    }

    /**
     * Compares this {@code DigestCodeSource} to {@code o} for equality.
     *
     * <h4>No DNS — URI comparison only</h4>
     * <p>
     * Location equality is determined by RFC 3986 {@link Uri} comparison, which
     * never performs a DNS lookup.  {@link CodeSource#equals} is intentionally
     * <em>never</em> called; that method resolves hostnames and must be avoided
     * in security-sensitive paths.
     *
     * <h4>Invariant: {@code uri} is non-null whenever {@code location} is non-null</h4>
     * <p>
     * Every constructor either accepts a pre-validated {@link Uri} or calls
     * {@link Uri#urlToUri} / {@link Uri#parseAndCreate}, both of which throw
     * {@link URISyntaxException} on failure.  {@link #readExternal} similarly
     * throws {@link IOException} if the URL cannot be converted.  Therefore a
     * successfully constructed instance always satisfies
     * {@code (location == null) == (uri == null)}.
     *
     * <h4>Intentional incompatibility with plain {@link CodeSource}</h4>
     * <p>
     * {@code false} is returned whenever {@code o} is not also a
     * {@code DigestCodeSource}.  A plain {@code CodeSource} and a
     * {@code DigestCodeSource} that share the same URL and certificates are
     * deliberately <em>not</em> considered equal, because equality without a
     * matching digest would undermine the content-addressed identity guarantee.
     *
     * @param o the object to compare
     * @return {@code true} if {@code o} is a {@code DigestCodeSource} with
     *         equal URI, certificates, digest algorithm, and digest bytes
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DigestCodeSource that)) {
            return false;
        }
        // URI comparison — never null on a successfully constructed instance
        // when location is non-null, so XOR here means one has a location and
        // the other does not: they are not equal.
        if (uri == null ^ that.uri == null) {
            return false;
        }
        if (uri != null && !uri.equals(that.uri)) {
            return false;
        }
        // Both URIs are null (both have null location) or both are equal.
        if (!Arrays.equals(cachedCerts(), that.cachedCerts())) {
            return false;
        }
        if (!stringsEqual(digestAlgorithm, that.digestAlgorithm)) {
            return false;
        }
        return Arrays.equals(digest, that.digest);
    }

    /**
     * Returns a string describing this {@code DigestCodeSource}, including its
     * URL, certificates, digest algorithm, and digest value.
     * <p>
     * Format: {@code (url [cert ...] algorithm:hexDigest)}
     *
     * @return a human-readable description of this {@code DigestCodeSource}.
     */
    @Override
    public String toString() {
        // Start from CodeSource's representation, which ends with ')'..
        String base = super.toString();
        if (digestAlgorithm == null && digest == null) {
            return base;
        }
        // super.toString() closes its output with ')'.  Strip that trailing
        // character so we can append digest info inside the same pair of parens.
        StringBuilder sb = new StringBuilder(base.length() + 72);
        sb.append(base, 0, base.length() - 1);   // exclude the closing ')'
        sb.append(' ');
        sb.append(digestAlgorithm != null ? digestAlgorithm : "<null-algorithm>");
        sb.append(':');
        if (digest != null) {
            sb.append(hexEncode(digest));
        } else {
            sb.append("<null-digest>");
        }
        sb.append(')');
        return sb.toString();
    }
    
    /**
     * Returns true if the digest hasn't been verified.
     * @return true if the digest wasn't calculated 
     */
    public boolean unverified(){
        return unverified;
    }

    /**
     * Returns the URI of this code source, the type of this object is not
     * published, calling toString on it will produce a RFC 3986 compliant URI string.
     *
     * @return the URI of this code source
     */
    public Object getUri() {
        return uri;
    }

    /**
     * Encodes a byte array as a lowercase hex string.
     */
    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    // -----------------------------------------------------------------------
    // Externalizable
    // -----------------------------------------------------------------------

    /**
     * Binary stream layout — each nullable field is preceded by a presence
     * byte:
     * <pre>
     *   byte  urlPresent        (FIELD_NULL | FIELD_PRESENT)
     *   if present: UTF  url.toExternalForm()
     *
     *   byte  certsPresent      (FIELD_NULL | FIELD_PRESENT)
     *   if present:
     *     int  certCount                          (≤ MAX_CERT_COUNT)
     *     for each cert:
     *       int    encodedLength                  (≤ MAX_CERT_BYTES)
     *       byte[] encoded          (DER)
     *       UTF    cert.getType()
     *
     *   byte  algorithmPresent  (FIELD_NULL | FIELD_PRESENT)
     *   if present: UTF  digestAlgorithm
     *
     *   byte  digestPresent     (FIELD_NULL | FIELD_PRESENT)
     *   if present:
     *     int    digestLength                     (≤ MAX_DIGEST_BYTES)
     *     byte[] digest
     * </pre>
     */
    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        // --- URL ---
        URL loc = getLocation();
        if (loc != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeUTF(loc.toExternalForm());
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Certificates ---
        Certificate[] certArr = getCertificates();
        if (certArr != null && certArr.length > 0) {
            out.writeByte(FIELD_PRESENT);
            out.writeInt(certArr.length);
            for (Certificate cert : certArr) {
                try {
                    byte[] enc = cert.getEncoded();
                    out.writeInt(enc.length);
                    out.write(enc);
                    out.writeUTF(cert.getType());
                } catch (CertificateEncodingException e) {
                    throw new IOException("Cannot encode certificate: " + e.getMessage(), e);
                }
            }
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Digest algorithm ---
        if (digestAlgorithm != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeUTF(digestAlgorithm);
        } else {
            out.writeByte(FIELD_NULL);
        }

        // --- Digest bytes ---
        if (digest != null) {
            out.writeByte(FIELD_PRESENT);
            out.writeInt(digest.length);
            out.write(digest);
        } else {
            out.writeByte(FIELD_NULL);
        }
    }

    /**
     * Restores all fields from the stream written by {@link #writeExternal}.
     *
     * <p>
     * DOS defence: array lengths read from the stream are validated against
     * hard ceilings ({@link #MAX_CERT_COUNT}, {@link #MAX_CERT_BYTES},
     * {@link #MAX_DIGEST_BYTES}) before any allocation is performed.
     */
    @Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        // --- URL ---
        URL loc = null;
        if (in.readByte() == FIELD_PRESENT) {
            try {
                loc = Uri.parseAndCreate(in.readUTF()).toURL();
            } catch (MalformedURLException e) {
                throw new IOException("Malformed URL in DigestCodeSource stream", e);
            } catch (URISyntaxException e) {
                throw new IOException("URI Syntax error in DigestCodeSource stream", e);
            }
        }

        // --- Certificates ---
        Certificate[] restoredCerts = null;
        if (in.readByte() == FIELD_PRESENT) {
            int count = in.readInt();
            if (count < 0 || count > MAX_CERT_COUNT) {
                throw new IOException(
                        "Certificate count out of range in DigestCodeSource stream: " + count
                        + " (max " + MAX_CERT_COUNT + ")");
            }
            restoredCerts = new Certificate[count];
            for (int i = 0; i < count; i++) {
                int len = in.readInt();
                if (len < 0 || len > MAX_CERT_BYTES) {
                    throw new IOException(
                            "Certificate encoding length out of range: " + len
                            + " (max " + MAX_CERT_BYTES + ")");
                }
                byte[] enc = new byte[len];
                in.readFully(enc);
                String type = in.readUTF();
                if (type.length() > 64)// no legitimate cert type is longer than this
                {
                    throw new IOException("Certificate type string too long: " + type.length());
                }
                if (!"X.509".equals(type)) {
                    throw new IOException("Unknown Certificate Type: " + type);
                }
                try {
                    CertificateFactory cf = CertificateFactory.getInstance(type);
                    restoredCerts[i] = cf.generateCertificate(
                            new ByteArrayInputStream(enc));
                } catch (CertificateException e) {
                    throw new IOException(
                            "Cannot reconstruct certificate of type "
                            + type + ": " + e.getMessage(), e);
                }
            }
        }

        // Restore inherited CodeSource fields directly — all are package-private.
        location = loc;
        certs = restoredCerts;
        locationNoFragString = loc != null ? URLUtil.urlNoFragString(loc) : null;

        // --- Digest algorithm ---
        digestAlgorithm = null;
        try {
            if (in.readByte() == FIELD_PRESENT) {
                digestAlgorithm = checkAlgorithm(in.readUTF());
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("Algorithm not allowed here: ", e);
        } catch (NullPointerException e) {
            throw new IOException("No digest algorithm: ", e);
        }

        // --- Digest bytes ---
        digest = null;
        if (in.readByte() == FIELD_PRESENT) {
            int len = in.readInt();
            if (len < 0 || len > MAX_DIGEST_BYTES) {
                throw new IOException(
                        "Digest length out of range in DigestCodeSource stream: " + len
                        + " (max " + MAX_DIGEST_BYTES + ")");
            }
            digest = new byte[len];
            in.readFully(digest);
        }

        uri = uriFromUrl(loc);   // throws IOException if loc is non-null but unparseable
        cachedHashCode = computeHashCode();
        unverified = true;
    }

    // -----------------------------------------------------------------------
    // Digest computation — two-layer cache
    // -----------------------------------------------------------------------

    private static byte[] computeDirectoryDigest(File directory, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("Directory digest computation is not supported at this time");
    }

    /**
     * Computes an aggregate digest of a named JDK module by walking every
     * resource entry via {@link ModuleReader} in lexicographic order and
     * feeding each entry's bytes into the digest.  This covers {@code jrt:}
     * and {@code jmod:} URIs whose module-root URL cannot be opened as a
     * single stream.
     *
     * <p>The digest is computed over the concatenation of:
     * {@code (entry-name-UTF8-bytes + entry-content-bytes)} for every entry,
     * in sorted name order, so the result is deterministic.
     *
     * @param moduleName the plain module name (e.g. {@code "jdk.localedata"})
     * @param algorithm  digest algorithm (e.g. {@code "SHA-256"})
     * @return raw digest bytes
     * @throws IOException              if any module resource cannot be read
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     * @throws SecurityException        if the module is not found
     */
    private static byte[] computeModuleDigest(String moduleName, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        // Locate the module in the system image.
        Optional<ModuleReference> oref = ModuleFinder.ofSystem().find(moduleName);
        if (oref.isEmpty()) {
            throw new SecurityException("Module not found in system image: " + moduleName);
        }
        InternalDigests md = InternalDigests.sha256();
        try (ModuleReader reader = oref.get().open();
            Stream<String> entries = reader.list()) {
            // Sort for a deterministic digest regardless of iteration order.
            entries.sorted().forEach(name -> {
                try {
                    Optional<InputStream> oin = reader.open(name);
                    if (oin.isPresent()) {
                        // Mix in the entry name so renames are detected.
                        md.update(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        try (InputStream in = oin.get()) {
                            byte[] buf = new byte[8192];
                            int n;
                            while ((n = in.read(buf)) >= 0) {
                                md.update(buf, 0, n);
                            }
                        }
                    }
                } catch (IOException ex) {
                    throw new java.io.UncheckedIOException(ex);
                }
            });
        } catch (java.io.UncheckedIOException ex) {
            throw ex.getCause();
        }
        return md.digest(); 
    }

    /**
     * Returns the content digest of the artifact at the given URI/URL.
     *
     * <h4>Two-layer caching strategy</h4>
     * <ol>
     *   <li><b>Layer 1 — {@link JarResponseCache}:</b> {@code setUseCaches(true)}
     *       directs the JDK {@link URLConnection} machinery to consult the
     *       JVM-wide {@link ResponseCache} before opening a network connection.
     *       On a cache hit the response body (JAR bytes) is served from memory;
     *       on a miss the bytes are downloaded and the cache is populated for
     *       future callers — including any code outside {@code DigestCodeSource}
     *       that loads from the same URL.
     *       <br><em>Note:</em> for {@code jrt:} and {@code jmod:} URIs Layer 1
     *       is skipped — the module image is read directly via
     *       {@link ModuleReader}, which has its own OS-level caching.</li>
     *   <li><b>Layer 2 — {@code digestCache} (TOCTOU defence):</b> the digest
     *       computed from the stream (cached or fresh) is compared against the
     *       first-trusted value recorded for this {@code (URI, algorithm)} pair.
     *       If the values differ the remote artifact (or local JDK image) has
     *       changed since it was first loaded; a {@link SecurityException} is
     *       thrown (fail-secure).  This layer applies to <em>all</em> schemes,
     *       including {@code jrt:} and {@code jmod:}.</li>
     * </ol>
     *
     * <p>DOS defence: throws {@link IOException} if the stream exceeds
     * {@link #MAX_STREAM_BYTES} (default 512 MiB).
     *
     * @param uri       RFC 3986 URI used as the cache key (must not be {@code null})
     * @param url       URL opened on a cache miss (ignored for {@code jrt:}/{@code jmod:})
     * @param algorithm digest algorithm (e.g. {@code "SHA-256"})
     * @return a fresh defensive copy of the raw digest bytes
     * @throws IOException              if the URL cannot be read or the stream
     *                                  exceeds {@code MAX_STREAM_BYTES}
     * @throws NoSuchAlgorithmException if the algorithm is unavailable
     * @throws SecurityException        if the artifact content has changed
     *                                  since its digest was first computed
     */
    private static byte[] computeDigest(Uri uri, URL url, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        byte[] computed = null;

        String scheme = uri.getScheme();
        if ("jrt".equals(scheme) || "jmod".equals(scheme)) {
            // Layer 1 is skipped — module entries are read directly via
            // ModuleReader.  The result still flows through Layer 2 below.
            String path = uri.getPath();
            String moduleName = (path != null && path.startsWith("/"))
                    ? path.substring(1) : path;
            if (moduleName == null || moduleName.isEmpty()) {
                throw new IOException("Cannot compute digest: no module name in URI: " + uri);
            }
            // Strip any trailing resource path — we digest the whole module.
            int slash = moduleName.indexOf('/');
            if (slash != -1) moduleName = moduleName.substring(0, slash);
            computed = computeModuleDigest(moduleName, algorithm);
        } else if ("file".equals(scheme)) {
            File file = null;
            String host = uri.getHost();
            // Only allow network after the VM is booted.
            if (host != null && !host.isEmpty() && File.separatorChar == '\\' && uri.getUserInfo() == null
                && uri.getPort() == -1 && uri.getQuery() == null && uri.getFragment() == null) {
                if (!VM.isBooted()) {
                    throw new UnsupportedOperationException("Network file access is not allowed before the VM is booted: " + uri);
                }
                // UNC path, e.g. file://host/share/file.txt
                String raw = uri.getRawPath();
                String lower = raw.toLowerCase(Locale.ROOT);
                if (lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00")){
                    throw new SecurityException("Codebase path contains an encoded separator or NUL: " + uri);
                }
                file = new File("\\\\" + host + uri.getPath().replace('/', '\\'));
            } else {
                try {
                    file = Uri.uriToFile(uri);
                } catch (IllegalArgumentException ex) {
                    throw new SecurityException("Codebase is not a local file: " + uri, ex);
                }
            }
            if (file.exists()) {
                if (!file.canRead()) {
                    throw new SecurityException("Codebase file exists but is not readable: " + uri);
                }
                if (file.isDirectory()) {
                    computed = computeDirectoryDigest(file, algorithm);
                } else {
                    try (InputStream in = new BufferedInputStream(new FileInputStream(file), 8192)) {
                        computed = computeDigestFromStream(in, algorithm);
                    }
                }
            }
        } else {
            if (!VM.isBooted()) {
                throw new UnsupportedOperationException("Network URL access is not allowed before the VM is booted: " + uri);
            }
            // Layer 1: URLConnection consults JarResponseCache automatically via
            // setUseCaches(true).  On a cache hit no network connection is opened;
            // on a miss the response is downloaded and stored by JarResponseCache.
            URLConnection conn = url.openConnection();
            conn.setUseCaches(true);

            try (InputStream raw = conn.getInputStream()) {
                InputStream buffered = raw instanceof BufferedInputStream
                        ? raw : new BufferedInputStream(raw, 8192);
                computed = computeDigestFromStream(buffered, algorithm);
            } finally {
                if (conn instanceof HttpURLConnection http) {
                    http.disconnect();
                }
            }
        }

        // Layer 2: compare against the first-trusted digest for this URI.
        // Applies to all schemes — including jrt: and jmod: — so that a
        // tampered JDK image is detected on every subsequent class load.
        DigestCacheKey key = new DigestCacheKey(uri, algorithm);
        byte[] trusted = computed != null ? digestCache.putIfAbsent(key, computed.clone()) : null;
        if (trusted != null && !Arrays.equals(trusted, computed)) {
            // The artifact has changed since the digest was first trusted.
            // Evict only the raw-bytes cache entry so the next access re-downloads
            // fresh content; the trusted digest entry is deliberately kept so that
            // any concurrent thread that also downloaded the malicious version
            // cannot silently re-establish it as trusted after this remove.
            if (!("jrt".equals(scheme) || "jmod".equals(scheme))) {
                JAR_CACHE.invalidate(Uri.uriToURI(uri));
            }
            throw new SecurityException(
                    "Artifact digest has changed since first load; "
                    + "refusing to load from: " + uri);
        }

        return computed;    // fresh array; caller may store or use directly
    }

    /**
     * Computes the digest from an already-open stream (stream is not closed).
     *
     * <p>
     * DOS defence: aborts with {@link IOException} after
     * {@link #MAX_STREAM_BYTES} have been read.
     */
    private static byte[] computeDigestFromStream(InputStream in, String algorithm)
            throws IOException, NoSuchAlgorithmException {
        
        InternalDigests md = InternalDigests.sha256();
        byte[] buf = new byte[8192];
        long totalRead = 0;
        int n;
        while ((n = in.read(buf)) >= 0) {
            totalRead += n;
            if (totalRead > MAX_STREAM_BYTES) {
                throw new IOException(
                        "Digest computation aborted: stream exceeds "
                        + MAX_STREAM_BYTES + " bytes");
            }
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private static Uri parseUri(String url) throws URISyntaxException {
        return url == null ? null : Uri.parseAndCreate(url);
    }

    private static URL uriToUrl(Uri uri) throws MalformedURLException {
        return uri == null ? null : uri.toURL();
    }

    /**
     * Converts a {@link URL} to a {@link Uri}, throwing {@link IOException}
     * if the conversion fails.
     *
     * <p>Called from {@link #readExternal} where a parse failure indicates a
     * malformed stream and must not be silently swallowed.
     *
     * @throws IOException if {@code url} is non-null but cannot be represented
     *                     as a valid RFC 3986 URI
     */
    private static Uri uriFromUrl(URL url) throws IOException {
        if (url == null) {
            return null;
        }
        try {
            return Uri.urlToUri(url);
        } catch (URISyntaxException e) {
            throw new IOException(
                    "Cannot convert URL to RFC 3986 URI in DigestCodeSource stream: "
                    + url, e);
        }
    }

    private int computeHashCode() {
        int h = 7;
        h = 31 * h + (uri != null ? uri.hashCode() : 0);
        h = 31 * h + Arrays.hashCode(cachedCerts());   // use cached copy
        h = 31 * h + (digestAlgorithm != null ? digestAlgorithm.hashCode() : 0);
        h = 31 * h + Arrays.hashCode(digest);
        return h;
    }

    private static boolean stringsEqual(String a, String b) {
        return a == b || (a != null && a.equals(b));
    }

    /**
     * Sentinel stored in {@link #cachedCerts} when {@link #getCertificates()}
     * returns {@code null} (no certificates).  Distinguishes "not yet computed"
     * ({@code cachedCerts == null}) from "computed and empty"
     * ({@code cachedCerts == NO_CERTS}), preventing the cache from being
     * permanently bypassed in the common no-certificate case.
     */
    private static final Certificate[] NO_CERTS = new Certificate[0];

    /**
     * Returns the cached certificate array, computing and caching it on the
     * first call.  Avoids repeated defensive copies from
     * {@link CodeSource#getCertificates()} in {@link #equals} and
     * {@link #computeHashCode}.
     *
     * <p>{@code null} is returned (and stored as {@link #NO_CERTS}) when the
     * underlying {@code CodeSource} carries no certificates, preserving the
     * contract of {@link #getCertificates()}.
     */
    private Certificate[] cachedCerts() {
        Certificate[] c = cachedCerts;          // single volatile read
        if (c == null) {
            Certificate[] got = getCertificates();
            cachedCerts = c = (got == null) ? NO_CERTS : got;
        }
        return (c == NO_CERTS) ? null : c;
    }
}
