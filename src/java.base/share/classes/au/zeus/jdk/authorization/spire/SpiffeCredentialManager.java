/*
 * Copyright (c) 2025, Peter Firmstone.
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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 */
package au.zeus.jdk.authorization.spire;

import au.zeus.jdk.net.Uri;
import javax.security.auth.Subject;
import javax.security.auth.WorkerSubject;
import javax.security.auth.x500.X500Principal;
import javax.security.auth.x500.X500PrivateCredential;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Singleton manager for SPIFFE credentials obtained from the SPIRE Workload
 * API. Maintains the current X.509 SVID as a read-only {@link WorkerSubject}
 * and watches for SVID rotation in the background.
 *
 * <p>
 * When a new SVID is received, all registered listeners are notified so they
 * can refresh their policy grants. This enables automatic policy refresh on
 * SVID rotation without polling.
 *
 * <p>
 * Bootstrap-safe: no lambdas, method references, string switches, or
 * invokedynamic constructs. Can be used during early JVM initialization. Uses
 * {@code sun.security.util.Debug} for diagnostic output rather than
 * {@code System.getLogger()} which is not available during bootstrap.
 *
 * <p>
 * SPIRE unavailability at startup is tolerated — the manager operates in a
 * degraded mode and schedules reconnection automatically. TLS will fail
 * gracefully until SPIRE provides credentials. Callers should check
 * {@link #getSubject()} for {@code null} before use.
 *
 * <p>
 * Configuration via system properties:
 * <ul>
 * <li>{@code spiffe.workload.socket} — path to SPIRE agent socket (default:
 * {@code /run/spire/sockets/agent.sock})
 * <li>{@code spiffe.policy.url} — bootstrap policy URL (overrides derivation
 * from SPIFFE ID)
 * <li>{@code spiffe.reconnect.max.attempts} — maximum reconnection attempts
 * (default: 10, set to 0 to disable reconnection)
 * <li>{@code spiffe.reconnect.initial.backoff.ms} — initial backoff delay
 * (default: 1000 ms)
 * <li>{@code spiffe.reconnect.max.backoff.ms} — maximum backoff delay (default:
 * 300000 ms = 5 minutes)
 * </ul>
 *
 * <p>
 * Diagnostic output is controlled by the standard JDK security debug property:
 * {@code -Djava.security.debug=spiffe}
 *
 * @author Peter Firmstone
 * @since 27
 */
public final class SpiffeCredentialManager implements AutoCloseable {

    // Bootstrap-safe debug channel — available before System.getLogger() is ready.
    // Controlled by -Djava.security.debug=spiffe
    private static final sun.security.util.Debug debug
            = sun.security.util.Debug.getInstance("spiffe", "SPIFFE/SPIRE Credential Manager");

    private static final String DEFAULT_SOCKET_PATH = "/run/spire/sockets/agent.sock";
    private static final String SOCKET_PROPERTY = "spiffe.workload.socket";
    private static final String POLICY_URL_PROPERTY = "spiffe.policy.url";
    private static final String RECONNECT_MAX_ATTEMPTS_PROPERTY = "spiffe.reconnect.max.attempts";
    private static final String RECONNECT_INITIAL_BACKOFF_PROPERTY = "spiffe.reconnect.initial.backoff.ms";
    private static final String RECONNECT_MAX_BACKOFF_PROPERTY = "spiffe.reconnect.max.backoff.ms";

    private static final int DEFAULT_MAX_RECONNECT_ATTEMPTS = 10;
    private static final long DEFAULT_INITIAL_BACKOFF_MS = 1000L;
    private static final long DEFAULT_MAX_BACKOFF_MS = 300_000L; // 5 minutes

    // Singleton — never null; may have null subjectBundle until SPIRE connects.
    private static final SpiffeCredentialManager INSTANCE = new SpiffeCredentialManager();

    // Holds the current SVID state atomically.  Null until first successful fetch.
    private final AtomicReference<R> subjectBundle = new AtomicReference<R>();

    private volatile SpireWorkloadApiClient client;

    private final List<SvidRotationListener> listeners = new ArrayList<SvidRotationListener>();
    private final Object listenerLock = new Object();

    // Reconnection state
    private volatile boolean watcherRunning = false;
    private final AtomicInteger reconnectAttempts = new AtomicInteger();
    private final int maxReconnectAttempts;
    private final long initialBackoffMs;
    private final long maxBackoffMs;

    // Immutable snapshot of a single SVID fetch result
    private static final class R {

        private final Subject currentSubject;
        private final String currentSpiffeId;
        private final X509Certificate[] trustBundle;
        private final Subject credentialSubject;

        R(Subject s, Subject cs, String id, X509Certificate[] certs) {
            this.currentSubject = s;
            this.credentialSubject = cs;
            this.currentSpiffeId = id;
            this.trustBundle = certs;
        }
    }

    /**
     * Private constructor for singleton. Attempts to connect to the SPIRE agent
     * and perform an initial SVID fetch. If SPIRE is unavailable, the manager
     * enters degraded mode and schedules automatic reconnection. The
     * constructor never throws — all failures are logged via
     * {@code sun.security.util.Debug}
     */
    private SpiffeCredentialManager() {

        // Load reconnection configuration
        int mra = getIntProperty(RECONNECT_MAX_ATTEMPTS_PROPERTY, DEFAULT_MAX_RECONNECT_ATTEMPTS);
        if (mra > 62) {
            mra = 62; // prevent bitshift overflow in backoff calculation
        }
        this.maxReconnectAttempts = mra;
        this.initialBackoffMs = getLongProperty(RECONNECT_INITIAL_BACKOFF_PROPERTY, DEFAULT_INITIAL_BACKOFF_MS);
        this.maxBackoffMs = getLongProperty(RECONNECT_MAX_BACKOFF_PROPERTY, DEFAULT_MAX_BACKOFF_MS);

        String socketPath = System.getProperty(SOCKET_PROPERTY, DEFAULT_SOCKET_PATH);
        
        this.client = createClient(socketPath);
        if (client instanceof UnavailableClient) scheduleReconnect(initialBackoffMs);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    close();
                } catch (Exception ex) {
                    if (debug != null) {
                        debug.println(
                                "SpiffeCredentialManager exception thrown during shutdown hook close",
                                ex.getMessage());
                    }
                }
            }
        }, "SPIRE-Shutdown"));
    }

    private final SpireWorkloadApiClient createClient(String socketPath) {
        SpireWorkloadApiClient client = null;
        Path path = Path.of(socketPath);
        SpireWorkloadApiClient c = null;
        try {
            c = new SpireWorkloadApiClient(path);
            SpireProtobuf.X509SVIDResponse response = c.fetchSVID();
            updateSubjectInternal(response);
            this.watcherRunning = true;
            c.startWatching(createCallback());
            if (debug != null) {
                debug.println("Connected to SPIRE agent at " + socketPath);
            }
            client = c;
        } catch (SpiffeConnectionException e) {
            // SPIRE not available at startup — degrade gracefully and retry
            if (debug != null) {
                debug.println("WARNING: SPIFFE/SPIRE agent unavailable at "
                        + socketPath + " — local worker identity not established."
                        + " TLS will fail until SPIRE connects. Reconnection scheduled." + e);
            }
            if (c != null) c.close();
            // Assign even if null — reconnectWatcher() rebuilds client as needed
        }
        return client != null ? client : new UnavailableClient(path);
    }

    /**
     * Returns the singleton instance. Never {@code null}.
     *
     * @return the credential manager instance
     */
    public static SpiffeCredentialManager getInstance() {
        return INSTANCE;
    }

    /**
     * Returns the current SPIFFE {@link LocalWorkerSubject} containing X.509
     * SVID credentials, or {@code null} if no SVID has been obtained from SPIRE
     * yet.
     *
     * <p>
     * The returned Subject is read-only and contains:
     * <ul>
     * <li>Public credentials: {@link java.security.cert.CertPath} (leaf +
     * intermediates)
     * <li>Private credentials: {@link X500PrivateCredential} for the leaf
     * certificate
     * <li>Principal: {@link X500Principal} from the leaf certificate
     * </ul>
     *
     * <p>
     * Callers must check for {@code null} — this occurs when SPIRE has not yet
     * provided credentials (startup race or SPIRE unavailability).
     *
     * @return current SPIFFE Subject, or {@code null} if unavailable
     */
    public Subject getSubject() {
        R r = subjectBundle.get();
        return r != null ? r.currentSubject : null;
    }

    /**
     * Returns the current SPIFFE credential {@link Subject} containing X.509
     * SVID credentials, or {@code null} if no SVID has been obtained from SPIRE
     * yet.
     *
     * <p>
     * The returned Subject is read-only and contains:
     * <ul>
     * <li>Public credentials: {@link java.security.cert.CertPath} (leaf +
     * intermediates)
     * <li>Private credentials: {@link X500PrivateCredential} for the leaf
     * certificate
     * <li>Principal: {@link X500Principal} from the leaf certificate
     * </ul>
     *
     * <p>
     * Callers must check for {@code null} — this occurs when SPIRE has not yet
     * provided credentials (startup race or SPIRE unavailability).
     *
     * @return current SPIFFE Subject, or {@code null} if unavailable
     */
    public Subject getCredentialSubject() {
        R r = subjectBundle.get();
        return r != null ? r.credentialSubject : null;
    }

    /**
     * Returns the SPIFFE ID URI of the current SVID, or {@code null} if
     * unavailable.
     *
     * @return SPIFFE ID (e.g.,
     * {@code "spiffe://jgdms.example.org/host/policy"}), or {@code null}
     */
    public String getSpiffeId() {
        R r = subjectBundle.get();
        return r != null ? r.currentSpiffeId : null;
    }

    /**
     * Returns the SPIRE trust bundle (root CA certificates). The returned array
     * is a defensive copy — modifications will not affect internal state.
     *
     * <p>
     * The trust bundle is used to validate peer SPIFFE SVIDs. It rotates
     * independently of the workload SVID and contains the root CA certificates
     * for the trust domain.
     *
     * @return defensive copy of the trust bundle; never {@code null} but may be
     * empty if no bundle has been received yet
     */
    public X509Certificate[] getTrustBundle() {
        R r = subjectBundle.get();
        if (r == null || r.trustBundle == null || r.trustBundle.length == 0) {
            return new X509Certificate[0];
        }
        X509Certificate[] copy = new X509Certificate[r.trustBundle.length];
        System.arraycopy(r.trustBundle, 0, copy, 0, r.trustBundle.length);
        return copy;
    }

    /**
     * Returns the bootstrap policy URL. Derivation order:
     * <ol>
     * <li>System property {@code spiffe.policy.url} (if set)
     * <li>Derived from the SPIFFE ID trust domain (if property not set)
     * </ol>
     *
     * <p>
     * Derivation example:
     * <pre>
     * SPIFFE ID:   spiffe://jgdms.example.org/host/policy
     * Derived URL: https://policy.jgdms.example.org/bootstrap/policy
     * </pre>
     *
     * @return bootstrap policy URL
     * @throws MalformedURLException if the URL cannot be constructed
     * @throws URISyntaxException if the URL string is not URI-3986 compliant
     * @throws IllegalStateException if no SPIFFE ID is available yet
     */
    public URL getPolicyUrl() throws MalformedURLException, URISyntaxException {
        // Option 1: explicit system property
        String explicitUrl = System.getProperty(POLICY_URL_PROPERTY);
        if (explicitUrl != null) {
            return Uri.parseAndCreate(explicitUrl).toURL();
        }

        // Option 2: derive from SPIFFE ID
        R r = subjectBundle.get();
        String spiffeId = (r != null) ? r.currentSpiffeId : null;
        if (spiffeId == null || !spiffeId.startsWith("spiffe://")) {
            throw new MalformedURLException("No SPIFFE ID available — SPIRE may not have connected yet. ID=" + spiffeId);
        }

        String withoutScheme = spiffeId.substring("spiffe://".length());
        int slashIndex = withoutScheme.indexOf('/');
        String trustDomain = (slashIndex == -1) ? withoutScheme : withoutScheme.substring(0, slashIndex);

        return Uri.parseAndCreate("https://policy." + trustDomain + "/bootstrap/policy").toURL();
    }

    /**
     * Registers a listener to be notified when the SVID rotates. Listeners are
     * notified on the background watcher thread and should return quickly
     * without blocking.
     *
     * <p>
     * Weak references are NOT used — callers must call
     * {@link #removeListener(SvidRotationListener)} to prevent leaks.
     *
     * @param listener listener to register; must not be {@code null}
     */
    public void addListener(SvidRotationListener listener) {
        if (listener == null) {
            throw new NullPointerException("listener");
        }
        synchronized (listenerLock) {
            if (!listeners.contains(listener)) {
                listeners.add(listener);
            }
        }
    }

    /**
     * Removes a previously registered listener.
     *
     * @param listener listener to remove; ignored if {@code null}
     */
    public void removeListener(SvidRotationListener listener) {
        if (listener == null) {
            return;
        }
        synchronized (listenerLock) {
            listeners.remove(listener);
        }
    }

    /**
     * Updates the current Subject and trust bundle from a SPIRE SVID response.
     * All checked exceptions are caught and logged — callers do not need to
     * handle failure. If parsing fails the existing Subject is preserved.
     *
     * @param response SVID response from SPIRE; ignored if {@code null} or
     * empty
     */
    private void updateSubjectInternal(SpireProtobuf.X509SVIDResponse response) {
        if (response == null || response.svids.isEmpty()) {
            // Do NOT overwrite the existing Subject — the current SVID remains valid
            // until it expires.
            if (debug != null) {
                debug.println(
                        "SPIRE returned empty SVID list — workload may not be registered. Existing SVID preserved.");
            }
            return;
        }

        SpireProtobuf.X509SVID svid = response.svids.get(0);

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // Parse certificate chain
            ByteArrayInputStream certStream = new ByteArrayInputStream(svid.certChain);
            List<X509Certificate> certList = new ArrayList<X509Certificate>();
            while (certStream.available() > 0) {
                certList.add((X509Certificate) cf.generateCertificate(certStream));
            }
            if (certList.isEmpty()) {
                if (debug != null) {
                    debug.println("SVID contains no certificates — ignoring update");
                }
                return;
            }

            X509Certificate leafCert = certList.get(0);

            // Parse private key (PKCS#8)
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(svid.privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance(leafCert.getPublicKey().getAlgorithm());
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Build credentials
            CertPath certPath = cf.generateCertPath(certList);
            Set<Object> pubCreds = new LinkedHashSet<Object>();
            pubCreds.add(certPath);

            Set<Object> privCreds = new LinkedHashSet<Object>();
            privCreds.add(new X500PrivateCredential(leafCert, privateKey));

            Set<Principal> principals = new LinkedHashSet<Principal>();
            principals.add(leafCert.getSubjectX500Principal());
            Collection<List<?>> names;
            try {
                names = leafCert.getSubjectAlternativeNames();
            } catch (CertificateParsingException e) {
                throw new IllegalArgumentException(
                        "Cannot parse SubjectAlternativeNames from certificate: "
                        + leafCert.getSubjectX500Principal(), e);
            }
            if (names != null) {
                Iterator<List<?>> altNamesIt = names.iterator();
                while (altNamesIt.hasNext()) {
                    List<?> altName = altNamesIt.next();
                    if (altName != null && altName.size() >= 2 && Integer.valueOf(6).equals(altName.get(0))) {
                        if (altName.get(1) instanceof String uri) {
                            if (uri.startsWith("spiffe://")) {
                                principals.add(new SpiffePrincipal(uri));
                                break;
                            }
                        }
                    }
                }
            }

            // Construct read-only WorkerSubject (SpiffeSubject is the sealed permit)
            Subject subject = new SpiffeSubject(
                    true,
                    Collections.unmodifiableSet(principals),
                    Collections.unmodifiableSet(pubCreds),
                    Collections.unmodifiableSet(privCreds)
            );

            Subject credentialSubject = new Subject(
                    true,
                    Collections.unmodifiableSet(principals),
                    Collections.unmodifiableSet(pubCreds),
                    Collections.unmodifiableSet(privCreds)
            );

            // Parse trust bundle
            X509Certificate[] bundle;
            if (svid.bundle != null && svid.bundle.length > 0) {
                ByteArrayInputStream bundleStream = new ByteArrayInputStream(svid.bundle);
                List<X509Certificate> bundleList = new ArrayList<X509Certificate>();
                while (bundleStream.available() > 0) {
                    bundleList.add((X509Certificate) cf.generateCertificate(bundleStream));
                }
                bundle = bundleList.toArray(new X509Certificate[bundleList.size()]);
            } else {
                bundle = new X509Certificate[0];
            }

            // Atomic update — visible immediately to all readers
            subjectBundle.set(new R(subject, credentialSubject, svid.spiffeId, bundle));
            if (debug != null) {
                debug.println("SVID updated: spiffeId=" + svid.spiffeId);
            }

        } catch (CertificateException e) {
            if (debug != null) {
                debug.println("Failed to parse SVID certificates: " + e);
            }
        } catch (NoSuchAlgorithmException e) {
            if (debug != null) {
                debug.println("Unsupported key algorithm in SVID: " + e);
            }
        } catch (InvalidKeySpecException e) {
            if (debug != null) {
                debug.println("Failed to parse SVID private key: " + e);
            }
        }
    }

    /**
     * Notifies all registered listeners that the SVID has rotated. Called on
     * the background watcher thread. One listener throwing an exception does
     * not prevent subsequent listeners from being notified.
     */
    private void notifyListeners() {
        List<SvidRotationListener> copy;
        synchronized (listenerLock) {
            copy = new ArrayList<SvidRotationListener>(listeners);
        }
        for (int i = 0; i < copy.size(); i++) {
            SvidRotationListener listener = copy.get(i);
            try {
                listener.onSvidRotation();
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Listener " + listener + " threw exception during SVID rotation: " + e);
                }
            }
        }
    }

    /**
     * Creates the {@link SpireWorkloadApiClient.SvidUpdateCallback} used by the
     * background watcher thread.
     */
    private SpireWorkloadApiClient.SvidUpdateCallback createCallback() {
        return new SpireWorkloadApiClient.SvidUpdateCallback() {

            @Override
            public void onUpdate(SpireProtobuf.X509SVIDResponse response) {
                updateSubjectInternal(response);
                reconnectAttempts.set(0); // reset on successful update
                notifyListeners();
            }

            @Override
            public void onError(SpiffeConnectionException error) {
                if (debug != null) {
                    debug.println("SVID watcher error: " + error);
                }
                watcherRunning = false;

                if (maxReconnectAttempts <= 0) {
                    if (debug != null) {
                        debug.println(
                                "Reconnection disabled (spiffe.reconnect.max.attempts=0). SVID will expire without renewal.");
                    }
                    return;
                }

                // Increment first so attempt 1 uses 1× delay, attempt 2 uses 2×, etc.
                // A concurrent successful update resets reconnectAttempts to 0 via
                // onUpdate(). If that races here the worst case is one extra reconnect
                // attempt, which is harmless.
                int attempt = reconnectAttempts.incrementAndGet();
                long backoffMs = Math.min(initialBackoffMs * (1L << (attempt - 1)), maxBackoffMs);

                if (attempt <= maxReconnectAttempts) {
                    if (debug != null) {
                        debug.println("Scheduling reconnect attempt " + attempt
                                + " of " + maxReconnectAttempts + " in " + backoffMs + "ms");
                    }
                    scheduleReconnect(backoffMs);
                } else {
                    if (debug != null) {
                        debug.println("ERROR: SPIFFE — max reconnect attempts ("
                                + maxReconnectAttempts + ") reached. SVID will expire without renewal.");
                    }
                }
            }
        };
    }

    /**
     * Schedules a reconnection attempt after the specified delay.
     * Bootstrap-safe: uses raw {@link Thread} + {@link Thread#sleep}, not
     * {@code ScheduledExecutorService}.
     *
     * <p>
     * The {@code !watcherRunning} guard is intentional: if a concurrent
     * successful update has already restarted the watcher (setting
     * {@code watcherRunning = true}), this thread must not start a second
     * watcher. The guard is a volatile read, sufficient for visibility. The
     * small window between the guard check and {@link #reconnectWatcher()} is
     * safe because {@code reconnectWatcher()} tolerates a redundant call.
     *
     * @param delayMs delay in milliseconds before attempting reconnection
     */
    private void scheduleReconnect(final long delayMs) {
        final int attemptNumber = reconnectAttempts.get();
        Thread reconnector = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Thread.sleep(delayMs);
                    if (!watcherRunning) {
                        reconnectWatcher();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    if (debug != null) {
                        debug.println("Reconnection attempt " + attemptNumber + " interrupted");
                    }
                }
            }
        });
        reconnector.setDaemon(true);
        reconnector.setName("SPIRE-Watcher-Reconnect-" + attemptNumber);
        reconnector.start();
    }

    /**
     * Attempts to reconnect to the SPIRE agent and restart the background
     * watcher. If the reconnection succeeds, {@link #subjectBundle} is updated
     * and all listeners are notified. If it fails, {@code onError} on the new
     * callback will schedule the next retry.
     */
    private void reconnectWatcher() {
        if (client instanceof UnavailableClient) {
            // Rebuild the client from the original socket path
            String socketPath = System.getProperty(SOCKET_PROPERTY, DEFAULT_SOCKET_PATH);
            try {
                client.close();
            } catch (Exception e) {
                if (debug != null) {
                    debug.println("Failed to close previous UnavailableClient: " + e);
                }
            }
            client = createClient(socketPath);
        } else {
            try {
                client.stopWatching();
                SpireProtobuf.X509SVIDResponse response = client.fetchSVID();
                updateSubjectInternal(response);

                watcherRunning = true;
                client.startWatching(createCallback());
                reconnectAttempts.set(0);

                if (debug != null) {
                    debug.println("SPIRE watcher reconnected successfully");
                }
                notifyListeners();
            } catch (SpiffeConnectionException e) {
                // onError on the new callback will be called automatically via the watcher
                if (debug != null) {
                    debug.println("Reconnection attempt failed: " + e);
                }
            }
        }
    }

    /**
     * Reads an integer system property, returning {@code defaultValue} if the
     * property is absent or unparseable. Bootstrap-safe.
     */
    private static int getIntProperty(String name, int defaultValue) {
        String value = System.getProperty(name);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            if (debug != null) {
                debug.println(
                        "Invalid integer property " + name + "=" + value
                        + ", using default " + defaultValue);
            }
            return defaultValue;
        }
    }

    /**
     * Reads a long system property, returning {@code defaultValue} if the
     * property is absent or unparseable. Bootstrap-safe.
     */
    private static long getLongProperty(String name, long defaultValue) {
        String value = System.getProperty(name);
        if (value == null) {
            return defaultValue;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            if (debug != null) {
                debug.println(
                        "Invalid long property " + name + "=" + value
                        + ", using default " + defaultValue);
            }
            return defaultValue;
        }
    }

    /**
     * Callback interface for SVID rotation notifications. Bootstrap-safe: no
     * default methods, no {@code @FunctionalInterface}.
     */
    public interface SvidRotationListener {

        /**
         * Invoked when a new SVID is received from SPIRE. Implementations
         * should refresh policy grants or other SVID-dependent state.
         *
         * <p>
         * Called on a background thread. Must return quickly and not block.
         */
        void onSvidRotation();
    }

    /**
     * Concrete sealed subtype of {@link WorkerSubject} for SPIFFE SVIDs. Only
     * constructible within {@code SpiffeCredentialManager} — enforces that the
     * local worker identity can only be established by SPIRE infrastructure.
     */
    public static final class SpiffeSubject extends WorkerSubject {

        private static final long serialVersionUID = 1L;

        private SpiffeSubject(boolean readOnly,
                Set<? extends Principal> principals,
                Set<?> pubCredentials,
                Set<?> privCredentials) {
            super(readOnly, principals, pubCredentials, privCredentials);
        }
    }

    /**
     * Stand-in {@link SpireWorkloadApiClient} used when the SPIRE agent was
     * unreachable at constructor time. {@link #fetchSVID()} always throws so
     * that {@link #reconnectWatcher()} retries via the standard error path. All
     * other methods are no-ops.
     */
    static final class UnavailableClient extends SpireWorkloadApiClient {

        private final Path socketPath;

        UnavailableClient(Path socketPath) {
            super(socketPath, true /* skipConnect */);
            this.socketPath = socketPath;
        }

        @Override
        SpireProtobuf.X509SVIDResponse fetchSVID() throws SpiffeConnectionException {
            throw new SpiffeConnectionException("SPIRE agent was unavailable at startup — reconnection pending");
        }

        @Override
        void startWatching(SpireWorkloadApiClient.SvidUpdateCallback callback) {
            // No-op — the reconnect thread will establish a real connection
        }

        @Override
        void stopWatching() {
            // No-op
        }

        @Override
        public void close() {
            // No-op
        }
    }

    @Override
    public void close() {
        client.close();
        if (debug != null) {
            debug.println("SpiffeCredentialManager closed");
        }
    }
}
