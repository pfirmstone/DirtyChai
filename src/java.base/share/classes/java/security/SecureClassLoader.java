/*
 * Copyright (c) 1997, 2023, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
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
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.security;

import au.zeus.jdk.authorization.guards.LoadClassPermission;
import au.zeus.jdk.authorization.spire.SpiffeCredentialManager;
import au.zeus.jdk.net.Uri;
import java.io.FilePermission;
import java.io.IOException;
import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLPermission;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Locale;
import sun.security.util.Debug;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import javax.security.auth.Subject;
import jdk.internal.misc.CDS;
import jdk.internal.misc.VM;

/**
 * This class extends {@code ClassLoader} with additional support for defining
 * classes with an associated code source and permissions which are
 * retrieved by the system policy by default.
 *
 * @author  Li Gong
 * @author  Roland Schemers
 * @since 1.2
 */
public class SecureClassLoader extends ClassLoader {
    
    private static final Permission LOAD_CLASS_ALLOW = new LoadClassPermission();

    /*
     * Map that maps the CodeSource to a ProtectionDomain. The key is a
     * CodeSourceKey class that uses a {@code String} instead of a URL to avoid
     * potential expensive name service lookups. This does mean that URLs that
     * are equivalent after nameservice lookup will be placed in separate
     * ProtectionDomains; however during policy enforcement these URLs will be
     * canonicalized and resolved resulting in a consistent set of granted
     * permissions.
     */
    private final Map<CodeSourceKey, ProtectionDomain> pdcache
            = new ConcurrentHashMap<>(11);

    static {
        ClassLoader.registerAsParallelCapable();
    }

    /**
     * Creates a new {@code SecureClassLoader} using the specified parent
     * class loader for delegation.
     *
     * <p>If there is a security manager, this method first
     * calls the security manager's {@code checkCreateClassLoader}
     * method  to ensure creation of a class loader is allowed.
     *
     * @apiNote If {@code parent} is specified as {@code null} (for the
     * bootstrap class loader) then there is no guarantee that all platform
     * classes are visible.
     * See {@linkplain ClassLoader##builtinLoaders Run-time Built-in Class Loaders}
     * for information on the bootstrap class loader and other built-in class loaders.
     *
     * @param parent the parent ClassLoader, can be {@code null} for the bootstrap
     *               class loader
     * @throws     SecurityException  if a security manager exists and its
     *             {@code checkCreateClassLoader} method doesn't allow
     *             creation of a class loader.
     * @see SecurityManager#checkCreateClassLoader
     */
    protected SecureClassLoader(ClassLoader parent) {
        super(parent);
    }

    /**
     * Creates a new {@code SecureClassLoader} using the
     * {@linkplain ClassLoader#getSystemClassLoader() system class loader as the parent}.
     *
     * <p>If there is a security manager, this method first
     * calls the security manager's {@code checkCreateClassLoader}
     * method  to ensure creation of a class loader is allowed.
     *
     * @throws     SecurityException  if a security manager exists and its
     *             {@code checkCreateClassLoader} method doesn't allow
     *             creation of a class loader.
     * @see SecurityManager#checkCreateClassLoader
     */
    protected SecureClassLoader() {
        super();
    }

    /**
     * Creates a new {@code SecureClassLoader} of the specified name and
     * using the specified parent class loader for delegation.
     *
     * @apiNote If {@code parent} is specified as {@code null} (for the
     * bootstrap class loader) then there is no guarantee that all platform
     * classes are visible.
     * See {@linkplain ClassLoader##builtinLoaders Run-time Built-in Class Loaders}
     * for information on the bootstrap class loader and other built-in class loaders.
     *
     * @param name class loader name; or {@code null} if not named
     * @param parent the parent class loader, can be {@code null} for the bootstrap
     *               class loader
     *
     * @throws IllegalArgumentException if the given name is empty.
     *
     * @throws SecurityException  if a security manager exists and its
     *         {@link SecurityManager#checkCreateClassLoader()} method
     *         doesn't allow creation of a class loader.
     *
     * @since 9
     */
    protected SecureClassLoader(String name, ClassLoader parent) {
        super(name, parent);
    }

    /**
     * Converts an array of bytes into an instance of class {@code Class},
     * with an optional CodeSource. Before the
     * class can be used it must be resolved.
     * <p>
     * If a non-null CodeSource is supplied a ProtectionDomain is
     * constructed and associated with the class being defined.
     *
     * @param      name the expected name of the class, or {@code null}
     *                  if not known, using '.' and not '/' as the separator
     *                  and without a trailing ".class" suffix.
     * @param      b    the bytes that make up the class data. The bytes in
     *             positions {@code off} through {@code off+len-1}
     *             should have the format of a valid class file as defined by
     *             <cite>The Java Virtual Machine Specification</cite>.
     * @param      off  the start offset in {@code b} of the class data
     * @param      len  the length of the class data
     * @param      cs   the associated CodeSource, or {@code null} if none
     * @return the {@code Class} object created from the data,
     *         and optional CodeSource.
     * @throws     ClassFormatError if the data did not contain a valid class
     * @throws     IndexOutOfBoundsException if either {@code off} or
     *             {@code len} is negative, or if
     *             {@code off+len} is greater than {@code b.length}.
     *
     * @throws     SecurityException if an attempt is made to add this class
     *             to a package that contains classes that were signed by
     *             a different set of certificates than this class, or if
     *             the class name begins with "java.".
     */
    protected final Class<?> defineClass(String name,
                                         byte[] b, int off, int len,
                                         CodeSource cs)
    {
        return defineClass(name, b, off, len, getProtectionDomain(cs, null));
    }

    /**
     * Converts an array of bytes into an instance of class {@code Class},
     * with an optional CodeSource and process Principal's. Before the
     * class can be used it must be resolved.
     * <p>
     * If a non-null CodeSource is supplied a ProtectionDomain is
     * constructed and associated with the class being defined.
     *
     * @param      name the expected name of the class, or {@code null}
     *                  if not known, using '.' and not '/' as the separator
     *                  and without a trailing ".class" suffix.
     * @param      b    the bytes that make up the class data. The bytes in
     *             positions {@code off} through {@code off+len-1}
     *             should have the format of a valid class file as defined by
     *             <cite>The Java Virtual Machine Specification</cite>.
     * @param      off  the start offset in {@code b} of the class data
     * @param      len  the length of the class data
     * @param      cs   the associated CodeSource, or {@code null} if none
     * @param      p    JVM process principals.
     * @return the {@code Class} object created from the data,
     *         and optional CodeSource.
     * @throws     ClassFormatError if the data did not contain a valid class
     * @throws     IndexOutOfBoundsException if either {@code off} or
     *             {@code len} is negative, or if
     *             {@code off+len} is greater than {@code b.length}.
     *
     * @throws     SecurityException if an attempt is made to add this class
     *             to a package that contains classes that were signed by
     *             a different set of certificates than this class, or if
     *             the class name begins with "java.".
     */
    protected final Class<?> defineClass(String name,
                                         byte[] b, int off, int len,
                                         CodeSource cs, Principal [] p)
    {
        return defineClass(name, b, off, len, getProtectionDomain(cs, p));
    }

    /**
     * Converts a {@link java.nio.ByteBuffer ByteBuffer}
     * into an instance of class {@code Class}, with an optional CodeSource.
     * Before the class can be used it must be resolved.
     * <p>
     * If a non-null CodeSource is supplied a ProtectionDomain is
     * constructed and associated with the class being defined.
     *
     * @param      name the expected name of the class, or {@code null}
     *                  if not known, using '.' and not '/' as the separator
     *                  and without a trailing ".class" suffix.
     * @param      b    the bytes that make up the class data.  The bytes from positions
     *                  {@code b.position()} through {@code b.position() + b.limit() -1}
     *                  should have the format of a valid class file as defined by
     *                  <cite>The Java Virtual Machine Specification</cite>.
     * @param      cs   the associated CodeSource, or {@code null} if none
     * @return the {@code Class} object created from the data,
     *         and optional CodeSource.
     * @throws     ClassFormatError if the data did not contain a valid class
     * @throws     SecurityException if an attempt is made to add this class
     *             to a package that contains classes that were signed by
     *             a different set of certificates than this class, or if
     *             the class name begins with "java.".
     *
     * @since  1.5
     */
    protected final Class<?> defineClass(String name, java.nio.ByteBuffer b,
                                         CodeSource cs)
    {
        return defineClass(name, b, getProtectionDomain(cs, null));
    }
    
    /**
     * Converts a {@link java.nio.ByteBuffer ByteBuffer}
     * into an instance of class {@code Class}, with an optional CodeSource
     * and process Principal's.
     * Before the class can be used it must be resolved.
     * <p>
     * If a non-null CodeSource is supplied a ProtectionDomain is
     * constructed and associated with the class being defined.
     *
     * @param      name the expected name of the class, or {@code null}
     *                  if not known, using '.' and not '/' as the separator
     *                  and without a trailing ".class" suffix.
     * @param      b    the bytes that make up the class data.  The bytes from positions
     *                  {@code b.position()} through {@code b.position() + b.limit() -1}
     *                  should have the format of a valid class file as defined by
     *                  <cite>The Java Virtual Machine Specification</cite>.
     * @param      cs   the associated CodeSource, or {@code null} if none
     * @param      p    JVM process principals.
     * @return the {@code Class} object created from the data,
     *         and optional CodeSource.
     * @throws     ClassFormatError if the data did not contain a valid class
     * @throws     SecurityException if an attempt is made to add this class
     *             to a package that contains classes that were signed by
     *             a different set of certificates than this class, or if
     *             the class name begins with "java.".
     */
    protected final Class<?> defineClass(String name, java.nio.ByteBuffer b,
                                         CodeSource cs, Principal [] p)
    {
        return defineClass(name, b, getProtectionDomain(cs, p));
    }

    /**
     * Returns the permissions for the given CodeSource object.
     * <p>
     * This method is invoked by the defineClass method which takes
     * a CodeSource as an argument when it is constructing the
     * ProtectionDomain for the class being defined.
     *
     * @param codesource the codesource.
     *
     * @return the permissions granted to the codesource.
     *
     */
    protected PermissionCollection<Permission> getPermissions(CodeSource codesource)
    {
        return new Permissions(); // ProtectionDomain defers the binding
    }

    /*
     * holder class for the static field "debug" to delay its initialization
     */
    private static class DebugHolder {
        private static final Debug debug = Debug.getInstance("scl");
    }

    /*
     * Returned cached ProtectionDomain for the specified CodeSource.
     */
    @SuppressWarnings("removal")
    private ProtectionDomain getProtectionDomain(CodeSource cs, Principal [] p) {
        if (cs == null && (p == null || p.length == 0)) return null;
        Set<Principal> principals = null;
        if (p != null && p.length > 0) principals = new LinkedHashSet<>(); // preserve order.
        
        CodeSourceKey key;
        try {
            key = new CodeSourceKey(cs);
        } catch (URISyntaxException ex) {
            throw new SecurityException("URI Syntax error: ", ex);
        }

        // Always check the cache first — permission checks (URLPermission and
        // LOAD_CLASS_ALLOW) are performed only on the first construction of a
        // ProtectionDomain for a given CodeSource key.  Subsequent defineClass
        // calls for the same source return the already-vetted domain directly.
        // This is safe: the pdcache is an instance field of this ClassLoader and
        // cannot be externally mutated; an entry is only ever placed here after
        // all permission checks have already passed.
        ProtectionDomain domain = pdcache.get(key);
        if (domain != null) return domain;

        SecurityManager sm = System.getSecurityManager();
        PermissionCollection<Permission> perms = SecureClassLoader.this.getPermissions(cs);
        ProtectionDomain pd;
        DigestCodeSource digest = null;
        if (sm != null) {
            // SpiffeCredentialManager.getInstance() opens a SocketChannel which
            // calls SelectorProvider.provider() → getSystemClassLoader().  During
            // initPhase3 the system class loader is not yet ready, so defer the
            // SPIFFE subject lookup until the VM is fully booted.
            Subject sub = VM.isBooted() ? SpiffeCredentialManager.getInstance().getSubject() : null;
            Principal[] pals = null;
            if (sub != null && sub.isReadOnly()) {
                Set<Principal> prin = sub.getPrincipals();
                if (principals != null) {
                    principals.addAll(prin);
                    principals.addAll(Arrays.asList(p));
                    prin = principals;
                }
                pals = prin.toArray(new Principal[0]);
            }
            pd = new ProtectionDomain(cs, perms, SecureClassLoader.this, pals);
            if (cs.location != null) {
                Permission checkURL;
                String scheme = key.uri.getScheme();
                if ("file".equals(scheme)){
                    String host = key.uri.getHost();
                    if (host != null && !host.isEmpty() && File.separatorChar == '\\' && key.uri.getUserInfo() == null
                        && key.uri.getPort() == -1 && key.uri.getQuery() == null && key.uri.getFragment() == null) {
                        // UNC path, e.g. file://host/share/file.txt
                        String raw = key.uri.getRawPath();
                        String lower = raw.toLowerCase(Locale.ROOT);
                        if (lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00"))
                            throw new SecurityException("Codebase path contains an encoded separator or NUL: " + key.uri);
                        checkURL = new FilePermission(new File("\\\\" + host + key.uri.getPath().replace('/', '\\')).getPath(), "read");
                    } else {
                        try {
                            checkURL = new FilePermission(Uri.uriToFile(key.uri).getPath(), "read");
                        } catch (IllegalArgumentException ex) {
                            throw new SecurityException("Codebase is not a local file: " + key.uri, ex);
                        }
                    }
                } else {
                    checkURL = new URLPermission(key.uri.toString(), "GET:");
                }
                sm.checkPermission(checkURL,
                        AccessControlContext.create(new ProtectionDomain[]{pd}, false));
                // Promote plain CodeSource to DigestCodeSource by computing its
                // content digest.  For jrt:/jmod: URIs DigestCodeSource walks
                // every module entry via ModuleReader; for file: and remote URLs
                // it reads the stream directly.  The algorithm is hard-coded to
                // "SHA-256" for now; making it configurable is a planned follow-up.
                try {
                    digest = new DigestCodeSource(key.uri, key.certs, "SHA-256");
                    perms = SecureClassLoader.this.getPermissions(digest);
                } catch (IOException ex) {
                    throw new SecurityException("Unable to contact URL: ", ex);
                } catch (NoSuchAlgorithmException ex) {
                    throw new SecurityException(
                            "URL Provider not loaded or unknown algorithm: ", ex);
                }
                pd = new ProtectionDomain(digest, perms, SecureClassLoader.this, pals);
                sm.checkPermission(LOAD_CLASS_ALLOW,
                        AccessControlContext.create(new ProtectionDomain[]{pd}, false));
            } else {
                sm.checkPermission(LOAD_CLASS_ALLOW,
                        AccessControlContext.create(new ProtectionDomain[]{pd}, false));
            }
        } else {
            pd = new ProtectionDomain(cs, perms, SecureClassLoader.this, null);
        }
        if (DebugHolder.debug != null) {
            DebugHolder.debug.println(" getPermissions " + pd);
            DebugHolder.debug.println("");
        }
        ProtectionDomain existed = pdcache.putIfAbsent(key, pd);
        if (existed != null) return existed;
        return pd;
    }

    private static class CodeSourceKey {
        
        private final Uri uri;
        private final java.security.cert.Certificate [] certs;
         // Populated only when the incoming CodeSource is a DigestCodeSource.
        private final String digestAlgorithm;
        private final byte[] digest;
        private final int hashCode;
        final CodeSource cs; // package-private: used by resetArchivedStates
        
        private CodeSourceKey(CodeSource cs) throws URISyntaxException {
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
    }

    /**
     * Called by the VM, during -Xshare:dump
     */
    private void resetArchivedStates() {
        if (CDS.isDumpingAOTLinkedClasses()) {
            for (CodeSourceKey key : pdcache.keySet()) {
                if (key.cs.getCodeSigners() != null) {
                    // We don't archive any signed classes, so we don't need to cache their ProtectionDomains.
                    pdcache.remove(key);
                }
            }
            if (System.getProperty("cds.debug.archived.protection.domains") != null) {
                for (CodeSourceKey key : pdcache.keySet()) {
                    System.out.println("Archiving ProtectionDomain " + key.cs + " for " + this);
                }
            }
        } else {
            pdcache.clear();
        }
    }
}
