/*
 * Copyright (c) 2026, Oracle and/or its affiliates. All rights reserved.
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

import au.zeus.jdk.net.Uri;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * This class is not part of the Java Standards.
 * 
 * DomainIdentity provides Object equals and hashCode identity based on the equality of 
 * its fields.
 * <p>
 * This domain is provided to support virtual threads, to limit duplication of
 * ProtectionDomain's stored in AccessControlContext's cache.
 * <p>
 * This domain is intended to be used for temporary domain's and temporary 
 * contexts, used while performing a privileged action, it is not intended to
 * be used to represent a domain within a ClassLoader.
 * 
 * @author peter
 */
public final class DomainIdentity extends ProtectionDomain {
    
    /**
     * Generates unique hash codes for Permissions without calling their
     * hashcode method.
     * 
     * @param perms the PermissionCollection
     * @return hash code.
     */
    static int permissionsHashCode(PermissionCollection<? extends Permission> perms){
        if (perms == null) return 0;
        int hashCode = 13;
        Enumeration<? extends Permission> e = perms.elements();
        while (e.hasMoreElements()){
            hashCode ^= permissionHashCode(e.nextElement());
        }
        return hashCode;
    }

    /**
     * Generates unique hash codes for Permission without calling their
     * hashcode method.
     * 
     * @param perm the Permission
     * @return hash code.
     */
    static int permissionHashCode(Permission perm){
        if (perm == null) return 0;
        int hashCode = 5;
        hashCode = hashCode * 5 + perm.getClass().hashCode();
        hashCode = hashCode * 5 + perm.getName().hashCode();
        hashCode = hashCode * 5 + perm.getActions().hashCode();
        if (perm instanceof javax.security.auth.PrivateCredentialPermission pcp){
            hashCode = hashCode * 5 + Arrays.deepHashCode(pcp.getPrincipals());
            String credClass = pcp.getCredentialClass();
            if (credClass != null) hashCode = hashCode * 5 + credClass.hashCode();
        }
        return hashCode;   
    }
    
    /**
     * A SortedSet doesn't call hashCode on elements, this is important to
     * avoid DNS calls or File system access that occurs with some Permission
     * implementations like SocketPermission or FilePermission.
     * 
     * @param p
     * @return a SortedSet
     */
    static SortedSet<Permission> permissionsToSet(PermissionCollection<? extends Permission> p){
        SortedSet<Permission> result = new TreeSet<>(PERM_COMPARE);
        Enumeration<? extends Permission> e = p.elements();
        while (e.hasMoreElements()){
            result.add(e.nextElement());
        }
        return result;
    }

    /* Object fields */ 
    private final int hashcode;
    private final Set<Principal> principals;
    private final SortedSet<Permission> permissions;
    private final CodeSource uriCS;
    private final ProtectionDomain callerDomain;
    
    /**
     * Creates a new {@code ProtectionDomain} qualified by the given
     * {@code CodeSource}, permissions, {@code ClassLoader} and array
     * of principals. If permissions is not {@code null}, then
     * {@code setReadOnly()} will be called on the passed in permissions.
     * <p>
     * The permissions granted to this domain include both the permissions
     * passed to this constructor, and any permissions granted to this domain
     * by the current policy at the time a permission is checked.
     * <p>
     * This constructor is typically used by
     * {@link SecureClassLoader ClassLoaders}
     * and {@link DomainCombiner DomainCombiners} which delegate to the
     * {@code Policy} object to actively associate the permissions granted to
     * this domain. This constructor affords the
     * policy provider the opportunity to augment the supplied
     * {@code PermissionCollection} to reflect policy changes.
     *
     * @param codesource the {@code CodeSource} associated with this domain
     * @param permissions the permissions granted to this domain
     * @param classloader the {@code ClassLoader} associated with this domain
     * @param principals the array of {@code Principal} objects associated
     * with this domain. The contents of the array are copied to protect against
     * subsequent modification.
     * @see Policy#refresh
     * @see Policy#getPermissions(ProtectionDomain)
     * @since 25
     */
    @SuppressWarnings("unchecked")
    public DomainIdentity(CodeSource codesource,
                          PermissionCollection<? extends Permission> permissions,
                          ClassLoader classloader,
                          Principal[] principals) 
    {
        this(codesource, permissions, classloader, principals, null);
    }

    /**
     * Creates a new {@code ProtectionDomain} qualified by the given
     * {@code CodeSource}, permissions, {@code ClassLoader} and array
     * of principals. If permissions is not {@code null}, then
     * {@code setReadOnly()} will be called on the passed in permissions.
     * <p>
     * The permissions granted to this domain include both the permissions
     * passed to this constructor, and any permissions granted to this domain
     * by the current policy at the time a permission is checked.
     * <p>
     * This constructor is typically used by
     * {@link SecureClassLoader ClassLoaders}
     * and {@link DomainCombiner DomainCombiners} which delegate to the
     * {@code Policy} object to actively associate the permissions granted to
     * this domain. This constructor affords the
     * policy provider the opportunity to augment the supplied
     * {@code PermissionCollection} to reflect policy changes.
     *
     * @param codesource the {@code CodeSource} associated with this domain
     * @param permissions the permissions granted to this domain
     * @param classloader the {@code ClassLoader} associated with this domain
     * @param principals the array of {@code Principal} objects associated
     * with this domain. The contents of the array are copied to protect against
     * subsequent modification.
     * @param callerDomain that called an {@link AccessController AccessController#doPrivileged} method.
     * @see Policy#refresh
     * @see Policy#getPermissions(ProtectionDomain)
     * @since 27
     */
    DomainIdentity(CodeSource codesource,
                          PermissionCollection<? extends Permission> permissions,
                          ClassLoader classloader,
                          Principal[] principals,
                          ProtectionDomain callerDomain){
        super(codesource, permissions, classloader, principals);
        this.principals = principals != null ? new HashSet<>(Arrays.asList(principals)): null; 
        this.permissions = permissions != null ? permissionsToSet(permissions) : null;
        this.uriCS = codesource instanceof DigestCodeSource ? codesource : 
                codesource!= null ? new UriCodeSource(codesource) : null;
        this.callerDomain = callerDomain;
        int hash = 7;
        hash = 7 * hash + (hasAllPerm() ? 1231 : 1237);
        hash = 7 * hash + getClass().hashCode();
        hash = 7 * hash + Objects.hashCode(this.uriCS);
        if (this.uriCS == null && codesource != null) hash = 7 * hash + codesource.hashCode();
        hash = 7 * hash + permissionsHashCode(permissions);
        hash = 7 * hash + Objects.hashCode(classloader);
        hash = 7 * hash + Objects.hashCode(this.principals);
        hash = 7 * hash + Objects.hashCode(callerDomain);
        hashcode = hash;
    }
    
    /**
     * Creates a new {@code ProtectionDomain} qualified by the given
     * {@code CodeSource} and permissions. If permissions is not {@code null}, then
     * {@code setReadOnly()} will be called on the passed in permissions.
     * <p>
     * The permissions granted to this domain include both the permissions
     * passed to this constructor.
     *
     * @param codesource the {@code CodeSource} associated with this domain
     * @param permissions the permissions granted to this domain
     * 
     */
    @SuppressWarnings("unchecked")
    public DomainIdentity(CodeSource codesource,
                          PermissionCollection<? extends Permission> permissions) 
    {
        super(codesource, permissions);
        this.principals = null;
        this.callerDomain = null;
        this.permissions = permissions != null ? permissionsToSet(permissions) : null;
        this.uriCS = codesource instanceof DigestCodeSource ? codesource : 
                codesource!= null ? new UriCodeSource(codesource) : null;
        int hash = 5;
        hash = 5 * hash + (hasAllPerm() ? 1231 : 1237);
        hash = 5 * hash + getClass().hashCode();
        hash = 5 * hash + Objects.hashCode(this.uriCS);
        if (this.uriCS == null && codesource != null) hash = 7 * hash + codesource.hashCode();
        hash = 5 * hash + permissionsHashCode(permissions);
        hashcode = hash;
    }
    
    @Override
    public int hashCode() {
        return hashcode;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (obj instanceof DomainIdentity other){
            if (hashcode != other.hashcode) return false;
            if (staticPermissionsOnly() != other.staticPermissionsOnly()) return false;
            if (!Objects.equals(this.getClassLoader(), other.getClassLoader())) return false;
            if (!Objects.equals(this.uriCS, other.uriCS)) return false;
            if (this.uriCS == null && this.getCodeSource() != null 
                    && other.uriCS == null && other.getCodeSource()!= null)
            {
                if (!Objects.equals(this.getCodeSource(), other.getCodeSource())) return false;
            }
            if (!Objects.equals(this.principals, other.principals)) return false;
            if (hasAllPerm() && other.hasAllPerm()) return true;
            if (!Objects.equals(this.callerDomain, other.callerDomain)) return false;
            return Objects.equals(permissions, other.permissions);
        }
        return false;
    }

    /**
     * Returns the Class that made a limited doPrivilged call, may be null.
     * @return the Class that made a limited doPrivilged call, may be null.
     */
    public ProtectionDomain getCallerDomain(){
        return callerDomain;
    }
    
    /**
     * To avoid CodeSource equals and hashCode methods.
     * 
     * Shamelessly stolen from RFC3986URLClassLoader
     * 
     * CodeSource uses DNS lookup calls to check location IP addresses are 
     * equal.
     * 
     * This class must not be serialized.
     * @author Peter Firmstone.
     */
    @SuppressWarnings("serial")
    private static class UriCodeSource extends CodeSource{
        private final Uri uri;
        private final int hashCode;
        
        UriCodeSource(CodeSource cs){
            this(cs.getLocation(), cs.getCertificates());
        }
        
        private UriCodeSource(URL url, java.security.cert.Certificate [] certs){
            super(url, certs);
            Uri uRi = null;
            if (url != null){
                try {
                    uRi = Uri.urlToUri(url);
                } catch (URISyntaxException ex) { }//Ignore
            }
            this.uri = uRi;
            int hash = 7;
            hash = 23 * hash + (this.uri != null ? this.uri.hashCode() : 0);
            hash = 23 * hash + (certs != null ? Arrays.hashCode(certs) : 0);
            hashCode = hash;
        }

        @Override
        public int hashCode() {
            return hashCode;
        }
        
        @Override
        public boolean equals(Object o){
            if (!(o instanceof UriCodeSource)) return false;
            if (uri == null) return super.equals(o); // In case of URISyntaxException
            UriCodeSource that = (UriCodeSource) o; 
            if ( !uri.equals(that.uri)) return false;
            java.security.cert.Certificate [] mine = getCertificates();
            java.security.cert.Certificate [] theirs = that.getCertificates();
            return Arrays.equals(mine, theirs);
        }

        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            throw new NotSerializableException(
            "UriCodeSource must not be serialized — use standard CodeSource for serialization");
        }

        @Serial
        private void readObject(ObjectInputStream in) throws IOException {
            throw new NotSerializableException(
                "UriCodeSource must not be deserialized");
        }
       
    }

    
}
