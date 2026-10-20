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
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.Objects;
import java.security.DigestCodeSource;
import au.zeus.jdk.net.Uri;
import au.zeus.jdk.authorization.policy.CodeSourceKey;

/**
 * DigestDomainGrant is a subclass of ProtectionDomainGrant that represents
 * a grant of permissions to a specific ClassLoader with DigestCodeSource
 * codebases and principals. It is used in the context of security policies.
 *
 * @author Peter Firmstone.
 * @since 27
 */
 @SuppressWarnings("serial")
 final class DigestDomainGrant extends ProtectionDomainGrant {
	private static final long serialVersionUID = 1L;
	private final WeakReference<ClassLoader> clRef;
	private final DigestCodeSource [] digestCodeSources;
	private final int hashCode;

	DigestDomainGrant(WeakReference<ProtectionDomain> domain,
					  List<CodeSource> sources,
					  Principal[] groups,
					  Permission[] perms){
		super(domain, groups, perms);
		ProtectionDomain pd = domain.get();
		ClassLoader cl = pd != null? pd.getClassLoader() : null;
		this.clRef = cl != null? new WeakReference<ClassLoader>(cl) : null;
		this.digestCodeSources = sources.toArray(new DigestCodeSource[sources.size()]);
		int hashCode = 3;
		hashCode = 37 * hashCode + Arrays.hashCode(digestCodeSources);
		hashCode = 37 * hashCode + (cl != null ? System.identityHashCode(cl) : 0);
		hashCode = 37 * hashCode + super.hashCode();
		this.hashCode = hashCode;


	}

	@Override
	public boolean equals(Object o){
		if (o == null) return false;
		if (o == this) return true;
		if (o instanceof DigestDomainGrant that){
			if (hashCode != that.hashCode()) return false;
			ClassLoader myLoader = clRef != null? clRef.get() : null;
			ClassLoader thatLoader = that.clRef != null? that.clRef.get() : null;
			if (myLoader != thatLoader) return false;
			if (!super.equals(o)) return false;
			return Arrays.equals(digestCodeSources, that.digestCodeSources);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public String toString() {
		ClassLoader cl = clRef != null? clRef.get() : null;
		StringBuilder sb = new StringBuilder();
		sb.append(super.toString());
		sb.append("\nDigestDomainGrant[");
		sb.append("ClassLoader: ").append(cl).append(", ");
		sb.append("CodeSources: ").append(Arrays.toString(digestCodeSources)).append(", ");
		return sb.toString();
	}

	@Override
    public boolean implies(ProtectionDomain pd) {
        ClassLoader myLoader = clRef != null ? clRef.get(): null;
        if (myLoader == null || pd == null || pd.getClassLoader() != myLoader) return false;
        if (!implies(getPrincipals(pd))) return false;
        CodeSource cs = pd.getCodeSource();
		if (cs instanceof DigestCodeSource dcs) {
			if (dcs.unverified()) return false;
			for (DigestCodeSource dcs2 : digestCodeSources) {
				if (dcs.equals(dcs2)) return true;
			}
		}
		return false;
    }

	 
    public boolean implies(ClassLoader cl, Principal[] pal) {
        return false; // We could determine this if we can obtain the list of CodeSource's
    }

    
    public boolean implies(CodeSource codeSource, Principal[] pal) {
        return false; // Grant is dynamic only.
    }

	@Override
    public boolean isVoid() {
        return super.isVoid() || clRef == null || clRef.get() == null;
    }

	@Override
    public boolean impliesEquivalent(PermissionGrant grant) {
        if (grant instanceof DigestDomainGrant other){
			ClassLoader myloader = clRef != null ? clRef.get(): null;
			ClassLoader theirLoader = other.clRef != null ? other.clRef.get(): null;
			if (myloader == null || myloader != theirLoader) return false;
			if (!super.impliesEquivalent(grant)) return false;
			return Arrays.equals(digestCodeSources, other.digestCodeSources);
		}
		return false;
    }

	@Override
    public PermissionGrantBuilder getBuilderTemplate() {
        PermissionGrantBuilder pgb = super.getBuilderTemplate();
        if (pgb instanceof PermissionGrantBuilderImp pgbi) {
            pgbi.setCodeSources(Arrays.asList(digestCodeSources));
        }
        return pgb.context(PermissionGrantBuilder.DIGEST_DOMAIN);
    }


	//writeReplace method for serialization proxy pattern
    private Object writeReplace() {
        return getBuilderTemplate();
    }
    
    //readObject method for the serialization proxy pattern
    private void readObject(ObjectInputStream stream) 
            throws InvalidObjectException{
        throw new InvalidObjectException("PermissionGrantBuilder required");
    }
 }