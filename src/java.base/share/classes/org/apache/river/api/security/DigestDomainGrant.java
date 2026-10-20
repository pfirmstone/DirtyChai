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
 class DigestDomainGrant extends ProtectionDomainGrant {
	private static final long serialVersionUID = 1L;
	private final WeakReference<ClassLoader> clRef;
	private final Set<CodeSourceKey> verified;
	private final DigestCodeSource [] digestCodeSources;
	private final int hashCode;

	DigestDomainGrant(WeakReference<ProtectionDomain> domain,
					  WeakReference<ClassLoader> loader,
					  Set<CodeSourceKey> verified,
					  List<CodeSource> sources,
					  Principal[] groups,
					  Permission[] perms){
		super(domain, groups, perms);
		this.clRef = loader;
		this.verified = Collections.unmodifiableSet(verified);
		this.digestCodeSources = sources.toArray(new DigestCodeSource[sources.size()]);
		int hashCode = 3;
		hashCode = 37 * hashCode + Arrays.hashCode(digestCodeSources);
		hashCode = 37 * hashCode + Objects.hashCode(verified);
		ClassLoader cl = clRef.get();
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
			if (!Objects.equals(clRef.get(), that.clRef.get())) return false;
			if (!super.equals(o)) return false;
			if (!Arrays.equals(digestCodeSources, that.digestCodeSources)) return false;
			return verified.equals(that.verified);
		}
		return false;
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