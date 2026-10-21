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
import java.lang.ref.WeakReference;
import java.security.Permission;
import java.security.Principal;
import java.security.ProtectionDomain;

/**
 *
 * @author Peter Firmstone
 * @since 3.0.0
 */
 @SuppressWarnings("serial")
class ClassLoaderGrant extends ProtectionDomainGrant {
    private static final long serialVersionUID = 1L;
    private final int hashCode;
    private final WeakReference<ClassLoader> loaderRef;

    @SuppressWarnings("unchecked")
    ClassLoaderGrant(WeakReference<ClassLoader> loaderRef, Principal[] groups, 
            Permission[] perm){
        super(null, groups, perm);
        ClassLoader myLoader = loaderRef != null? loaderRef.get() : null;
        int hash = 7;
        hash = 19 * hash + super.hashCode();
        if ( myLoader != null) hash = 19 * hash + myLoader.hashCode();
        hashCode = hash;
        this.loaderRef = loaderRef;
    }
    
    @Override
    public boolean equals(Object o){
        if (o == null) return false;
        if (o == this) return true;
	    if (o.hashCode() != this.hashCode()) return false;
        if (o instanceof ClassLoaderGrant that){
            ClassLoader myLoader = this.loaderRef != null? this.loaderRef.get() : null;
            ClassLoader thatLoader = that.loaderRef != null? that.loaderRef.get() : null;
            return myLoader == thatLoader;
        }
        return false;
    }
   
    @Override
    public int hashCode() {
        return hashCode;
    }
    
    public String toString(){
        StringBuilder sb = new StringBuilder(500);
        return sb.append(super.toString())
                 .append("ClassLoader grant.")
                 .append(loaderRef != null? loaderRef.get() : "NULL")
                 .toString();
    }

    @Override
    public boolean implies(ProtectionDomain pd) {
       if (pd != null) return implies(pd.getClassLoader(), getPrincipals(pd));
       return false;
    }

    public boolean implies(ClassLoader cl, Principal[] pal) {
        if (cl == null) return false;
        ClassLoader myLoader = loaderRef != null ? loaderRef.get() : null;
        if (myLoader != cl) return false;
        return implies(pal);
    }

	@Override
    public boolean isVoid() {
        return loaderRef == null || loaderRef.get() == null || getPermissions().isEmpty();
    }
    
    @Override
    public boolean impliesEquivalent(PermissionGrant grant) {
	    if (!(grant instanceof ClassLoaderGrant)) return false;
	    ProtectionDomain myPd = domain.get();
	    ProtectionDomain yourPd = ((ClassLoaderGrant)grant).domain.get();
	    if (myPd != null && yourPd != null){
	        ClassLoader myCL = myPd.getClassLoader();
	        ClassLoader yourCL = yourPd.getClassLoader();
	        if (myCL != null && yourCL != null){
		    return myCL.equals(yourCL);
	        }
	    }
	    return false;
	    // The superclass has a narrower scope than ClassLoaderGrant.
    }

    @Override
    public PermissionGrantBuilder getBuilderTemplate() {
        PermissionGrantBuilder pgb = super.getBuilderTemplate();
        return pgb.context(PermissionGrantBuilder.CLASSLOADER);
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
