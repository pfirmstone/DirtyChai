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

import au.zeus.jdk.authorization.sm.CombinerSecurityManager;
import java.lang.ref.WeakReference;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.LinkedHashSet;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ForkJoinPool;
import java.lang.invoke.MethodHandles;
import javax.security.auth.Subject;

import sun.security.util.Debug;
import sun.security.util.SecurityConstants;


/**
 * An {@code AccessControlContext} is used to make system resource access
 * decisions based on the context it encapsulates.
 *
 * <p>More specifically, it encapsulates a context and
 * has a single method, {@code checkPermission},
 * that is equivalent to the {@code checkPermission} method
 * in the {@code AccessController} class, with one difference:
 * The {@code checkPermission} method makes access decisions based on the
 * context it encapsulates,
 * rather than that of the current execution thread.
 *
 * <p>Thus, the purpose of {@code AccessControlContext} is for those
 * situations where a security check that should be made within a given context
 * actually needs to be done from within a
 * <i>different</i> context (for example, from within a worker thread).
 *
 * <p> An {@code AccessControlContext} is created by calling the
 * {@code AccessController.getContext} method.
 * The {@code getContext} method takes a "snapshot"
 * of the current calling context, and places
 * it in an {@code AccessControlContext} object, which it returns.
 * A sample call is the following:
 *
 * <pre>
 *   AccessControlContext acc = AccessController.getContext()
 * </pre>
 *
 * <p>
 * Code within a different context can subsequently call the
 * {@code checkPermission} method on the
 * previously-saved {@code AccessControlContext} object. A sample call is the
 * following:
 *
 * <pre>
 *   acc.checkPermission(permission)
 * </pre>
 * 
 * <p>
 * Deprecated since 17, disabled since 24, 
 * retained and maintained operational for Authorization.
 *
 * @see AccessController
 *
 * @author Roland Schemers
 * @since 1.2
 */ 
public final class AccessControlContext {

    private final ProtectionDomain[] context;
    // isPrivileged is referenced by the VM - do not remove or change.
    private final boolean isPrivileged; // context is from privileged act call scope.

    // Note: This field is directly used by the virtual machine
    // native codes. Don't touch it.
    private final AccessControlContext privilegedContext;

    @SuppressWarnings("removal")
    private final DomainCombiner combiner;

    private int hashCode;

    private static boolean debugInit = false;
    private static Debug debug = null;
    static volatile AtomicReferenceArray<WeakReference<AccessControlContext>> CONTEXTS;
    private static volatile int MASK;
    // Called by ContextCache class initalizer, by VM at completion of VM init.
    static void initCache(AtomicReferenceArray<WeakReference<AccessControlContext>> cache, int slots){
        if (CONTEXTS != null) return;
        CONTEXTS = cache;
        MASK = slots - 1;
    }

    @SuppressWarnings("removal")
    static Debug getDebug()
    {
        if (debugInit)
            return debug;
        else {
            if (Policy.isSet()) {
                debug = Debug.getInstance("access");
                debugInit = true;
            }
            return debug;
        }
    }

    /**
     * Create an {@code AccessControlContext} with the given array of
     * {@code ProtectionDomain} objects.
     * Context must not be {@code null}. Duplicate domains will be removed
     * from the context.  If caller does not have the "createAccessControlContext"
     * {@link SecurityPermission}, then domains from the calling context will 
     * be added to prevent privilege escalation.
     * 
     * <p>
     * Non standard API.
     *
     * @param context the {@code ProtectionDomain} objects associated with this
     * context. The non-duplicate domains are copied from the array. Subsequent
     * changes to the array will not affect this {@code AccessControlContext}.
     * @param privileged_context the privileged context associated with this
     * context.  This is used to determine if a privileged action was performed
     * in the current call stack.
     * @param isPrivileged true if this context is from a privileged action call
     * scope, false otherwise.
     * @return a cached AccessControlContext matching the provided parameters or
     * a new AccessControlContext if one doesn't already exist.
     * @throws NullPointerException if {@code context} is {@code null}
     * @since 25
     */
    static AccessControlContext create(ProtectionDomain [] context,
            AccessControlContext privileged_context,
            boolean isPrivileged)
    {
        return create(context, privileged_context, null, isPrivileged);
    } 

    /**
     * Create an {@code AccessControlContext} with the given array of
     * {@code ProtectionDomain} objects.
     * Context must not be {@code null}. Duplicate domains will be removed
     * from the context.  If caller does not have the "createAccessControlContext"
     * {@link SecurityPermission}, then domains from the calling context will 
     * be added to prevent privilege escalation.
     * 
     * <p>
     * Non standard API.
     *
     * @param context the {@code ProtectionDomain} objects associated with this
     * context. The non-duplicate domains are copied from the array. Subsequent
     * changes to the array will not affect this {@code AccessControlContext}.
     * @return a cached AccessControlContext matching the provided parameters or
     * a new AccessControlContext if one doesn't already exist.
     * @throws NullPointerException if {@code context} is {@code null}
     * @since 25
     */
    public static AccessControlContext create(ProtectionDomain[] context)
    {
        notNull(context);
        AccessControlContext unAuthorizedContext = checkAuthorized(false, false);
        if (unAuthorizedContext == null){
            if (context.length == 0) {
                context = null;
            } else if (context.length == 1) {
                if (context[0] != null) {
                    context = context.clone();
                } else {
                    context = null;
                }
            } else {
                Set<ProtectionDomain> v = new HashSet<>(context.length);
                for (int i =0; i< context.length; i++) {
                    if ((context[i] != null)) v.add(context[i]);
                }
                if (!v.isEmpty()) {
                    context = v.toArray(new ProtectionDomain[v.size()]);
                } else {
                    context = null;
                }
            }
        } else {
            int len = unAuthorizedContext.context != null ? unAuthorizedContext.context.length : 0;
            Set<ProtectionDomain> v = new HashSet<>(context.length + len);
            for (int i =0; i< context.length; i++) {
                if ((context[i] != null)) v.add(context[i]);
            }
            for (int i =0; i< len; i++) {
                if ((unAuthorizedContext.context[i] != null)) v.add(unAuthorizedContext.context[i]);
            }
            if (!v.isEmpty()) {
                context = v.toArray(new ProtectionDomain[v.size()]);
            } else {
                context = null;
            }
        }
        return create(context, null, null, false);
    }

    /**
     * Build an {@code AccessControlContext} with the given
     * {@code AccessControlContext} and {@code DomainCombiner}.
     * This constructor associates the provided
     * {@code DomainCombiner} with the provided
     * {@code AccessControlContext}.
     * <p>
     * Non standard API.
     *
     * @param acc the {@code AccessControlContext} associated
     *          with the provided {@code DomainCombiner}.
     *
     * @param combiner the {@code DomainCombiner} to be associated
     *          with the provided {@code AccessControlContext}.
     *
     * @throws    NullPointerException if the provided
     *          {@code context} is {@code null}.
     *
     * @throws    SecurityException if a security manager is installed and the
     *          caller does not have the "createAccessControlContext"
     *          {@link SecurityPermission}
     * @return a cached AccessControlContext matching the provided parameters or
     * a new AccessControlContext if one doesn't already exist.
     * @since 25
     */    
    public static AccessControlContext create(AccessControlContext acc,
                                             DomainCombiner combiner) 
    {
        checkAuthorized(false, true);
        return create(notNull(acc).context, null, combiner, false);
    }

    /**
     * package private to allow calls from {@code ProtectionDomain} without
     * performing the security check for
     * {@linkplain SecurityConstants#CREATE_ACC_PERMISSION} permission
     */
    static AccessControlContext create(AccessControlContext acc,
                                      DomainCombiner combiner,
                                      boolean isAuthorized)
    {
        checkAuthorized(isAuthorized, true);
        return create(notNull(acc).context, null, combiner, false);
    }

    /**
     * package private to allow calls for {@code JavaSecurityAccess.doIntersectionPrivilege()}
     */
    static AccessControlContext create(ProtectionDomain[] context,
                                      AccessControlContext privilegedContext)
    {
        return create(context, privilegedContext, null, true);
    }
    
    /**
     * package private for {@code AccessController} doPrivileged methods
     * with permission argument and null context argument.
     */
    static AccessControlContext create(ProtectionDomain[] context,
                                      DomainCombiner combiner,
                                      boolean isAuthorized)
    {
        checkAuthorized(isAuthorized, true);
        return create(context, null, combiner, false);
    }
    
    /**
     * package private for {@code AccessController.getContext()}
     * to return a privileged domain without security check.
     */
    static AccessControlContext create(ProtectionDomain[] context,
                                      boolean isPrivileged)
    {
        return create(context, null, null, isPrivileged);
    }
    

    /**
     * For AccessController new Java stack walk.
     */
    static AccessControlContext create(ProtectionDomain[] context,
                                      boolean privileged,
                                      AccessControlContext privilegedContext)
    {
        return create(context, privilegedContext, null, privileged);
    }

    /**
     * This creator determines whether the cache has been initialized and 
     * if so returns a matching cached AccessControlContext if it exists.
     * Otherwise it creates a new AccessControlContext.
     */
    static AccessControlContext create(ProtectionDomain[] context,
                                      AccessControlContext privilegedContext,
                                      DomainCombiner combiner,
                                      boolean isPrivileged)
    {
        return create(null, context, privilegedContext, combiner, isPrivileged);
    }

    /**
     * This creator determines whether the cache has been initialized and 
     * if so returns a matching cached AccessControlContext if it exists.
     * Otherwise it creates a new AccessControlContext.
     */
    static AccessControlContext create(AccessControlContext result,
                                        ProtectionDomain[] context,
                                        AccessControlContext privilegedContext,
                                        DomainCombiner combiner,
                                        boolean isPrivileged) {
        AtomicReferenceArray<WeakReference<AccessControlContext>> table = CONTEXTS;
        if (table == null) {
            return result != null ? result
                    : new AccessControlContext(dedup(context), privilegedContext, combiner, isPrivileged);
        }
        int hash = result == null ? genHashCode(context, privilegedContext, combiner, isPrivileged)
                                  : result.hashCode();
        int h = hash ^ (hash >>> 16);
        int i = h & (table.length() - 1);   // mask from the table itself; see 3
        int j = i ^ 1;
        WeakReference<AccessControlContext> wi = table.get(i), wj = table.get(j);
        AccessControlContext ai = wi != null ? wi.get() : null;
        if (ai != null && ai.hashCode == hash && ai.match(context, privilegedContext, combiner, isPrivileged)) return ai;
        AccessControlContext aj = wj != null ? wj.get() : null;
        if (aj != null && aj.hashCode == hash && aj.match(context, privilegedContext, combiner, isPrivileged)) return aj;

        if (result == null) {
            result = new AccessControlContext(dedup(context), privilegedContext, combiner, isPrivileged);
        }
        // Empty or cleared i first; otherwise replace j, so i stays sticky.
        int slot = (ai == null) ? i : j;
        WeakReference<AccessControlContext> expected = (ai == null) ? wi : wj;
        if (!table.compareAndSet(slot, expected, new WeakReference<>(result))) {
            WeakReference<AccessControlContext> w = table.get(slot);   // lost a race: prefer the winner if equal
            AccessControlContext winner = w != null ? w.get() : null;
            if (winner != null && winner.hashCode == hash
                    && winner.match(context, privilegedContext, combiner, isPrivileged)) return winner;
        }
        return result;
    }

    static AccessControlContext cache(AccessControlContext result){
           return create(result, result.context, result.privilegedContext, result.combiner, result.isPrivileged);
    }
    
    /**
     * Creates or returns an unprivileged AccessControlContext without
     * checking for "createAccessControlContext" {@link SecurityPermission}
     * 
     * This context can gain privileges from Subject, but is otherwise unprivileged.
     * 
     * @return unprivileged AccessControlContext
     */
    public static AccessControlContext unprivileged(){
        return create(new ProtectionDomain[]{new DomainIdentity(null, null, null, null)}, false);
    }
    
    /**
     * Creates or returns a guaranteed never privileged AccessControlContext without
     * checking for "createAccessControlContext" {@link SecurityPermission}
     * 
     * This context cannot gain privileges from a thread's Subject.
     * 
     * @return unprivileged AccessControlContext
     */
    public static AccessControlContext neverPrivileged(){
        return create(new ProtectionDomain[]{new DomainIdentity(null, null)}, false);
    }

    /**
     * Convenience methods that checks for null.
     */
    private static <T> T notNull(T t) throws NullPointerException {
        if (t == null) throw new NullPointerException("parameter cannot be null");
        return t;
    }

    /**
     * Create an {@code AccessControlContext} with the given array of
     * {@code ProtectionDomain} objects.
     * Context must not be {@code null}. Duplicate domains will be removed
     * from the context.  If caller does not have the "createAccessControlContext"
     * {@link SecurityPermission}, then domains from the calling context will 
     * be added to prevent privilege escalation.
     *
     * @param context the {@code ProtectionDomain} objects associated with this
     * context. The non-duplicate domains are copied from the array. Subsequent
     * changes to the array will not affect this {@code AccessControlContext}.
     * @throws NullPointerException if {@code context} is {@code null}
     * @deprecated to support VirtualThread's use a factory method instead.
     */
    @Deprecated
    public AccessControlContext(ProtectionDomain[] context){
        this(notNull(context), checkAuthorized(false,false));
    }

    /**
     * Called by public constructor.
     */
    private AccessControlContext(ProtectionDomain[] context, AccessControlContext unAuthorizedContext)
    {
        if (unAuthorizedContext == null){
            if (context.length == 0) {
                context = null;
            } else if (context.length == 1) {
                if (context[0] != null) {
                    context = context.clone();
                } else {
                    context = null;
                }
            } else {
                Set<ProtectionDomain> v = new HashSet<>(context.length);
                for (int i =0; i< context.length; i++) {
                    if ((context[i] != null)) v.add(context[i]);
                }
                if (!v.isEmpty()) {
                    context = v.toArray(new ProtectionDomain[v.size()]);
                } else {
                    context = null;
                }
            }
        } else {
            int len = unAuthorizedContext.context != null ? unAuthorizedContext.context.length : 0;
            Set<ProtectionDomain> v = new HashSet<>(context.length + len);
            for (int i =0; i< context.length; i++) {
                if ((context[i] != null)) v.add(context[i]);
            }
            for (int i =0; i< len; i++) {
                if ((unAuthorizedContext.context[i] != null)) v.add(unAuthorizedContext.context[i]);
            }
            if (!v.isEmpty()) {
                context = v.toArray(new ProtectionDomain[v.size()]);
            } else {
                context = null;
            }
        }
        this.hashCode = genHashCode(context, null, null, false);
        this.context = context;
        this.isPrivileged = false;
        this.privilegedContext = null;
        this.combiner = null;
    }

    /**
     * Create a new {@code AccessControlContext} with the given
     * {@code AccessControlContext} and {@code DomainCombiner}.
     * This constructor associates the provided
     * {@code DomainCombiner} with the provided
     * {@code AccessControlContext}.
     *
     * @param acc the {@code AccessControlContext} associated
     *          with the provided {@code DomainCombiner}.
     *
     * @param combiner the {@code DomainCombiner} to be associated
     *          with the provided {@code AccessControlContext}.
     *
     * @throws    NullPointerException if the provided
     *          {@code context} is {@code null}.
     *
     * @throws    SecurityException if a security manager is installed and the
     *          caller does not have the "createAccessControlContext"
     *          {@link SecurityPermission}
     * @since 1.3
     * 
     * @deprecated to support VirtualThread's use a factory method instead.
     */
    @Deprecated
    public AccessControlContext(AccessControlContext acc,
                            @SuppressWarnings("removal") DomainCombiner combiner) 
    {
        this(notNull(acc).context, combiner, checkAuthorized(false, true));
    }

    /* checks the caller is authorized to create an instance of AccessControlContext.*/
    private static AccessControlContext checkAuthorized(boolean preauthorized, boolean throwSecurityException){
        if (!preauthorized) {
            SecurityManager sm = System.getSecurityManager();
            if (sm != null) {
                AccessControlContext unAuthorizedContext =  AccessController.getContext();
                Permission perm = SecurityConstants.CREATE_ACC_PERMISSION;
                try {
                    sm.checkPermission(perm, unAuthorizedContext);
                    return null;
                } catch (SecurityException se){
                    if (throwSecurityException) throw se;
                }
                return unAuthorizedContext;
            }
        }
        return null;
    }

    /**
     * Called by public constructor after checking permission to prevent finalizer
     * attack.
     */
    private AccessControlContext(ProtectionDomain[] context,
                        @SuppressWarnings("removal") DomainCombiner combiner,
                        AccessControlContext unAuthorizedContext /*Always null*/) 
    {
        assert(unAuthorizedContext == null);
        this.context = context;

        // we do not need to run the combine method on the
        // provided ACC.  it was already "combined" when the
        // context was originally retrieved.
        //
        // at this point in time, we simply throw away the old
        // combiner and use the newly provided one.
        this.combiner = combiner;
        this.isPrivileged = false;
        this.privilegedContext = null;
        this.hashCode = genHashCode(context, privilegedContext, combiner, isPrivileged);
    }

    /* Constructor used by createer methods. */
    private AccessControlContext(ProtectionDomain[] context,
                         AccessControlContext privilegedContext,
                         DomainCombiner combiner,
                         boolean isPrivileged)
    {
        this.context = context;
        this.privilegedContext = privilegedContext;
        this.combiner = combiner;
        this.isPrivileged = isPrivileged;
        this.hashCode = genHashCode(context, privilegedContext, combiner, isPrivileged);
    }
    
    private static int genHashCode(ProtectionDomain[] context,
                                   AccessControlContext privilegedContext,
                                   DomainCombiner combiner,
                                   boolean isPrivileged)
    {
        int hash = 5;
        hash = hash * 27 + (context != null ? domainsHash(context) : 0);
        hash = hash * 27 + Objects.hashCode(privilegedContext);
        hash = hash * 27 + Objects.hashCode(combiner);
        hash = hash * 27 + (isPrivileged ? 1 : 0);
        return hash;
    }

    /**
     * Equal to Set(pds).hashCode(): the sum of the hash codes of the
     * distinct non-null domains, so equal domain sets hash equally
     * whatever their order or repetition.
     */
    private static int domainsHash(ProtectionDomain[] pds) {
        if (pds == null) return 0;
        int h = 0;
        outer:
        for (int i = 0; i < pds.length; i++) {
            ProtectionDomain pd = pds[i];
            if (pd == null) continue;
            for (int j = 0; j < i; j++) {          // already counted?
                ProtectionDomain prev = pds[j];
                if (prev == pd || (prev != null && prev.equals(pd))) continue outer;
            }
            h += pd.hashCode();
        }
        return h;
    }

    /**
     * Appends a new ProtectionDomain with permissions to the context, preserving
     * all other existing properties.
     * @param perms
     * @return 
     */
    AccessControlContext intersectionPermissions(ProtectionDomain permDomain){
        return intersectionOfPermsDoWithCombiner(this.combiner, permDomain);
    }

    /**
     * Appends a new ProtectionDomain with permissions to the context, using
     * the specified DomainCombiner while preserving all other existing properties.
     * 
     * @param perms
     * @return 
     */
    AccessControlContext intersectionOfPermsDoWithCombiner(DomainCombiner dc, ProtectionDomain permDomain){
        ProtectionDomain [] domains = new ProtectionDomain[context.length + 1];
        for (int i = 0, len = context.length; i < len; i++){
            domains[i] = context [i];
        }
        domains[context.length] = permDomain;
        return create(domains, this.privilegedContext, dc, this.isPrivileged);
    }

    /**
     * Returns this context's context.
     */
    ProtectionDomain[] getContext() {
        return context;
    }
    
    AccessControlContext privilegedContext() {
        return privilegedContext;
    }

    /**
     * Returns {@code true} if this context captures the scope from a 
     * privileged action.
     */
    boolean isPrivileged()
    {
        return isPrivileged;
    }

    /**
     * get the assigned combiner from the privileged or inherited context
     */
    @SuppressWarnings("removal")
    DomainCombiner getAssignedCombiner() {
        AccessControlContext acc;
        if (isPrivileged) {
            acc = privilegedContext;
        } else {
            acc = AccessController.getInheritedAccessControlContext();
        }
        if (acc != null) {
            return acc.combiner;
        }
        return null;
    }

    /**
     * Get the {@code DomainCombiner} associated with this
     * {@code AccessControlContext}.
     *
     * @return the {@code DomainCombiner} associated with this
     *          {@code AccessControlContext}, or {@code null}
     *          if there is none.
     *
     * @throws    SecurityException if a security manager is installed and
     *          the caller does not have the "getDomainCombiner"
     *          {@link SecurityPermission}
     * @since 1.3
     */
    @SuppressWarnings("removal")
    public DomainCombiner getDomainCombiner() {

        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(SecurityConstants.GET_COMBINER_PERMISSION);
        }
        return getCombiner();
    }

    /**
     * package private for {@code AccessController}
     */
    @SuppressWarnings("removal")
    DomainCombiner getCombiner() {
        return combiner;
    }

    /**
     * Determines whether the access request indicated by the
     * specified permission should be allowed or denied, based on
     * the security policy currently in effect, and the context in
     * this object. The request is allowed only if every
     * {@code ProtectionDomain} in the context implies the permission.
     * Otherwise the request is denied.
     *
     * <p>
     * This method quietly returns if the access request
     * is permitted, or throws a suitable {@code AccessControlException}
     * otherwise.
     *
     * @param perm the requested permission.
     *
     * @throws    AccessControlException if the specified permission
     * is not permitted, based on the current security policy and the
     * context encapsulated by this object.
     * @throws    NullPointerException if the permission to check for is
     * {@code null}.
     */
    @SuppressWarnings("removal")
    public void checkPermission(Permission perm)
        throws AccessControlException
    {
        if (!implies(perm, false)) throw new AccessControlException("access denied "+perm, perm);
    }
    
    private boolean implies(Permission perm, boolean ephemeral){
        boolean dumpDebug = false;

        if (perm == null) {
            throw new NullPointerException("permission can't be null");
        }
        if (getDebug() != null) {
            // If "codebase" is not specified, we dump the info by default.
            dumpDebug = !Debug.isOn("codebase=");
            if (!dumpDebug) {
                // If "codebase" is specified, only dump if the specified code
                // value is in the stack.
                for (int i = 0; context != null && i < context.length; i++) {
                    if (context[i].getCodeSource() != null &&
                        context[i].getCodeSource().getLocation() != null &&
                        Debug.isOn("codebase=" + context[i].getCodeSource().getLocation().toString())) {
                        dumpDebug = true;
                        break;
                    }
                }
            }

            dumpDebug &= !Debug.isOn("permission=") ||
                Debug.isOn("permission=" + perm.getClass().getCanonicalName());

            if (dumpDebug && Debug.isOn("stack")) {
                Thread.dumpStack();
            }

            if (dumpDebug && Debug.isOn("domain")) {
                if (context == null) {
                    debug.println("domain (context is null)");
                } else {
                    for (int i=0; i< context.length; i++) {
                        debug.println("domain "+i+" "+context[i]);
                    }
                }
            }
        }

        /*
         * iterate through the ProtectionDomains in the context.
         * Stop at the first one that doesn't allow the
         * requested permission (throwing an exception).
         *
         */

        /* if ctxt is null, all we had on the stack were system domains,
           or the first domain was a Privileged system domain. This
           is to make the common case for system code very fast */

        if (context == null) return true;

        for (int i=0, len = context.length; i < len; i++) {
            if (context[i] != null && !context[i].impliesWithAltFilePerm(perm, ephemeral)) {
                if (dumpDebug) {
                    debug.println("access denied " + perm);
                }

                if (Debug.isOn("failure") && debug != null) {
                    // Want to make sure this is always displayed for failure,
                    // but do not want to display again if already displayed
                    // above.
                    if (!dumpDebug) {
                        debug.println("access denied " + perm);
                    }
                    Thread.dumpStack();
                    final ProtectionDomain pd = context[i];
                    final Debug db = debug;
                    AccessController.doPrivileged (new PrivilegedAction<>() {
                        public Void run() {
                            db.println("domain that failed "+pd.getCodeSource());
                            return null;
                        }
                    });
                }
                return false;
            }
        }

        // allow if all of them allowed access
        if (dumpDebug) {
            debug.println("access allowed "+perm);
        }
        return true;
    }

    /**
     * Take the stack-based context (this) and combine it with the
     * privileged or inherited context, if need be.
     */
    @SuppressWarnings("removal")
    AccessControlContext optimize() {
        // the assigned (privileged or inherited) context
        AccessControlContext acc;

        if (isPrivileged) {
            acc = privilegedContext;
        } else {
            acc = AccessController.getInheritedAccessControlContext();
        }

        // this.context could be null if only system code is on the stack;
        // in that case, ignore the stack context
        boolean skipStack = (context == null);

        // acc.context could be null if only system code was involved;
        // in that case, ignore the assigned context
        boolean skipAssigned = (acc == null || acc.context == null);

        if (acc != null && acc.combiner != null) {
            // let the assigned acc's combiner do its thing
            return goCombiner(context, acc);
        }

        // optimisation: if neither have context; return acc if possible
        // rather than this, becasue acc might have a combiner
        if (skipAssigned && skipStack){
            return cache(this);
        }
        // optimization: if there is no stack context; there is no reason
        // to compress the assigned context, it already is compressed
        if (skipStack){
            return cache(acc);
        }

        int slen = context.length;

        // optimization: if there is no assigned context and the stack length
        // is less then or equal to two; there is no reason to compress the
        // stack context, it already is
        if (skipAssigned && slen <= 2) {
            return cache(this);
        }

        // optimization: if there is a single stack domain and that domain
        // is already in the assigned context; no need to combine
        if ((slen == 1) && acc.context.length > 0 && (context[0] == acc.context[0])){
            return cache(acc);
        }

        int n = (skipAssigned)? 0 : acc.context.length;

        // now we combine both of them, and create a new context
        ProtectionDomain[] pd = new ProtectionDomain[slen + n];

        // first copy in the assigned context domains, no need to compress
        if (!skipAssigned) {
            System.arraycopy(acc.context, 0, pd, 0, n);
        }

        // now add the stack context domains, discarding nulls and duplicates
    outer:
        for (int i = 0; i < slen; i++) {
            ProtectionDomain sd = context[i];
            if (sd != null) {
                for (int j = 0; j < n; j++) {
                    if (sd == pd[j]) {
                        continue outer;
                    }
                }
                pd[n++] = sd;
            }
        }

        // if length isn't equal, we need to shorten the array
        if (n != pd.length) {
            // optimization: if we didn't really combine anything
            if (!skipAssigned && n == acc.context.length) {
                return cache(acc);
            } else if (skipAssigned && n == slen) {
                return cache(this);
            }
            ProtectionDomain[] tmp = new ProtectionDomain[n];
            System.arraycopy(pd, 0, tmp, 0, n);
            pd = tmp;
        }

        return create(pd, privilegedContext, null, false);
    }

    private AccessControlContext goCombiner(ProtectionDomain[] current, 
                                            AccessControlContext assigned){
        // the assigned ACC's cimbiner is not null --
        // let the combiner do its thing
        /// XXX we could add optimisations to 'current' here...

        if (getDebug() != null) {
            debug.println("AccessControlContext invoking the Combiner");
        }

        // No need to clone current and assigned.context
        // combine() will not update them
        ProtectionDomain[] combinedPds = assigned.combiner.combine(
            current, assigned.context);

        return AccessControlContext.create(combinedPds, privilegedContext,
                assigned.combiner, false);
    }

    /**
     * Checks two {@code AccessControlContext} objects for equality.
     * Checks that {@code obj} is
     * an {@code AccessControlContext} and has the same set of
     * {@code ProtectionDomain} objects as this context.
     *
     * @param obj the object we are testing for equality with this object.
     * @return {@code true} if {@code obj} is an {@code AccessControlContext},
     * and has the same set of {@code ProtectionDomain} objects as this context,
     * {@code false} otherwise.
     */
    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null) return false;
        if (hashCode() != obj.hashCode()) return false;
        if (obj instanceof AccessControlContext that){
            if (this.isPrivileged != that.isPrivileged) return false;
            if (context == null && that.context != null) return false;
            if (that.context == null && this.context != null) return false;
            if (!Objects.equals(this.combiner, that.combiner)) return false;
            if (!Objects.equals(this.privilegedContext, that.privilegedContext)) return false;
            return sameDomains(this.context, that.context);
        }
        return false;       
    }

    boolean match(ProtectionDomain[] context,
                  AccessControlContext privilegedContext,
                  DomainCombiner combiner,
                  boolean isPrivileged){
        if (this.isPrivileged != isPrivileged) return false;
        if (!Objects.equals(this.combiner, combiner)) return false;
        if (!Objects.equals(this.privilegedContext, privilegedContext)) return false;
        return sameDomains(this.context, context);
    }

    /** True if every non-null domain in b is equal to some domain in a. */
    private static boolean containsAll(ProtectionDomain[] a, ProtectionDomain[] b) {
        if (b == null) return true;
        outer:
        for (ProtectionDomain y : b) {
            if (y == null) continue;
            if (a != null) {
                for (ProtectionDomain x : a) {
                    if (x == y || (x instanceof DomainIdentity && x.equals(y))) continue outer;
                }
            }
            return false;
        }
        return true;
    }

    /** Same distinct domains, in any order, ignoring repeats; null equals empty. */
    private static boolean sameDomains(ProtectionDomain[] a, ProtectionDomain[] b) {
        return a == b || (containsAll(a, b) && containsAll(b, a));
    }
    
    private static <T> Set<T> asSet(T[] a){
        if (a == null) return Collections.emptySet();
        int len = a.length;
        Set<T> result = new HashSet<T>(len);
        for (int i = 0; i < len; i++){
            result.add(a[i]);
        }
        return result;
    }

    /**
     * The distinct non-null domains of {@code pds}, in first-seen order, as a
     * new array; null if there are none. Domains match by identity, or by
     * equals() for DomainIdentity only (final, trusted). Called only when a new
     * context is about to be created, never on a cache hit.
     */
    private static ProtectionDomain[] dedup(ProtectionDomain[] pds) {
        if (pds == null) return null;
        int len = pds.length;
        ProtectionDomain[] out = new ProtectionDomain[len];
        int n = 0;
        outer:
        for (int i = 0; i < len; i++) {
            ProtectionDomain pd = pds[i];
            if (pd == null) continue;
            for (int k = 0; k < n; k++) {
                ProtectionDomain seen = out[k];
                if (seen == pd || (seen instanceof DomainIdentity && seen.equals(pd))) {
                    continue outer;
                }
            }
            out[n++] = pd;
        }
        if (n == 0) return null;
        if (n == len) return out;
        ProtectionDomain[] trimmed = new ProtectionDomain[n];
        System.arraycopy(out, 0, trimmed, 0, n);
        return trimmed;
    }

    /**
     * {@return the hash code value for this context}
     * The hash code is computed by exclusive or-ing the hash code of all the
     * protection domains in the context together.
     */
    @Override
    public int hashCode() {
        if (hashCode == 0) {
            hashCode = genHashCode(context, privilegedContext, combiner, isPrivileged);
        }
        return hashCode;
    }
    
    /**
     * This class is not part of the Java Standards.
     * 
     * Utility class allowing JVM platform classes to create AccessControlContext
     * without permission checks that would otherwise cause stack overflow errors.
     * 
     * Previously an AccessControlContext instance could be created without
     * requiring {@code SecurityPermission "createAccessControlContext"} when
     * calling the constructor with a {@code ProtectionDomain [] context} 
     * parameter.  Significant complexity was added to AccessControlContext's
     * implementation to delay checking for this permission in AccessController
     * doPrivileged calls, however this allowed for the opportunity for 
     * injection attacks, as the context of the caller of doPrivileged may be
     * different to the creator of AccessControlContext.
     * 
     * To solve this problem and simplify AccessControlContext, make it 
     * immutable and cache instances to support virtual threads, the
     * permission check is now performed, but doesn't throw a SecurityException,
     * instead if the caller doesn't possess the required permission, it's stack
     * context will be captured and added to the new context, preventing an
     * escalation of permissions.   
     */
    public static abstract sealed class ContextBuilder 
            permits ClassLoader.Context, ForkJoinPool.Context,
            MethodHandles.Context, Subject.Context, Thread.Context, 
            CombinerSecurityManager.Context {
        
        /**
         * Creates a new ContextBuilder instance;
         */
        protected ContextBuilder(){}
        
         /**
         * Create an {@code AccessControlContext} with the given array of
         * {@code ProtectionDomain} objects.
         * Context must not be {@code null}.
         * 
         * <p>
         * Non standard API.
         *
         * @param context the {@code ProtectionDomain} objects associated with this
         * context. 
         * @return a cached AccessControlContext matching the provided parameters or
         * a new AccessControlContext if one doesn't already exist.
         * @throws NullPointerException if {@code context} is {@code null}
         * @since 25
         */
        public final AccessControlContext build(ProtectionDomain[] context){
            return AccessControlContext.create(context, false);
        }
        
        /**
         * Create an {@code AccessControlContext} with the given array of
         * {@code ProtectionDomain} objects.
         * Context must not be {@code null}.
         * 
         * <p>
         * Non standard API.
         *
         * @param acc the {@code AccessControlContext}. 
         * @param combiner the {@code DomainCombiner}.
         * @return a cached AccessControlContext matching the provided parameters or
         * a new AccessControlContext if one doesn't already exist.
         * @throws NullPointerException if {@code acc} is {@code null}
         * @since 27
         */
        public AccessControlContext build(AccessControlContext acc,
                                             DomainCombiner combiner) {
            return AccessControlContext.create(acc, combiner, true); // Skips check authorized.
        }
        
        /**
         * Allows access to the DomainCombiner without a permission check.
         * 
         * @param acc the AccessControlContext
         * @return DomainCombiner or null.
         */
        public DomainCombiner getCombiner(AccessControlContext acc){
            return acc.getCombiner();
        }

        /**
         * Allows permission check without throwing a SecurityException
         * @param acc, the AccessControlContext
         * @param perm, the permission
         * @param ephemeral Ephemeral authority.
         * @return true if permission is implied by the context.
         */
        public boolean implies(AccessControlContext acc, Permission perm, boolean ephemeral){
            return acc.implies(perm, ephemeral);
        }
        
    }
}
