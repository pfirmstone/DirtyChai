/*
 * Copyright (c) 1997, 2022, Oracle and/or its affiliates. All rights reserved.
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
import java.lang.ref.Reference;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URI;
import javax.security.auth.Subject;
import javax.security.auth.SubjectDomainCombiner;
import javax.security.auth.WorkerSubject;

import jdk.internal.vm.annotation.Hidden;
import sun.security.util.Debug;
import jdk.internal.reflect.CallerSensitive;
import jdk.internal.reflect.Reflection;
import jdk.internal.vm.annotation.ForceInline;
import jdk.internal.vm.annotation.ReservedStackAccess;

/**
 * <p> The {@code AccessController} class is used for access control operations
 * and decisions.
 *
 * <p> More specifically, the {@code AccessController} class is used for
 * three purposes:
 *
 * <ul>
 * <li> to decide whether an access to a critical system
 * resource is to be allowed or denied, based on the security policy
 * currently in effect,
 * <li>to mark code as being "privileged", thus affecting subsequent
 * access determinations, and
 * <li>to obtain a "snapshot" of the current calling context so
 * access-control decisions from a different context can be made with
 * respect to the saved context. </ul>
 *
 * <p> The {@link #checkPermission(Permission) checkPermission} method
 * determines whether the access request indicated by a specified
 * permission should be granted or denied. A sample call appears
 * below. In this example, {@code checkPermission} will determine
 * whether or not to grant "read" access to the file named "testFile" in
 * the "/temp" directory.
 *
 * <pre>
 *
 * FilePermission perm = new FilePermission("/temp/testFile", "read");
 * AccessController.checkPermission(perm);
 *
 * </pre>
 *
 * <p> If a requested access is allowed,
 * {@code checkPermission} returns quietly. If denied, an
 * {@code AccessControlException} is
 * thrown. {@code AccessControlException} can also be thrown if the requested
 * permission is of an incorrect type or contains an invalid value.
 * Such information is given whenever possible.
 *
 * Suppose the current thread traversed m callers, in the order of caller 1
 * to caller 2 to caller m. Then caller m invoked the
 * {@code checkPermission} method.
 * The {@code checkPermission} method determines whether access
 * is granted or denied based on the following algorithm:
 *
 *  <pre> {@code
 * for (int i = m; i > 0; i--) {
 *
 *     if (caller i's domain does not have the permission)
 *         throw AccessControlException
 *
 *     else if (caller i is marked as privileged) {
 *         if (a context was specified in the call to doPrivileged)
 *             context.checkPermission(permission)
 *         if (limited permissions were specified in the call to doPrivileged) {
 *             for (each limited permission) {
 *                 if (the limited permission implies the requested permission)
 *                     return;
 *             }
 *         } else
 *             return;
 *     }
 * }
 *
 * // Next, check the context inherited when the thread was created.
 * // Whenever a new thread is created, the AccessControlContext at
 * // that time is stored and associated with the new thread, as the
 * // "inherited" context.
 *
 * inheritedContext.checkPermission(permission);
 * }</pre>
 *
 * <p> A caller can be marked as being "privileged"
 * (see {@link #doPrivileged(PrivilegedAction) doPrivileged} and below).
 * When making access control decisions, the {@code checkPermission}
 * method stops checking if it reaches a caller that
 * was marked as "privileged" via a {@code doPrivileged}
 * call without a context argument (see below for information about a
 * context argument). If that caller's domain has the
 * specified permission and at least one limiting permission argument (if any)
 * implies the requested permission, no further checking is done and
 * {@code checkPermission}
 * returns quietly, indicating that the requested access is allowed.
 * If that domain does not have the specified permission, an exception
 * is thrown, as usual. If the caller's domain had the specified permission
 * but it was not implied by any limiting permission arguments given in the call
 * to {@code doPrivileged} then the permission checking continues
 * until there are no more callers or another {@code doPrivileged}
 * call matches the requested permission and returns normally.
 *
 * <p> The normal use of the "privileged" feature is as follows. If you
 * don't need to return a value from within the "privileged" block, do
 * the following:
 *
 *  <pre> {@code
 * somemethod() {
 *     ...normal code here...
 *     AccessController.doPrivileged(new PrivilegedAction<Void>() {
 *         public Void run() {
 *             // privileged code goes here, for example:
 *             System.loadLibrary("awt");
 *             return null; // nothing to return
 *         }
 *     });
 *     ...normal code here...
 * }}</pre>
 *
 * <p>
 * {@code PrivilegedAction} is an interface with a single method, named
 * {@code run}.
 * The above example shows creation of an implementation
 * of that interface; a concrete implementation of the
 * {@code run} method is supplied.
 * When the call to {@code doPrivileged} is made, an
 * instance of the {@code PrivilegedAction} implementation is passed
 * to it. The {@code doPrivileged} method calls the
 * {@code run} method from the {@code PrivilegedAction}
 * implementation after enabling privileges, and returns the
 * {@code run} method's return value as the
 * {@code doPrivileged} return value (which is
 * ignored in this example).
 *
 * <p> If you need to return a value, you can do something like the following:
 *
 *  <pre> {@code
 * somemethod() {
 *     ...normal code here...
 *     String user = AccessController.doPrivileged(
 *         new PrivilegedAction<String>() {
 *         public String run() {
 *             return System.getProperty("user.name");
 *             }
 *         });
 *     ...normal code here...
 * }}</pre>
 *
 * <p>If the action performed in your {@code run} method could
 * throw a "checked" exception (those listed in the {@code throws} clause
 * of a method), then you need to use the
 * {@code PrivilegedExceptionAction} interface instead of the
 * {@code PrivilegedAction} interface:
 *
 *  <pre> {@code
 * somemethod() throws FileNotFoundException {
 *     ...normal code here...
 *     try {
 *         FileInputStream fis = AccessController.doPrivileged(
 *         new PrivilegedExceptionAction<FileInputStream>() {
 *             public FileInputStream run() throws FileNotFoundException {
 *                 return new FileInputStream("someFile");
 *             }
 *         });
 *     } catch (PrivilegedActionException e) {
 *         // e.getException() should be an instance of FileNotFoundException,
 *         // as only "checked" exceptions will be "wrapped" in a
 *         // PrivilegedActionException.
 *         throw (FileNotFoundException) e.getException();
 *     }
 *     ...normal code here...
 *  }}</pre>
 *
 * <p> Be *very* careful in your use of the "privileged" construct, and
 * always remember to make the privileged code section as small as possible.
 * You can pass {@code Permission} arguments to further limit the
 * scope of the "privilege" (see below).
 *
 *
 * <p> Note that {@code checkPermission} always performs security checks
 * within the context of the currently executing thread.
 * Sometimes a security check that should be made within a given context
 * will actually need to be done from within a
 * <i>different</i> context (for example, from within a worker thread).
 * The {@link #getContext() getContext} method and
 * {@code AccessControlContext} class are provided
 * for this situation. The {@code getContext} method takes a "snapshot"
 * of the current calling context, and places
 * it in an {@code AccessControlContext} object, which it returns. A sample call is
 * the following:
 *
 * <pre>
 *
 * AccessControlContext acc = AccessController.getContext()
 *
 * </pre>
 *
 * <p>
 * {@code AccessControlContext} itself has a {@code checkPermission} method
 * that makes access decisions based on the context <i>it</i> encapsulates,
 * rather than that of the current execution thread.
 * Code within a different context can thus call that method on the
 * previously-saved {@code AccessControlContext} object. A sample call is the
 * following:
 *
 * <pre>
 *
 * acc.checkPermission(permission)
 *
 * </pre>
 *
 * <p> There are also times where you don't know a priori which permissions
 * to check the context against. In these cases you can use the
 * {@code doPrivileged} method that takes a context. You can also limit the
 * scope of the privileged code by passing additional {@code Permission}
 * parameters.
 *
 *  <pre> {@code
 * somemethod() {
 *     AccessController.doPrivileged(new PrivilegedAction<Object>() {
 *         public Object run() {
 *             // Code goes here. Any permission checks within this
 *             // run method will require that the intersection of the
 *             // caller's protection domain and the snapshot's
 *             // context have the desired permission. If a requested
 *             // permission is not implied by the limiting FilePermission
 *             // argument then checking of the thread continues beyond the
 *             // caller of doPrivileged.
 *         }
 *     }, acc, new FilePermission("/temp/*", read));
 *     ...normal code here...
 * }}</pre>
 * <p> Passing a limiting {@code Permission} argument of an instance of
 * {@code AllPermission} is equivalent to calling the equivalent
 * {@code doPrivileged} method without limiting {@code Permission}
 * arguments. Passing a zero length array of {@code Permission} disables
 * the code privileges so that checking always continues beyond the caller of
 * that {@code doPrivileged} method.
 * <p> Deprecated since 17, removed or disabled since 24,
 * retained and maintained operational for Authorization.
 *
 * @see AccessControlContext
 *
 * @author Li Gong
 * @author Roland Schemers
 * @since 1.2
 */
 /* Removed from Java 24
 *      @deprecated This class is only useful in conjunction with
 *       {@linkplain SecurityManager the Security Manager}, which is deprecated
 *       and subject to removal in a future release. Consequently, this class
 *       is also deprecated and subject to removal. There is no replacement for
 *       the Security Manager or this class.
 */
//@Deprecated(since="17", forRemoval=true)
public final class AccessController {

    /**
     * Don't allow anyone to instantiate an {@code AccessController}
     */
    private AccessController() { }

    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled. The action is performed with <i>all</i> of the permissions
     * possessed by the caller's protection domain.
     *
     * <p> If the action's {@code run} method throws an (unchecked)
     * exception, it will propagate through this method.
     *
     * <p> Note that any {@code DomainCombiner} associated with the current
     * {@code AccessControlContext} will be ignored while the action is
     * performed.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *                  {@code run} method.
     *
     * @param action the action to be performed.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction,AccessControlContext)
     * @see #doPrivileged(PrivilegedExceptionAction)
     * @see #doPrivilegedWithCombiner(PrivilegedAction)
     * @see java.security.DomainCombiner
     */

    @CallerSensitive
    public static <T> T doPrivileged(PrivilegedAction<T> action)
    {
        Class<?> caller = Reflection.getCallerClass();
        return executePrivileged(action, limited(null,caller), caller);
    }

    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled. The action is performed with <i>all</i> of the permissions
     * possessed by the caller's protection domain.
     *
     * <p> If the action's {@code run} method throws an (unchecked)
     * exception, it will propagate through this method.
     *
     * <p> This method preserves the current AccessControlContext's
     * {@code DomainCombiner} (which may be null) while the action is performed.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *                  {@code run} method.
     *
     * @param action the action to be performed.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see java.security.DomainCombiner
     *
     * @since 1.6
     */
    @CallerSensitive
    public static <T> T doPrivilegedWithCombiner(PrivilegedAction<T> action) {
        @SuppressWarnings("removal")
        AccessControlContext acc = getStackAccessControlContext();
        Class<?> caller = Reflection.getCallerClass();
        if (acc == null) {
            return executePrivileged(action, limited(acc,caller), caller);
        }
        @SuppressWarnings("removal")
        DomainCombiner dc = acc.getAssignedCombiner();
        return executePrivileged(action,limited(preserveCombiner(dc, caller), caller), caller);
    }


    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled and restricted by the specified {@code AccessControlContext}.
     * The action is performed with the intersection of the permissions
     * possessed by the caller's protection domain, and those possessed
     * by the domains represented by the specified {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an (unchecked) exception,
     * it will propagate through this method.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *                  {@code run} method.
     * @param action the action to be performed.
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null}, then no additional restriction is applied.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedExceptionAction,AccessControlContext)
     */
    @CallerSensitive
    public static <T> T doPrivileged(PrivilegedAction<T> action,
                                     @SuppressWarnings("removal") AccessControlContext context)
    {
        if (action == null) throw new NullPointerException("action cannot be null");
        Class<?> caller = Reflection.getCallerClass();
        return executePrivileged(action, limited(context, caller), caller);
    }


    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled and restricted by the specified
     * {@code AccessControlContext} and with a privilege scope limited
     * by specified {@code Permission} arguments.
     *
     * The action is performed with the intersection of the permissions
     * possessed by the caller's protection domain, and those possessed
     * by the domains represented by the specified
     * {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an (unchecked) exception,
     * it will propagate through this method.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *                  {@code run} method.
     * @param action the action to be performed.
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null},
     *                then no additional restriction is applied.
     * @param perms the {@code Permission} arguments which limit the
     *              scope of the caller's privileges. The number of arguments
     *              is variable.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws NullPointerException if action or perms or any element of
     *         perms is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedExceptionAction,AccessControlContext)
     *
     * @since 1.8
     */
    @CallerSensitive
    public static <T> T doPrivileged(PrivilegedAction<T> action,
            @SuppressWarnings("removal") AccessControlContext context,
            Permission... perms) 
    {
        
        if (action == null) throw new NullPointerException("action cannot be null");
        if (perms == null) {
            throw new NullPointerException("null permissions parameter");
        }
        Class<?> caller = Reflection.getCallerClass();
        return executePrivileged(action, limited(context, caller, toPermissions(perms)), caller);
    }


    /**
     * Performs the specified {@code PrivilegedAction} with privileges
     * enabled and restricted by the specified
     * {@code AccessControlContext} and with a privilege scope limited
     * by specified {@code Permission} arguments.
     *
     * The action is performed with the intersection of the permissions
     * possessed by the caller's protection domain, and those possessed
     * by the domains represented by the specified
     * {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an (unchecked) exception,
     * it will propagate through this method.
     *
     * <p> This method preserves the current AccessControlContext's
     * {@code DomainCombiner} (which may be null) while the action is performed.
     *
     * @param <T> the type of the value returned by the PrivilegedAction's
     *                  {@code run} method.
     * @param action the action to be performed.
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null},
     *                then no additional restriction is applied.
     * @param perms the {@code Permission} arguments which limit the
     *              scope of the caller's privileges. The number of arguments
     *              is variable.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws NullPointerException if action or perms or any element of
     *         perms is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedExceptionAction,AccessControlContext)
     * @see java.security.DomainCombiner
     *
     * @since 1.8
     */
    @CallerSensitive
    public static <T> T doPrivilegedWithCombiner(PrivilegedAction<T> action,
            @SuppressWarnings("removal") AccessControlContext context,
            Permission... perms) {
        if (action == null) throw new NullPointerException("action cannot be null");
        if (perms == null) {
            throw new NullPointerException("null permissions parameter");
        }
        @SuppressWarnings("removal")
        AccessControlContext parent = getContext();
        @SuppressWarnings("removal")
        DomainCombiner dc = parent.getCombiner();
        Class<?> caller = Reflection.getCallerClass();
        return executePrivileged(action, limited(context, caller, dc, toPermissions(perms)), caller);
    }

    /**
     * Performs the specified {@code PrivilegedExceptionAction} with
     * privileges enabled.  The action is performed with <i>all</i> of the
     * permissions possessed by the caller's protection domain.
     *
     * <p> If the action's {@code run} method throws an <i>unchecked</i>
     * exception, it will propagate through this method.
     *
     * <p> Note that any {@code DomainCombiner} associated with the current
     * {@code AccessControlContext} will be ignored while the action is
     * performed.
     *
     * @param <T> the type of the value returned by the
     *                  PrivilegedExceptionAction's {@code run} method.
     *
     * @param action the action to be performed
     *
     * @return the value returned by the action's {@code run} method
     *
     * @throws    PrivilegedActionException if the specified action's
     *         {@code run} method threw a <i>checked</i> exception
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedExceptionAction,AccessControlContext)
     * @see #doPrivilegedWithCombiner(PrivilegedExceptionAction)
     * @see java.security.DomainCombiner
     */
    @CallerSensitive
    public static <T> T
        doPrivileged(PrivilegedExceptionAction<T> action)
        throws PrivilegedActionException
    {
        if (action == null) throw new NullPointerException("action cannot be null");
        @SuppressWarnings("removal")
        Class<?> caller = Reflection.getCallerClass();
        try {
            return executePrivileged(action, limited(null, caller), caller);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    /**
     * Performs the specified {@code PrivilegedExceptionAction} with
     * privileges enabled.  The action is performed with <i>all</i> of the
     * permissions possessed by the caller's protection domain.
     *
     * <p> If the action's {@code run} method throws an <i>unchecked</i>
     * exception, it will propagate through this method.
     *
     * <p> This method preserves the current AccessControlContext's
     * {@code DomainCombiner} (which may be null) while the action is performed.
     *
     * @param <T> the type of the value returned by the
     *                  PrivilegedExceptionAction's {@code run} method.
     *
     * @param action the action to be performed.
     *
     * @return the value returned by the action's {@code run} method
     *
     * @throws    PrivilegedActionException if the specified action's
     *         {@code run} method threw a <i>checked</i> exception
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedExceptionAction,AccessControlContext)
     * @see java.security.DomainCombiner
     *
     * @since 1.6
     */
    @CallerSensitive
    public static <T> T doPrivilegedWithCombiner(PrivilegedExceptionAction<T> action)
        throws PrivilegedActionException
    {
        @SuppressWarnings("removal")
        AccessControlContext acc = getStackAccessControlContext();
        Class<?> caller = Reflection.getCallerClass();
        try {
            if (acc == null) {
                return executePrivileged(action, limited(null, caller), caller);
            }
            @SuppressWarnings("removal")
            DomainCombiner dc = acc.getAssignedCombiner();
            return executePrivileged(action, limited( preserveCombiner(dc, caller), caller), caller);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    /**
     * preserve the combiner across the doPrivileged call
     */
    @SuppressWarnings("removal")
    private static AccessControlContext preserveCombiner(DomainCombiner combiner,
                                                         Class<?> caller)
    {
        ProtectionDomain callerPD = getProtectionDomain(caller);
        // perform 'combine' on the caller of doPrivileged,
        // even if the caller is from the bootclasspath
        ProtectionDomain[] pds = new ProtectionDomain[] {callerPD};
        if (combiner == null) {
            return AccessControlContext.create(pds, (DomainCombiner) null, true);
        } else {
            return AccessControlContext.create(combiner.combine(pds, null),
                                            combiner, true);
        }
    }

    static native ProtectionDomain getProtectionDomain(final Class<?> caller);

    /**
     * Performs the specified {@code PrivilegedExceptionAction} with
     * privileges enabled and restricted by the specified
     * {@code AccessControlContext}.  The action is performed with the
     * intersection of the permissions possessed by the caller's
     * protection domain, and those possessed by the domains represented by the
     * specified {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an <i>unchecked</i>
     * exception, it will propagate through this method.
     *
     * @param <T> the type of the value returned by the
     *                  PrivilegedExceptionAction's {@code run} method.
     * @param action the action to be performed
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null}, then no additional restriction is applied.
     *
     * @return the value returned by the action's {@code run} method
     *
     * @throws    PrivilegedActionException if the specified action's
     *         {@code run} method threw a <i>checked</i> exception
     * @throws    NullPointerException if the action is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedAction,AccessControlContext)
     */
    @CallerSensitive
    public static <T> T
        doPrivileged(PrivilegedExceptionAction<T> action,
                     @SuppressWarnings("removal") AccessControlContext context)
        throws PrivilegedActionException
    {
        Class<?> caller = Reflection.getCallerClass();
        try {
            return executePrivileged(action, limited(context, caller), caller);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }
    
    /**
     * The value needs to be physically located in the frame, so that it
     * can be found by a stack walk.
     */
    @Hidden
    private static native void ensureMaterializedForStackWalk(Object o);

    /**
     * Sanity check that the caller context is indeed privileged.
     *
     * Used by {@code executePrivileged} to make sure the frame is properly
     * recognized by the VM.
     */
    private static boolean isPrivileged() {
        @SuppressWarnings("removal")
        AccessControlContext ctx = getStackAccessControlContext();
        return ctx == null || ctx.isPrivileged();
    }

    /**
     * Execute the action as privileged.
     *
     * The VM recognizes this method as special, so any changes to the
     * name or signature require corresponding changes in
     * getStackAccessControlContext().
     */
    @Hidden
    @ForceInline
    private static <T> T
        executePrivileged(PrivilegedAction<T> action,
                          @SuppressWarnings("removal") AccessControlContext context,
                          Class<?> caller)
    {
        // Ensure context has a physical value in the frame
        if (context != null) {
            ensureMaterializedForStackWalk(context);
        }

        assert isPrivileged(); // sanity check invariant
        T result = action.run();
        assert isPrivileged(); // sanity check invariant

        // The 'getStackAccessControlContext' call inside 'isPrivileged'
        // requires that no Local was scalar replaced. However, in some
        // situations, after inlining, 'result' (or part of a possibly
        // allocation merge Phi leading to it) might become NonEscaping and get
        // scalar replaced. The call below enforces 'result' to always escape.
        ensureMaterializedForStackWalk(result);

        // Keep these alive across the run() call so they can be
        // retrieved by getStackAccessControlContext().
        Reference.reachabilityFence(context);
        Reference.reachabilityFence(caller);
        return result;
    }

    /**
     * Execute the action as privileged.
     *
     * The VM recognizes this method as special, so any changes to the
     * name or signature require corresponding changes in
     * getStackAccessControlContext().
     */
    @Hidden
    @ForceInline
    private static <T> T
        executePrivileged(PrivilegedExceptionAction<T> action,
                          @SuppressWarnings("removal") AccessControlContext context,
                          Class<?> caller)
        throws Exception
    {
        // Ensure context has a physical value in the frame
        if (context != null) {
            ensureMaterializedForStackWalk(context);
        }

        assert isPrivileged(); // sanity check invariant
        T result = action.run();
        assert isPrivileged(); // sanity check invariant

        // The 'getStackAccessControlContext' call inside 'isPrivileged'
        // requires that no Local was scalar replaced. However, in some
        // situations, after inlining, 'result' (or part of a possibly
        // allocation merge Phi leading to it) might become NonEscaping and get
        // scalar replaced. The call below enforces 'result' to always escape.
        ensureMaterializedForStackWalk(result);

        // Keep these alive across the run() call so they can be
        // retrieved by getStackAccessControlContext().
        Reference.reachabilityFence(context);
        Reference.reachabilityFence(caller);
        return result;
    }


    /**
     * Wrap an exception.  The annotations are used in a best effort to
     * avoid StackOverflowError in the caller.  Inlining the callees as
     * well and tail-call elimination could also help here, but are not
     * needed for correctness, only quality of implementation.
     */
    @Hidden
    @ForceInline
    @ReservedStackAccess
    private static PrivilegedActionException wrapException(Exception e) {
        return new PrivilegedActionException(e);
    }

    /**
     * Performs the specified {@code PrivilegedExceptionAction} with
     * privileges enabled and restricted by the specified
     * {@code AccessControlContext} and with a privilege scope limited by
     * specified {@code Permission} arguments.
     *
     * The action is performed with the intersection of the permissions
     * possessed by the caller's protection domain, and those possessed
     * by the domains represented by the specified
     * {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an (unchecked) exception,
     * it will propagate through this method.
     * <p>
     * If a security manager is installed and the specified
     * {@code AccessControlContext} was not created by system code and the
     * caller's {@code ProtectionDomain} has not been granted the
     * {@literal "createAccessControlContext"}
     * {@link java.security.SecurityPermission}, then the action is performed
     * with no permissions.
     *
     * @param <T> the type of the value returned by the
     *                  PrivilegedExceptionAction's {@code run} method.
     * @param action the action to be performed.
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null},
     *                then no additional restriction is applied.
     * @param perms the {@code Permission} arguments which limit the
     *              scope of the caller's privileges. The number of arguments
     *              is variable.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws PrivilegedActionException if the specified action's
     *         {@code run} method threw a <i>checked</i> exception
     * @throws NullPointerException if action or perms or any element of
     *         perms is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedAction,AccessControlContext)
     *
     * @since 1.8
     */
    @CallerSensitive
    public static <T> T doPrivileged(PrivilegedExceptionAction<T> action,
            @SuppressWarnings("removal") AccessControlContext context,
            Permission... perms)
        throws PrivilegedActionException
    {
        if (perms == null) {
            throw new NullPointerException("null permissions parameter");
        }
        Class<?> caller = Reflection.getCallerClass();
        try {
            return executePrivileged(action, limited(context, caller, toPermissions(perms)), caller);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }


    /**
     * Performs the specified {@code PrivilegedExceptionAction} with
     * privileges enabled and restricted by the specified
     * {@code AccessControlContext} and with a privilege scope limited by
     * specified {@code Permission} arguments.
     *
     * The action is performed with the intersection of the permissions
     * possessed by the caller's protection domain, and those possessed
     * by the domains represented by the specified
     * {@code AccessControlContext}.
     * <p>
     * If the action's {@code run} method throws an (unchecked) exception,
     * it will propagate through this method.
     *
     * <p> This method preserves the current AccessControlContext's
     * {@code DomainCombiner} (which may be null) while the action is performed.
     * <p>
     * If a security manager is installed and the specified
     * {@code AccessControlContext} was not created by system code and the
     * caller's {@code ProtectionDomain} has not been granted the
     * {@literal "createAccessControlContext"}
     * {@link java.security.SecurityPermission}, then the action is performed
     * with no permissions.
     *
     * @param <T> the type of the value returned by the
     *                  PrivilegedExceptionAction's {@code run} method.
     * @param action the action to be performed.
     * @param context an <i>access control context</i>
     *                representing the restriction to be applied to the
     *                caller's domain's privileges before performing
     *                the specified action.  If the context is
     *                {@code null},
     *                then no additional restriction is applied.
     * @param perms the {@code Permission} arguments which limit the
     *              scope of the caller's privileges. The number of arguments
     *              is variable.
     *
     * @return the value returned by the action's {@code run} method.
     *
     * @throws PrivilegedActionException if the specified action's
     *         {@code run} method threw a <i>checked</i> exception
     * @throws NullPointerException if action or perms or any element of
     *         perms is {@code null}
     *
     * @see #doPrivileged(PrivilegedAction)
     * @see #doPrivileged(PrivilegedAction,AccessControlContext)
     * @see java.security.DomainCombiner
     *
     * @since 1.8
     */
    @CallerSensitive
    public static <T> T doPrivilegedWithCombiner(PrivilegedExceptionAction<T> action,
                                                 @SuppressWarnings("removal") AccessControlContext context,
                                                 Permission... perms)
        throws PrivilegedActionException
    {
        if (perms == null) {
            throw new NullPointerException("null permissions parameter");
        }
        @SuppressWarnings("removal")
        AccessControlContext parent = getContext();
        @SuppressWarnings("removal")
        DomainCombiner dc = parent.getCombiner();
        Class<?> caller = Reflection.getCallerClass();
        try {
            return executePrivileged(action, limited(context, caller, dc, toPermissions(perms)), caller);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw wrapException(e);
        }
    }

    /**
     * Returns the {@code AccessControlContext}. i.e., it gets
     * the protection domains of all the callers on the stack,
     * starting at the first class with a non-null
     * {@code ProtectionDomain}.
     *
     * @return the access control context based on the current stack or
     *         {@code null} if there was only privileged system code.
     */

    @SuppressWarnings("removal")
    private static native AccessControlContext getStackAccessControlContext();

    /**
     * Returns the "inherited" {@code AccessControlContext}. This is the context
     * that existed when the thread was created. Package private so
     * {@code AccessControlContext} can use it.
     */

    @SuppressWarnings("removal")
    static native AccessControlContext getInheritedAccessControlContext();

    /**
     * This method takes a "snapshot" of the current calling context, which
     * includes the current thread's inherited {@code AccessControlContext}
     * and any limited privilege scope, and places it in an
     * {@code AccessControlContext} object.
     * This context may then be checked at a later point, possibly in another thread.
     *
     * @see AccessControlContext
     *
     * @return the {@code AccessControlContext} based on the current context.
     */

    @SuppressWarnings("removal")
    public static AccessControlContext getContext()
    {
        AccessControlContext acc = getStackAccessControlContext();
        if (acc == null) {
            // all we had was privileged system code. We don't want
            // to return null though, so we construct a real ACC.
            // We can't build an AccessControlContext without causing
            // an Error during initialization of VM, when using StackWalker 
            // getContext implementation.
            return AccessControlContext.create(null, true);
        } else {
            acc = acc.optimize();
            // If we want scoped subjects to be first class participants
            // If this context is used in Subject.doAs, the SubjectDomainCombiner
            // will be replaced.
            SubjectDomainCombiner sdc = SubjectDomainCombiner.currentAll();
            if (sdc != null){              
                DomainCombiner existing = acc.getCombiner();
                ProtectionDomain[] combined = sdc.combine(acc.getContext(), null);
                // Also inject into privilegedContext if present
                AccessControlContext privileged = acc.privilegedContext();
                if (privileged != null) {
                    ProtectionDomain[] combinedPrivileged = sdc.combine(
                        privileged.getContext(), null);
                    privileged = AccessControlContext.create(
                        combinedPrivileged, privileged.privilegedContext(),
                        privileged.getCombiner(), privileged.isPrivileged());
                }
                acc = AccessControlContext.create(combined, privileged, existing, acc.isPrivileged());
            }
            return acc;
        }
    }

    /**
     * Determines whether the access request indicated by the
     * specified permission should be allowed or denied, based on
     * the current {@code AccessControlContext} and security policy.
     * This method quietly returns if the access request
     * is permitted, or throws an {@code AccessControlException} otherwise. The
     * {@code getPermission} method of the {@code AccessControlException}
     * returns the {@code Permission} object instance ({@code perm}}.
     *
     * @param perm the requested permission.
     *
     * @throws    AccessControlException if the specified permission
     *            is not permitted, based on the current security policy.
     * @throws    NullPointerException if the specified permission
     *            is {@code null} and is checked based on the
     *            security policy currently in effect.
     */

    @SuppressWarnings("removal")
    public static void checkPermission(Permission perm)
        throws AccessControlException
    {
        //System.err.println("checkPermission "+perm);
        //Thread.currentThread().dumpStack();

        if (perm == null) {
            throw new NullPointerException("permission can't be null");
        }

        AccessControlContext acc = getContext();
        acc.checkPermission(perm);
    }
    
    private static PermissionCollection<Permission> toPermissions(Permission [] perms){
        Permissions p = new Permissions();
        for (int i = 0, len = perms.length; i < len; i++){
            if (perms[i] == null) throw new NullPointerException("null permission not permitted in array");
            p.add(perms[i]);
        }
        return p;
    }

    /**
     * Unlimited privilege call.
     */
    @CallerSensitive
    private static <T> T doUnlimited(PrivilegedAction<T> action)
    {
        Class<?> caller = Reflection.getCallerClass();
        return executePrivileged(action, null, caller);
    }
    
    private static CodeSource getResource(Class<?> clazz){
        // Don't use lambda, in case of bootstrap issues.
        
        // Reuse Certificates in case there are multiple instances
        // with different signers and they need to be destinguished?
        // This could interfere with Certificate based grants?  No,
        // Certificate grants shouldn't be broad brushed, it should be 
        // a combination of URI, Certificates and Principals that grant 
        // permission, otherwise it's bad policy, similar to AllPermission.
        // EG URL spoofed address might have URI and Principals, but not
        // Certificates, we don't want to grant imposter code permission,
        // all conditions must be satisfied.
        ProtectionDomain callerDomain = clazz.getProtectionDomain();
        CodeSource callerCodeSource = callerDomain.getCodeSource();
        Module module = clazz.getModule();
        String moduleName = module != null ? module.getName() : null;
        if (moduleName != null){
            StringBuilder sb = new StringBuilder();
            String className = clazz.getName();
            int index = className.indexOf('$');
            if (index > 0){
                className = className.substring(0, index);
            }
            sb.append("jrt:/").append(moduleName).append("/").append(className);
            try {
                return new CodeSource(Uri.escapeAndCreate(sb.toString()).toURL(), 
                        callerCodeSource != null?
                        callerCodeSource.getCertificates() : null);
            } catch (MalformedURLException | URISyntaxException e){
                // SECURITY: Return null CodeSource on exception.
                // A null CodeSource cannot match any policy grants,
                // preventing privilege escalation if URI validation fails.
                // This fail-secure approach ensures that malformed URIs
                // cannot be exploited to bypass policy enforcement.
                return null;
            }
        }
            
        // bootstrap workaround for null modules and null ClassLoaders
        if (callerCodeSource != null){
            try {
                String urlstring = callerCodeSource.getLocationNoFragString();
                StringBuilder sb = new StringBuilder();
                sb.append(urlstring);
                String className = clazz.getName();
                int index = className.indexOf('$');
                if (index > 0){
                    className = className.substring(0, index);
                }
                sb.append("/").append(className);
                return new CodeSource(Uri.escapeAndCreate(sb.toString()).toURL(),
                        callerCodeSource.getCertificates());
            } catch (MalformedURLException | URISyntaxException ex) {
                // SECURITY: Return null CodeSource on exception.
                // A null CodeSource cannot match any policy grants,
                // preventing privilege escalation if URI validation fails.
                // This fail-secure approach ensures that malformed URIs
                // cannot be exploited to bypass policy enforcement.
                return null;
            }
        }
        return null;
    }

    private static AccessControlContext limited(AccessControlContext context,
                                                Class<?> caller,
                                                DomainCombiner combiner,
                                                PermissionCollection<Permission> perms){
        if (AccessControlContext.hasStarted()){
            return doUnlimited(new PrivilegedAction<AccessControlContext>(){
                @Override
                public AccessControlContext run() {
                    CodeSource cs = caller != null ? getResource(caller) : null;
                    ProtectionDomain pd = new DomainIdentity(cs, perms, null, null,
                                caller != null ? getProtectionDomain(caller) : null);
                    if (context == null){
                        return AccessControlContext.create(
                                new ProtectionDomain[]{pd},
                                (AccessControlContext) null,
                                combiner, true);
                    } else {
                        if (combiner != null){
                            return context.intersectionOfPermsDoWithCombiner(combiner, pd);
                        } else {
                            return context.intersectionPermissions(pd);
                        }
                    }
                }
            });
        }   
        return context;
    }

    private static AccessControlContext limited(AccessControlContext context, Class<?> caller, PermissionCollection<Permission> perms){
        return limited(context, caller, null, perms);
    }

    private static AccessControlContext limited(AccessControlContext context, Class<?> caller){
        return limited(context, caller, null, null);
    }
}
