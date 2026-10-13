/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  This particular file is
 * subject to the "Classpath" exception as provided in the LICENSE file
 * that accompanied this code.
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
 */

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Helper for ContextCacheStabilityTest.  The test defines this class a
 * second time in its own class loader with its own ProtectionDomain, so
 * that a second non-system domain can be placed on the stack and in a
 * thread's inherited context.  It refers only to java.base types.
 *
 * <p>Requests:
 * <ul>
 * <li>{@code "getContext"}: returns {@code AccessController.getContext()}
 *     with this class's domain on the stack above the caller's.</li>
 * <li>a {@code Supplier}: calls it, so the caller's domain appears on the
 *     stack both above and below this class's domain.</li>
 * <li>a {@code Runnable}: runs it in a new platform thread created inside
 *     {@code doPrivileged}, so the thread's inherited context holds only
 *     this class's domain; waits for it to finish.</li>
 * </ul>
 *
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 */
public class ContextCacheStabilityHelper implements Function<Object, Object> {

    public ContextCacheStabilityHelper() {
    }

    @Override
    @SuppressWarnings("removal")
    public Object apply(Object request) {
        if ("getContext".equals(request)) {
            return AccessController.getContext();
        }
        if (request instanceof Supplier<?> supplier) {
            return supplier.get();
        }
        if (request instanceof Runnable task) {
            Thread thread = AccessController.doPrivileged(
                    (PrivilegedAction<Thread>) () ->
                            new Thread(task, "ContextCacheStabilityHelper"));
            thread.start();
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            }
            return null;
        }
        throw new IllegalArgumentException(String.valueOf(request));
    }
}
