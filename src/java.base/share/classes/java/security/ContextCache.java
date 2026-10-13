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

import au.zeus.jdk.concurrent.RC;
import au.zeus.jdk.concurrent.Ref;
import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Initialized by VM, not loaded by same ClassLoader as AccessControlContext.
 */
class ContextCache {
    private static final int MIN_SLOTS = 64;
    private static final int MAX_SLOTS = 1 << 20;   // about 4 MB of references; anything larger is a mistake
    
    private ContextCache(){};

    static {
        // Initialize the random number generator for the AccessControlContext cache.
        ThreadLocalRandom.current();
        // Permission is not required as we are pre SecurityManager initialization and the cache is not exposed to untrusted code.
        int slots = slots(Integer.parseInt(System.getProperty("accessControlContext.cache.size", "4096")));
        AtomicReferenceArray<WeakReference<AccessControlContext>> CONTEXTS =
            new AtomicReferenceArray<>(slots);
        AccessControlContext.initCache(CONTEXTS, slots);
        // Ensure AtomicReferenceArray methods we use have their VarHandles initialized prior to SM.
        CONTEXTS.get(0);
        CONTEXTS.getAcquire(0);
        CONTEXTS.set(0, null);
        CONTEXTS.setRelease(0, null);
        CONTEXTS.compareAndSet(0, null, null);
    }

    static int slots(int requested) {
        int n = Math.clamp(requested, MIN_SLOTS, MAX_SLOTS);
        // Smallest power of two >= n.  n >= 2 here, so n - 1 >= 1 and the shift is well defined.
        return Integer.highestOneBit(n - 1) << 1;
    }
    
}