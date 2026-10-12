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
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Initialized by VM, not loaded by same ClassLoader as AccessControlContext.
 */
class ContextCache {
    
    private ContextCache(){};

    static {
        // Initialize the random number generator for the AccessControlContext cache.
        ThreadLocalRandom.current();
        // Reference type change from time based to weak, with short cycle time
        // of 4000 to pass jtreg:test/jdk/java/lang/ClassLoader/forNameLeak/ClassForNameLeak.java
        // Consider increasing test time if we need longer cycle times.
        // Time of 3000L required to pass jtreg:test/langtools/tools/javac/Paths/MineField.java
        // Note, weakly referenced value causes collection of Key value tuple,
        // if there are contexts with identical hash only one will be collected.
        // Non-blocking is a requirement.
        ConcurrentMap<AccessControlContext.ContextKey,AccessControlContext> CONTEXTS 
            = RC.concurrentMap(new ConcurrentSkipListMap<>(), Ref.STRONG, Ref.WEAK, 2000L, 2000L);
        AccessControlContext.initCache(CONTEXTS);
    }
    
}