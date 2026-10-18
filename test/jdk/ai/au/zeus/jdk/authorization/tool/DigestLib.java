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

/**
 * Packaged into a jar at run time by {@code SecurityPolicyWriterDigestTest}
 * and loaded from it through a URLClassLoader, so its ProtectionDomain is the
 * jar's.  The property read is privileged, so only this jar's domain is
 * checked: the permission must come from the jar's own grant.
 *
 * @author Claude Opus 5.5 (claude-opus-5-5) -- AI-authored under AI_POLICY.md 4.1 (Zone T)
 */
public class DigestLib {
    public static final String PROPERTY = "ai.test.digest.lib.marker";

    @SuppressWarnings("removal")
    public static String run() {
        return AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty(PROPERTY));
    }
}
