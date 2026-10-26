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

package au.zeus.jdk.authorization.tool;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilePermission;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectStreamException;
import java.io.PrintWriter;
import java.io.Writer;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.SocketPermission;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLPermission;
import java.net.URLConnection;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.DigestCodeSource;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.Permissions;
import java.security.Policy;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.function.Function;
import java.lang.System.Logger;
import java.lang.System.Logger.Level;
import javax.security.auth.PrivateCredentialPermission;
import au.zeus.jdk.authorization.policy.PolicyInitializationException;
import au.zeus.jdk.net.Uri;
import au.zeus.jdk.authorization.sm.CombinerSecurityManager;
import au.zeus.jdk.authorization.policy.ConcurrentPolicyFile;
import au.zeus.jdk.authorization.policy.PermissionComparator;
import au.zeus.jdk.authorization.policy.PolicyUtils;
import au.zeus.jdk.authorization.policy.CodeSourceKey;

/**
 * This SecurityManager can be used in a simulation environment to generate
 * policy files that conform to the principle of least privilege.
 * <p>
 * It should be installed from the command line using the following system property:<br>
 * <code>-Djava.security.manager=org.apache.river.tool.SecurityPolicyWriter</code>
 * <p>
 * The policy file generated will be specific to the runtime where it is generated.
 * Users should edit the files after generation if they wish to deploy the policy
 * else where, replacing file path characters etc.
 * <p>
 * Note that the file generated will not contain the <code>ProtectionDomain</code>
 * of the jar file containing this SecurityManager, neither will it contain
 * Java platform jars.
 * <p>
 * 
 * The following properties should be set to obtain CodeSource signer 
 * Certificate Aliases.<br>
 * <table><caption>System Properties</caption>
 * <tr>
 * <td>System Property</td>
 * <td>Explanation</td>
 * </tr><tr>
 * <td>java.security.policy</td>
 * <td>The policy file location.</td>
 * </tr><tr>
 * <td>javax.net.ssl.trustStore</td>
 * <td>The location of the KeyStore,  if no location is specified, then the 
 * cacerts file in the lib/security subdirectory of the JDK installation 
 * directory is used. If specified, the location is treated as a URL.
 * If no protocol is specified in the URL or it is an unknown protocol, 
 * then, the location is treated as a file name.</td>
 * </tr><tr>
 * <td>javax.net.ssl.trustStoreType</td>
 * <td>The KeyStore type, If no keystore type is specified, then the type 
 * returned by KeyStore.getDefaultType() is used.</td>
 * </tr><tr>
 * <td>javax.net.ssl.trustStorePassword</td>
 * <td>The KeyStore password, if no password is specified, then no password
 * is used when loading the keystore.</td>
 * </tr>
 * </table>
 * <p>
 * A property file may be specified to replace paths with properties to
 * allow these to be customized for later policy file expansion in deployment for
 * CodeSource url and FilePermission path's, by setting the following property:
 * <code>-DpolpAudit.path.properties=</code> Properties defined in this
 * property file shouldn't reference other properties declared in this file.
 * <p>
 * If a policy file already exists, only additional permission grants
 * will be added during subsequent test runs.
 * <p>
 * Generated policy files should be edited after running each integration test
 * when widening
 * permission scope, such as SocketPermission which will typically specify a local
 * IP address. Subsequent integration tests append missing permissions, so it
 * is important to widen scope prior to adding more permission grants.
 * <p>
 * Note that the logger <code>net.jini.security.policy</code> should be set to
 * <code>Level.CONFIG</code> to
 * log any syntax errors in edited policy files.  If a policy file contains
 * a syntax error, all permissions granted in the new policy file will be ignored, 
 * this results in duplication of permissions in the new policy file as they will be 
 * re-granted until the syntax error is addressed.  For this reason the log 
 * output should be checked following each manual edit.
 * 
 * @see KeyStore
 * @author Peter Firmstone
 * @since 3.0.0
 */
@SuppressWarnings({"removal", "serial"})
public class SecurityPolicyWriter extends CombinerSecurityManager{
    
    private static Logger logger;
    private static final Object loggerLock = new Object();
    private final Policy POLICY;
    private final URL policyLocation;

    /**
     * @return the logger
     */
    private static Logger getLogger() {
        synchronized (loggerLock){
            if (logger != null) return logger;
            logger = 
            System.getLogger("au.zeus.jdk.authorization.tool");
            return logger;
        }
    }
    // Use concurrent collections to avoid deadlock from recursive calls.
    private final ConcurrentMap<ProtectionDomain, Collection<Permission>> domainPermissions;
    private static KeyStore keyStore = null;
    private static final Object keyStoreLock = new Object();
    private final ConcurrentMap<Certificate,String> aliases;
    private final Cert certFunc;
    private final List<Entry<String,String>> replacements;   // longest value first
    private final String hostname;
    private final String tmpDir;
    private final String ephemeralPorts = System.getProperty("polpAudit.ephemeralPorts", "32768-65535");
    private final int ephemeralLow, ephemeralHigh;   // parsed from ephemeralPorts
    
    @SuppressWarnings("deprecation")
    private SecurityPolicyWriter(
	    ConcurrentMap<ProtectionDomain,Collection<Permission>> map) 
    {
        super();
        
        domainPermissions = map;
        aliases = new ConcurrentHashMap<Certificate,String>();
        certFunc = new Cert();
        String securityPolicyWriterPropLocation = System.getProperty("polpAudit.path.properties");
        hostname = System.getProperty("HOST");
        Properties p = new Properties();
        if (securityPolicyWriterPropLocation != null){
            try {
                FileReader fr = new FileReader(securityPolicyWriterPropLocation);
                p.load(fr);
                Iterator<Entry<Object,Object>> propsit = p.entrySet().iterator();
                while (propsit.hasNext()){
                    Entry<Object,Object> entry = propsit.next();
                    System.setProperty((String) entry.getKey(), (String) entry.getValue());
                }
            } catch (FileNotFoundException ex) {
                getLogger().log(Level.ERROR, "Unable to read properties file", ex);
            } catch (IOException ex) {
                getLogger().log(Level.ERROR, "Unable to read properties file", ex);
            }
        }
        this.tmpDir = System.getProperty("java.io.tmpdir");
        p.put("java.io.tmpdir", tmpDir);
        p.put("java.home", System.getProperty("java.home"));
        if (hostname!= null) p.put("HOST", hostname);
        // Jini Support
        String jh = System.getProperty("jsk.home"); 
        if (jh != null) p.put("jsk.home", jh);
        String qh = System.getProperty("qa.home");  
        if (qh != null) p.put("qa.home", qh);
        Map<String,String> paths = new HashMap<String,String>(p.size());
        Set<Entry<Object,Object>> propSet = p.entrySet();
        Iterator<Entry<Object,Object>> propIt = propSet.iterator();
        while (propIt.hasNext()){
            Entry<Object,Object> props = propIt.next();
            Object key = props.getKey();
            Object value = props.getValue();
            if (key instanceof String && value instanceof String){
                paths.put(((String) value).replace('\\', '/'), (String) key);
            }
        }
        List<Entry<String,String>> r = new ArrayList<>(paths.entrySet());
        r.sort((a, b) -> Integer.compare(b.getKey().length(), a.getKey().length()));
        replacements = r;
        String policy = System.getProperty("java.security.policy");
        // One policy file only ==
        if (policy.startsWith("=")) policy= policy.substring(1);
        try {
            policy = PolicyUtils.expandURL(policy, System.getProperties());
        } catch (Exception ex){
            getLogger().log(Level.ERROR, "Unable to expand policy file path properties", ex);
        }
        URL dynamicURL = null;
        File policyFile = new File(policy);
        if (!policyFile.exists()){
	    try {
		policyFile.createNewFile();
	    } catch (IOException ex) {
                try {
                    dynamicURL = new URL(policy);
                } catch (MalformedURLException mex){
                    getLogger().log(Level.ERROR, "Unable to load policy", ex);
                    RuntimeException e = new RuntimeException("Unable to load policy");
                    e.addSuppressed(ex);
                    e.addSuppressed(mex);
                    throw e;
                }
            }
        } else {
            if (policyFile.isDirectory()) throw new RuntimeException("Directory found instead of file.");
        }
        if (dynamicURL == null){
            try {
                dynamicURL = policyFile.toURI().toURL();
            } catch (MalformedURLException mex){
                getLogger().log(Level.ERROR, "Unable to load policy", mex);
                RuntimeException e = new RuntimeException("Unable to load policy");
                e.addSuppressed(mex);
                throw e;
            }
        }
        getLogger().log(Level.INFO, "policy location: "+ dynamicURL.toString());
        policyLocation = dynamicURL;
        Policy polcy = null;
        try {
            polcy = new ConcurrentPolicyFile(new URL[]{dynamicURL});
        } catch (PolicyInitializationException ex) {
            getLogger().log(Level.ERROR, "Unable to create Policy instance", ex);
        }
        POLICY = polcy;
        int lo = 32768, hi = 65535;
        String spec = ephemeralPorts.trim();
        int dash = spec.indexOf('-');
        try {
            if (dash > 0) {
                lo = Integer.parseInt(spec.substring(0, dash).trim());
                String h = spec.substring(dash + 1).trim();
                hi = h.isEmpty() ? 65535 : Integer.parseInt(h);
            }
        } catch (NumberFormatException e) {
            getLogger().log(Level.WARNING, "Ignoring polpAudit.ephemeralPorts=" + spec + "; using 32768-65535");
            lo = 32768; hi = 65535;
        }
        if (lo < 1 || hi > 65535 || lo > hi) { lo = 32768; hi = 65535; }
        ephemeralLow = lo; ephemeralHigh = hi;
    } 
    
    public SecurityPolicyWriter() {
        this(new ConcurrentHashMap<ProtectionDomain,Collection<Permission>>());
        Runtime.getRuntime().addShutdownHook(shutdownHook());
    }
    
    private URL policyLocation() {
        return policyLocation;
    }
    
    private static KeyStore keyStore(){
	synchronized (keyStoreLock){
	    if (keyStore == null){
		try {
		    keyStore = initStore();
		} catch (IOException ex) {
		    getLogger().log(Level.ERROR, "Unable to create KeyStore instance", ex);
		} catch (GeneralSecurityException ex) {
		    getLogger().log(Level.ERROR, "Unable to create KeyStore instance", ex);
		}
	    }
	    return keyStore;
	}
    }
    
    /**
     * Initializes trust store and cert stores based on system property values.
     */
    private static KeyStore initStore() throws IOException, GeneralSecurityException {
	String path, type, passwd;
	if ((path = System.getProperty("javax.net.ssl.trustStore")) != null) {
	    type = System.getProperty(
		"javax.net.ssl.trustStoreType", KeyStore.getDefaultType());
	    passwd = System.getProperty("javax.net.ssl.trustStorePassword");
	} else {
	    path = System.getProperty("java.home") + "/lib/security/cacerts";
	    type = KeyStore.getDefaultType();
	    passwd = null;
	}
	KeyStore kstore = KeyStore.getInstance(type);
	InputStream in;
	URL url = null;
	try {
	    url = new Uri(path).toURL();
	} catch (MalformedURLException e) {
	    getLogger().log(Level.ERROR, "Keystore initialization failed", e);
	} catch (URISyntaxException ex) {
	    getLogger().log(Level.ERROR, "Keystore initialization failed", ex);
	}
	if (url != null) {
	    in = url.openStream();
	} else {
	    in = new FileInputStream(path);
	}
	try {
	    kstore.load(in, (passwd != null) ? passwd.toCharArray() : null);
	} finally {
	    in.close();
	}
//	if (getLogger().isLoggable(Level.FINEST)) {
//	    getLogger().log(Level.FINEST, "loaded trust store from {0} ({1})",
//		       new Object[]{ path, type });
//	}
        return kstore;
    }
    
    @Override
    protected boolean checkPermission(ProtectionDomain pd, Permission p){
        // An ephemeral grant (e.g. a human-gated escalation)  must never enter the generated floor:
        // recording it would promote a transient, human-gated grant to a permanent
        // baseline grant. Detect it while the one-shot grant is still live (record
        // time -- it is gone by shutdown): stable policy denies AND a one-shot grant
        // allows. Observe-only still allows the operation; it is simply not recorded.
        if (!pd.implies(p) && pd.impliesEphemeral(p)) return true;
        try{
            pd = new ProtectionDomainKey(pd);
        } catch (URISyntaxException ex) {
            getLogger().log(Level.ERROR, "Unable to create ProtectionDomainKey", ex);
        }
	Collection<Permission> perms = domainPermissions.get(pd);
	    if (perms == null) {
		perms = new ConcurrentSkipListSet<Permission>(new PermissionComparator());
                // The following code would include the static permissions from
                // the ProtectionDomain.  This doesn't seem like a good idea,
                // as these permissions may be granted by a ClassLoader at
                // creation time, so commented out.
//                PermissionCollection pc = pd.getPermissions();
//                if (pc != null) {
//                    Enumeration<Permission> e = pc.elements();
//                    while (e.hasMoreElements()){
//                        perms.add(e.nextElement());
//                    }
//                }
		Collection<Permission> existed = domainPermissions.putIfAbsent(pd, perms);
		if (existed != null) perms = existed;
	    }
	if (!(p instanceof AllPermission)) perms.add(p);
        return true;
    }
    
    private Thread shutdownHook(){
        Thread t = new Thread ( new Runnable(){
            @Override
            public void run (){
                // File will append, URL is assumed to handle output appropriately.
                PrintWriter pw = null;
                try {
                    Writer w;
		    URL policyURL = policyLocation();
                    File policyFile = new File(policyURL.toURI());
                    if (policyFile.exists()){
                        w = new FileWriter(policyFile, true);
                    } else {
                        URLConnection con = policyURL.openConnection();
                        con.setDoOutput(true);
                        w = new OutputStreamWriter(con.getOutputStream());
                    }
		    pw = new PrintWriter(new BufferedWriter(w));
                
                //REMIND: keystore "some_keystore_url", "keystore_type", "keystore_provider";
                //        keystorePasswordURL "some_password_url";
                
//                grant signedBy "signer_names", codeBase "URL",
//                    principal principal_class_name "principal_name",
//                    principal principal_class_name "principal_name",
//                    ... {
//
//                      permission permission_class_name "target_name", "action", 
//                          signedBy "signer_names";
//                      permission permission_class_name "target_name", "action", 
//                          signedBy "signer_names";
//                      ...
//                  };
                    Map<String, String[]> prePolpAudit = new HashMap<>(4);
                    prePolpAudit.put("jrt:/java.base/java.util.Arrays", 
                            new String []{
                                "    permission java.util.PropertyPermission \"java.util.Arrays.useLegacyMergeSort\", \"read\";\n"
                            });
                    prePolpAudit.put("jrt:/java.base/sun.security.action.GetPropertyAction",
                            new String[]{
                                "    permission java.util.PropertyPermission \"stackwalk.debug\", \"read\";\n",
                                "    permission java.util.PropertyPermission \"user.dir\", \"read\";\n"
                            });
                    prePolpAudit.put("jrt:/java.base/sun.security.util.SecurityProperties",
                            new String[]{
                                "    permission java.security.SecurityPermission \"getProperty.jdk.io.permissionsUseCanonicalPath\";\n",
                                "    permission java.util.PropertyPermission \"jdk.io.permissionsUseCanonicalPath\", \"read\";\n"
                            });
                    prePolpAudit.put("jrt:/java.base/java.lang.Class",
                            new String[]{
                                "    permission java.lang.reflect.ReflectPermission \"suppressAccessChecks\";\n"
                            });

                    StringBuilder grant = new StringBuilder(1024);
                    Set<String> written = new HashSet<>();// to avoid duplicate permission lines in a grant block
                    List<String> toAppend = new ArrayList<>();
                    Iterator<Entry<ProtectionDomain,Collection<Permission>>> it 
                            = domainPermissions.entrySet().iterator();
                    while (it.hasNext()){
                        grant.setLength(0);
                        written.clear();
                        toAppend.clear();
                        Entry<ProtectionDomain,Collection<Permission>> entry = it.next();
                        try {
                            ProtectionDomain pd = entry.getKey();
                            Collection<Permission> perms = entry.getValue();
                            Collection<Permission> permsToPrint = new ArrayList<Permission>();
                            PermissionCollection<Permission> pc = new Permissions();
                            Iterator<Permission> pIt = perms.iterator();
                            while (pIt.hasNext()){
                                Permission p = pIt.next();
                                if (POLICY != null && POLICY.implies(pd, p) || pc.implies(p)) continue;
                                pc.add(p);
                                permsToPrint.add(p);
                            }
                            if (permsToPrint.isEmpty()) continue;
                            CodeSource cs = null; 
                            Principal [] principals = null;
                            try {
                                cs = (pd instanceof ProtectionDomainKey pdk)
                                        ? pdk.originalCodeSource()
                                        : pd.getCodeSource();
                                principals = pd.getPrincipals();
                            } catch (NullPointerException e){
                                // On some occassions ProtectionDomain hasn't been
                                // safely published.
                                System.err.println(
                                    "ProtectionDomain wasn't safely published: " 
                                    + pd.toString()
                                );
                            }
                            // Delegate tasks to an executor so we don't cause recursive calls / stack overflow.		    
                            if (cs != null){
                                Certificate [] signers = cs.getCertificates();
                                if (signers != null && signers.length > 0){
                                     if (keyStore() != null){
                                        for (int i=0, l=signers.length; i<l; i++){
                                            aliases.computeIfAbsent(signers[i], certFunc);
                                        }
                                    }
                                }
                            }
                            if (cs != null || (principals != null && principals.length > 0)){
                                grant.append("grant ");
                                if (keyStore != null){
                                    Certificate [] signers = cs != null ? cs.getCertificates() : null;
                                    if (signers != null && signers.length > 0) {
                                        List<String> alia = new ArrayList<String>(signers.length);
                                        for (int i=0, l=signers.length; i<l; i++){
                                            alia.add(aliases.get(signers[i]));
                                        }
                                        if (!alia.isEmpty()){
                                            grant.append("signedBy \"");
                                            for (int i=0, l=alia.size(); i<l; i++){
                                               if (i != 0) grant.append(",");
                                               grant.append(alia.get(i));
                                            }
                                            grant.append("\", ");
                                            grant.append("\n");
                                        }
                                    }
                                }
                                Object cb = cs != null ? cs.getUriLocation() : null;
                                if (cb instanceof Uri codebase){
                                    grant.append("codebase \"");
                                    String codebaseStr = replaceValuesWithProperties(codebase.toString());
                                    grant.append(codebaseStr);
                                    grant.append("\"");
                                    boolean hasDigest = cs instanceof DigestCodeSource dcs
                                            && dcs.getDigestAlgorithm() != null
                                            && dcs.getDigest() != null;
                                    boolean hasPrincipals = principals != null
                                            && principals.length > 0;
                                    if (hasDigest || hasPrincipals) {
                                        grant.append(",");
                                    } else {
                                        String[] permsToAdd = prePolpAudit.remove(codebaseStr);
                                        if (permsToAdd != null){
                                            for (int i = 0, l = permsToAdd.length; i < l; i++){
                                                if (written.add(permsToAdd[i])){
                                                    toAppend.add(permsToAdd[i]);
                                                }
                                            }
                                        }
                                    }
                                    grant.append("\n");
                                }
                                // Emit digest clause for DigestCodeSource.
                                if (cs instanceof DigestCodeSource dcs) {
                                    String algorithm = dcs.getDigestAlgorithm();
                                    byte[] digestBytes = dcs.getDigest();
                                    if (algorithm != null && digestBytes != null) {
                                        grant.append("    digest \"");
                                        grant.append(algorithm);
                                        grant.append(':');
                                        grant.append(hexEncode(digestBytes));
                                        grant.append("\"");
                                        if (principals != null && principals.length > 0) grant.append(",");
                                        grant.append("\n");
                                    }
                                }
                                // Emit principal clauses.
                                if (principals != null && principals.length > 0) {
                                    for (int i = 0; i < principals.length; i++) {
                                        grant.append("    principal ");
                                        grant.append(principals[i].getClass().getCanonicalName());
                                        grant.append(" \"");
                                        grant.append(PolicyUtils.escape(principals[i].getName()));
                                        grant.append("\"");
                                        if (i < principals.length - 1) grant.append(",");
                                        grant.append("\n");
                                    }
                                }
                            } else {
                                // No codebase and no principals: emit a bare "grant" block
                                // that applies to all code regardless of origin.
                                grant.append("grant\n");
                            }
                            grant.append("{\n");
                            // Add any
                            for (String permAdd : toAppend) grant.append(permAdd);
                            Iterator<Permission> permIt = permsToPrint.iterator();
                            while (permIt.hasNext()) {
                                Permission p = permIt.next();
                                StringBuilder line = new StringBuilder(128);
                                try {
                                    line.append("    permission ").append(p.getClass().getCanonicalName()).append(" \"");
                                    if (p instanceof PrivateCredentialPermission pcp) {
                                        String credential = pcp.getCredentialClass();
                                        String [][] princpals = pcp.getPrincipals();
                                        line.append(credential);
                                        line.append(" ");
                                        for (int i=0,l=princpals.length; i<l; i++){
                                            String [] pals = princpals [i];
                                            for (int j=0,m=pals.length; j<m; j++){
                                                line.append(pals[j]);
                                                if (j < m-1) line.append(" \\\"");
                                                else line.append("\\\"");
                                            }
                                            if (i < l-1) line.append(" ");
                                        }
                                    } else {
                                        /* Some complex permissions have quoted strings embedded or
                                        literal carriage returns that must be escaped.  */
                                        String name = p.getName();
                                        if (p instanceof FilePermission) {
                                            if (name.contains(tmpDir)) {
                                                name = "${java.io.tmpdir}${/}-";
                                            } else {
                                                name = replaceValuesWithProperties(name).replace("/", "${/}");
                                            }
                                        } else if (p instanceof SocketPermission) {
                                            name = socketName(name); 
                                            if (hostname != null) name = name.replace(hostname, "${HOST}");
                                        } else if (p instanceof URLPermission) {
                                            if (hostname != null) name = name.replace(hostname, "${HOST}");
                                        }
                                        line.append(PolicyUtils.escape(name));
                                    }
                                    String actions = p.getActions();
                                    if (actions != null && !actions.isEmpty()) {
                                        line.append("\", \"").append(PolicyUtils.escape(actions));
                                    }
                                    line.append("\";\n");
                                    String text = line.toString();
                                    if (written.add(text)) grant.append(text);
                                } catch (RuntimeException ex) {
                                    grant.append("    // not recorded: " + oneLine(p.getClass().getName() + " " + p.getName()) + " (" + oneLine(ex.toString()) + ")\n");
                                    getLogger().log(Level.ERROR, "Unable to write permission to policy file", ex);
                                }
                            }
                            grant.append("};\n\n");
                            pw.write(grant.toString());
                        } catch (RuntimeException ex) {
                            pw.write("// grant not recorded: " + oneLine(String.valueOf(entry.getKey())) + " (" + oneLine(ex.toString()) + ")\n\n");
                            getLogger().log(Level.ERROR, "Unable to write grant to policy file", ex);
                        }
                    }
                    for (Entry<String, String[]> entry : prePolpAudit.entrySet()){
                        grant.setLength(0);
                        grant.append("grant ");
                        grant.append("codebase \"");
                        grant.append(entry.getKey());
                        grant.append("\"");
                        grant.append(" {\n");
                        String [] permsLines = entry.getValue();
                        for (String permLine : permsLines){
                            grant.append(permLine);
                        }
                        grant.append("};\n\n");
                        pw.write(grant.toString());
                    }
                    getLogger().log(Level.INFO, "Finished writing additional permissions, if any, to policy file.");
                } catch (IOException ex) {
                    getLogger().log(Level.ERROR, "unable to write to policy file ", ex);
                } catch (URISyntaxException ex) {
                    getLogger().log(Level.ERROR, "unable to write to policy file ", ex);
                } finally {
                    if (pw != null) {
                        pw.flush();
                        pw.close();
                    }
                }
            }
        },"SecurityPolicyWriter policy creation thread");
        if (t.isDaemon()) t.setDaemon(false);
        /**
         * See jtreg sun bug ID:4404702
         * This ensures that this thread doesn't unnecessarily hold 
         * a strong reference to a ClassLoader, thus preventing
         * it from being garbage collected.
         */ 
        t.setContextClassLoader(ClassLoader.getSystemClassLoader());
        return t;
    }
    
    private String replaceValuesWithProperties(String s){
        s = s.replace('\\', '/');
        for (Entry<String,String> path : replacements) {
            String value = path.getValue();
            String key = path.getKey();
            String prop = "${" + value + "}";
            s = s.replace(key, prop);
            if ("java.io.tmpdir".equals(value) && key.endsWith("/")) {
                getLogger().log(Level.INFO, "temp directory: {0}", s);
                s = s.replace(key.substring(0, key.length() - 1), prop);
            }
        }
        return s;
    }
    
    /** Encodes {@code bytes} as a lowercase hexadecimal string. */
    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    

    private static String oneLine(String s) {
        return s == null ? "null" : s.replace('\r', ' ').replace('\n', ' ');
    }

    private String socketName(String name) {
        int colon = name.lastIndexOf(':');
        if (colon <= 0 || colon == name.length() - 1 || name.endsWith("]")) return name;   // no port
        String host = name.substring(0, colon);
        if (!isLoopback(host)) return name;
        int port;
        try { port = Integer.parseInt(name.substring(colon + 1)); }
        catch (NumberFormatException e) { return name; }                  // already a range or "*"
        if (port == 0 || port < ephemeralLow || port > ephemeralHigh) return name;
        return host + ":" + ephemeralLow + "-" + ephemeralHigh;
    }

    private static boolean isLoopback(String host) {                     // textual: no DNS
        return host.equalsIgnoreCase("localhost") || host.startsWith("127.")
            || host.equals("[::1]") || host.equals("[0:0:0:0:0:0:0:1]");
    }
    
    private class Cert implements Function<Certificate,String> {

        @Override
        public String apply(Certificate t) {
            try {
                return keyStore().getCertificateAlias(t);
            } catch (KeyStoreException ex) {
                getLogger().log(Level.ERROR, "Alias not found in keystore", ex);
            }
            return null;
        }
        
    }
    
    /**
     * ProtectionDomainKey identity ignores the ClassLoader.
     */
    private static class ProtectionDomainKey extends ProtectionDomain{

        private final CodeSourceKey csKey;          // null for system code
        private final Principal[] princiPals;
        private final int hashCode;

        ProtectionDomainKey(ProtectionDomain pd) throws URISyntaxException {
            this(new CodeSourceKey(pd.getCodeSource()), pd.getPermissions(), pd.getPrincipals());
        }

        private ProtectionDomainKey(CodeSourceKey csKey, PermissionCollection<? extends Permission> perms, Principal [] p){
            super(csKey != null ? csKey.getCodeSource() : null, perms, null, p);
            this.princiPals = p;
            this.csKey = csKey;
            this.hashCode = 29 * (29 * 7 + Objects.hashCode(csKey)) + Arrays.deepHashCode(princiPals);
        }

        /**
         * Returns the original CodeSource (which may be a DigestCodeSource),
         * not the UriCodeSource wrapper used internally for equality checks.
         */
        CodeSource originalCodeSource() {
            return csKey != null ? csKey.getCodeSource() : null;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof ProtectionDomainKey k
                && Objects.equals(csKey, k.csKey)
                && Arrays.deepEquals(princiPals, k.princiPals);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

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
     */
    private static class UriCodeSource extends CodeSource {
        private static final long serialVersionUID = 1L;
        private final Uri uri;
        private final int hashCode;
        
        UriCodeSource(CodeSource cs){
            this(cs.getLocation(), cs.getCertificates());
        }
        
        UriCodeSource(URL url, Certificate [] certs){
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
            if (uri == null) return super.equals(o);
            UriCodeSource that = (UriCodeSource) o;
            if ( !uri.equals(that.uri)) return false;
            Certificate [] mine = getCertificates();
            Certificate [] theirs = that.getCertificates();
            if ( mine == null && theirs == null) return true;
            if ( mine == null && theirs != null) return false;
            if ( mine != null && theirs == null) return false;
            return (Arrays.asList(getCertificates()).equals(
                    Arrays.asList(that.getCertificates())));
        }
        
        public Object writeReplace() throws ObjectStreamException {
            return new CodeSource(getLocation(), getCertificates());
        }
       
    }
}
