package com.hortonworks.ldap

import com.beust.jcommander.JCommander
import com.beust.jcommander.Parameter
import org.apache.log4j.Logger

import javax.naming.Context
import javax.naming.NamingEnumeration
import javax.naming.directory.Attributes
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.*

/**
 *  A code example to demonstrate how StartTLS works
 *  Note: This example has been tested to work with Active Directory 2003
 */
class StartTLSConnector {

    private static final Logger logger = Logger.getLogger(StartTLSConnector.class)

    @Parameter(names = "--truststore", description = "Custom truststore path")
    private String truststorePath = "~/Workspace/certificates/truststore.jks"

    @Parameter(names = "--truststorepass", description = "Truststore password", password = true)
    private String truststorePass = "changeit"

    @Parameter(names = "--keystore", description = "Custom keystore path")
    private String keystorePath = "~/Workspace/certificates/alopresto.jks"

    @Parameter(names = "--keystorepass", description = "Keystore password", password = true)
    private String keystorePass = "changeit"

    @Parameter(names = "--keystoretype", description = "Keystore type")
    private String keystoreType = "JKS"

    @Parameter(names = ["-h", "--host"], description = "host (no protocol)")
    private String host = "localhost"

    @Parameter(names = ["-p", "--port"], description = "port")
    private String port = "10389"

    @Parameter(names = ["-c", "--connect"], description = "host:port (no protocol)")
    private String connection = ""

    @Parameter(names = ["-g", "--get"], description = "Direct retrieval (cn=William Bligh,ou=people,o=SevenSeas)")
    private String getQuery = ""

    @Parameter(names = ["-s", "--search"], description = "Search query UID checked against ou=people,o=SevenSeas (hhornblo)")
    private String searchQuery = "hhornblo"

    @Parameter(names = "--principal", description = "Security principal to connect to LDAP")
    private String securityPrincipal = "uid=admin,ou=system"

    @Parameter(names = "--principalpass", description = "Password for security principal", password = true)
    private String securityCredentials = "secret"

    @Parameter(names = "--securityauth", description = "Security authentication for principal")
    private String securityAuthentication = "simple"

    LdapContext ctx
    StartTlsResponse tls


    public static void main(String[] args) {

        StartTLSConnector startTLSConnector = new StartTLSConnector()

        new JCommander(startTLSConnector, args);

        try {
            startTLSConnector.connect()
            startTLSConnector.look()
        } catch (Exception e) {
            logger.error("Exception executing the search: ", e)
            throw e
        } finally {
            startTLSConnector.close()
        }
    }

    private void look() {
        if (getQuery) {
            get(getQuery)
        } else {
            search(searchQuery)
        }
    }

    public void connect() {

        if (!connection) {
            connection = "${host}:${port}"
        }

        preparePaths()

        // To specify the trustStore, if any other than the default one:
        //    %JAVA_HOME%\lib\security\certs
        System.setProperty("javax.net.ssl.trustStore", truststorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", truststorePass); // optional

        logger.info("Using truststore: ${truststorePath}")

        // To specify client's keyStore where client's certificate is located
        // Note: Client's keyStore is optional for StartTLS negotiation and connection.
        //     But it is required for implicit client identity assertion
        //     by SASL EXTERNAL where client ID is extracted from certificate subject.
        System.setProperty("javax.net.ssl.keyStore", keystorePath);
        System.setProperty("javax.net.ssl.keyStoreType", keystoreType);
        System.setProperty("javax.net.ssl.keyStorePassword", keystorePass);

        logger.info("Using keystore: ${keystorePath}")

        Hashtable env = new Hashtable(5, 0.75f);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://${connection}" as String);

        logger.info("Connecting to: ldap://${connection}")

        /* Establish LDAP association */
        ctx = new InitialLdapContext(env, null);

        /* Requesting to start TLS on an LDAP association */
        ExtendedRequest tlsRequest = new StartTlsRequest();
        ExtendedResponse tlsResponse = ctx.extendedOperation(tlsRequest);

        /* Starting TLS */
        tls = (StartTlsResponse) tlsResponse;
        tls.negotiate();

        // A TLS/SSL secure channel has been established if you reach here.

        /* Assertion of client's authorization Identity -- Explicit way */
        ctx.addToEnvironment(Context.SECURITY_AUTHENTICATION, securityAuthentication);
        ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, securityPrincipal);
        ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, securityCredentials);
    }

    public List<SearchResult> search(final String searchQuery) {
        String searchFilter = "(&(objectClass=*)(uid=" + searchQuery + "))"
        final String searchBase = "ou=people,o=SevenSeas"

        def searchControls = new SearchControls()
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE)
        NamingEnumeration<?> namingEnum = ctx.search(searchBase, searchFilter, searchControls);
        logger.info("Search results: ${namingEnum.dump()}")
        List<SearchResult> results = Collections.list(namingEnum)
        logger.info("Result count: ${results.size()}")

        results.eachWithIndex { it, i -> logger.info("Result ${i}: ${it}") }

        results
    }

    public Attributes get(final String dn) {
        Attributes result = ctx.getAttributes(searchQuery);
        logger.info("Retrieved from LDAP: ${result}")
        result
    }

    public void close() {
        tls?.close()

        // Something here will work but be in plaintext

        ctx?.close()
    }

    private void preparePaths() {
        truststorePath = preparePath(truststorePath)
        keystorePath = preparePath(keystorePath)
    }

    private static String preparePath(final String rawPath) {
        String cleanedPath = rawPath.replaceFirst(/^~/, System.getProperty("user.home"))
        cleanedPath
    }
}
