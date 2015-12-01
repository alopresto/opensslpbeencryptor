package com.hortonworks.ldap

import com.beust.jcommander.JCommander
import org.apache.log4j.Logger
import org.junit.After
import org.junit.Before
import org.junit.Ignore
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

import javax.naming.AuthenticationException
import javax.naming.directory.Attributes
import javax.naming.directory.SearchResult

/**
 * Created by alopresto on 11/20/15.
 */
@RunWith(JUnit4.class)
public class StartTLSConnectorTest extends GroovyTestCase {

    private static final Logger logger = Logger.getLogger(StartTLSConnectorTest.class)

    @Before
    public void setUp() throws Exception {
        System.getProperty(JCommander.DEBUG_PROPERTY, "true")
    }

    @After
    public void tearDown() throws Exception {
        System.clearProperty(JCommander.DEBUG_PROPERTY)
    }

    @Test
    public void testMainShouldConnectToLDAPWithStartTLS() throws Exception {
        // Arrange
        String args = "--truststore ~/Workspace/certificates/truststore.jks --keystore ~/Workspace/certificates/alopresto.jks --connect localhost:10389"

        // Act
        StartTLSConnector.main(args.split())

        // Assert

        // Didn't throw an exception
        assert true
    }

    @Ignore("Not supported with ApacheDS")
    @Test
    public void testMainShouldNotConnectWithoutKeystore() throws Exception {
        // Arrange
        String args = "--truststore ~/Workspace/certificates/truststore.jks --keystore \"\" --connect localhost:10389"

        // Act
        def message = shouldFail(AuthenticationException) {
            StartTLSConnector.main(args.split())
        }

        // Assert
        assert message =~ "LDAP: error code"
    }

    @Test
    public void testMainShouldNotConnectWithBadPrincipal() throws Exception {
        // Arrange
        String args = "--truststore ~/Workspace/certificates/truststore.jks --keystore ~/Workspace/certificates/alopresto.jks --connect localhost:10389 --principal uid=unknown,ou=system"

        // Act
        def message = shouldFail(AuthenticationException) {
            StartTLSConnector.main(args.split())
        }

        // Assert
        assert message =~ "\\[LDAP: error code 49 - INVALID_CREDENTIALS: Bind failed: Attempt to lookup non-existant entry:"
    }

    @Test
    public void testShouldOverrideHost() throws Exception {
        // Arrange
        String host = "127.0.0.1"

        String args = "--host ${host}"

        StartTLSConnector stc = new StartTLSConnector()
        new JCommander(stc, args.split())

        def result

        // Act
        try {
            stc.connect()
        } catch (Exception e) {
            logger.error("Failed to connect: ", e)
            fail(e.message)
        } finally {
            stc.close()
        }

        // Assert
    }

    @Test
    public void testSearchShouldRetrieveUser() throws Exception {
        // Arrange
        String searchQuery = "hhornblo"

        String args = "--search ${searchQuery}"

        StartTLSConnector stc = new StartTLSConnector()
        new JCommander(stc, args.split())

        logger.info("Will run search for ${searchQuery}")

        def results

        // Act
        try {
            stc.connect()
            results = stc.search(searchQuery)
        } catch (Exception e) {
            logger.error("Failed to search: ", e)
            fail(e.message)
        } finally {
            stc.close()
        }

        // Assert
        assert results
        assert results instanceof List<SearchResult>
        assert results.size() == 1
        assert (results.first().attributes as Attributes).get("cn") as String == "cn: Horatio Hornblower"
    }

    @Test
    public void testGetShouldRetrieveUserWithSpace() throws Exception {
        // Arrange
        String searchQuery = "\"cn=Horatio Hornblower,ou=people,o=SevenSeas\""

        String args = "--search ${searchQuery}"

        StartTLSConnector stc = new StartTLSConnector()
        new JCommander(stc, args.split(" ", 2))

        def result

        // Act
        try {
            stc.connect()
            result = stc.get(searchQuery)
        } catch (Exception e) {
            logger.error("Failed to search: ", e)
            fail(e.message)
        } finally {
            stc.close()
        }

        // Assert
        assert result
        assert result instanceof Attributes
        assert result.get("cn") as String == "cn: Horatio Hornblower"
    }

    @Test
    public void testShouldLoadClientKeystore() throws Exception {
        // Arrange
        String filepath = "${System.getProperty("user.home")}/Workspace/certificates/alopresto.jks"
        File clientKeystore = new File(filepath)

        // Act
        String content = Base64.encoder.encodeToString(clientKeystore.bytes)

        logger.info("Read from file: ${filepath} (base 64 encoded)\n${content}")

        // Assert
        assert content
    }

    @Test
    public void testShouldCleanPath() throws Exception {
        // Arrange
        final String TRAILING_PATH = "/Workspace/certificates/alopresto.jks"
        final String EXPECTED_CLEANED_PATH = "${System.getProperty("user.home")}${TRAILING_PATH}"

        String filepath = "~${TRAILING_PATH}"
        logger.info("Original path: ${filepath}")

        // Act
        String cleanedPath = StartTLSConnector.preparePath(filepath)

        logger.info("Cleaned path: ${cleanedPath}")

        // Assert
        assert cleanedPath == EXPECTED_CLEANED_PATH
    }
}