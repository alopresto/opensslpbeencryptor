package com.hortonworks.crypto

import org.apache.commons.codec.CharEncoding
import org.apache.commons.codec.binary.Hex
import org.apache.log4j.Logger
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.After
import org.junit.Before
import org.junit.Test

/**
 * Created by alopresto on 11/25/15.
 */
public class OpenSSLPBEEncryptorTest {
    private static final Logger logger = Logger.getLogger(OpenSSLPBEEncryptorTest.class)

    private static String plaintext

    static final String PASSWORD = "thisIsABadPassword"

    private static final String KEY = ("This is a bad key" * 3)[0..<32]
    private static final String IV = ("This is a bad IV" * 3)[0..<16]
    private static String keyHex
    private static String ivHex

    private static final int HEADER_LEN = OpenSSLPBEEncryptor.HEADER_LEN
    private static final int SALT_LEN = OpenSSLPBEEncryptor.SALT_LEN
    private static final int HEADER_AND_SALT_BASE_64_LEN = OpenSSLPBEEncryptor.HEADER_AND_SALT_BASE_64_LEN

    private static final Base64.Encoder encoder = Base64.encoder
    private static final Base64.Decoder decoder = Base64.decoder

    @Before
    void setUp() {
        plaintext = "This is a plaintext message."
        keyHex = Hex.encodeHexString(KEY.bytes)
        ivHex = Hex.encodeHexString(IV.bytes)
    }

    @After
    void tearDown() {

    }

    /**
     * Returns a formatted String representing the raw byte values of the hex string.
     *
     * Example:
     *
     * abcd -> "  61  62  63  64"
     *
     * @param hex a hex-encoded string
     * @return the byte values in a padded string
     */
    static String h2b(final String hex) {
        byte[] bytes = Hex.decodeHex(hex?.toCharArray())
        fb(bytes)
    }

    /**
     * Returns a String containing the ASCII representation of the hex String.
     *
     * @param hex a hex-encoded string
     * @return the ASCII string
     */
    static String h2a(final String hex) {
        Hex asciiHexDecoder = new Hex(CharEncoding.US_ASCII)
        byte[] bytes = asciiHexDecoder.decodeHex(hex?.toCharArray())
        new String(bytes, CharEncoding.US_ASCII)
    }

    /**
     * Returns a String containing the byte values as integers and padded for columnization.
     *
     * Example:
     *
     * [61, 62, 63, -57] -> "  61  62  63 -57"
     * @param bytes the byte array
     * @param padding columns to occupy (defaults to 4)
     * @return the formatted String
     */
    static String fb(final byte[] bytes, int padding = 4) {
        bytes.collect { (it as String).padLeft(padding, " ") }.join(" ")
    }

    /**
     * Returns a String containing the characters with a space inserted every <size> characters and the elements padded to <padding> columns.
     *
     * @param input the input String (ASCII/UTF/hex encoding)
     * @param size number of characters to combine in a single element
     * @param padding number of columns each element should occupy
     * @return the formatted String
     */
    static String s(final String input, int size = 2, int padding = 4) {
        input.toList().collate(size).collect { it.join().padLeft(padding, " ") }.join(" ")
    }

    @Test
    void testShouldEncryptAndDecryptWithSalt() {
        // Arrange
        final String SALT_HEX = Hex.encodeHexString("saltsalt".bytes)

        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD, SALT_HEX)
        logger.info("Using password: ${PASSWORD}")
        logger.info("Salt (hex): ${SALT_HEX}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")
        logger.info("Plaintext: ${plaintext}")

        // Act
        String cipherText = encryptor.encrypt(encoder.encodeToString(plaintext.bytes))
        logger.info("Cipher text: ${cipherText}")
        String cipherTextHex = Hex.encodeHexString(decoder.decode(cipherText))
        logger.info("Cipher text (hex): ${cipherTextHex} | ${cipherTextHex.size() / 2} bytes")

        String recoveredBase64 = encryptor.decrypt(cipherText)
        logger.info("Recovered  : ${recoveredBase64}")

        String recovered = new String(decoder.decode(recoveredBase64))
        logger.info("Decoded    : ${recovered}")

        // Assert
        assert plaintext != cipherText
        assert plaintext == recovered
    }

    @Test
    void testShouldEncryptAndDecryptWithoutSalt() {
        // Arrange
        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD)
        logger.info("Using password: ${PASSWORD}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")
        logger.info("Plaintext: ${plaintext}")

        // Act
        String cipherText = encryptor.encrypt(encoder.encodeToString(plaintext.bytes))
        logger.info("Cipher text: ${cipherText}")
        String cipherTextHex = Hex.encodeHexString(decoder.decode(cipherText))
        logger.info("Cipher text (hex): ${cipherTextHex} | ${cipherTextHex.size() / 2} bytes")

        String recoveredBase64 = encryptor.decrypt(cipherText)
        logger.info("Recovered  : ${recoveredBase64}")

        String recovered = new String(decoder.decode(recoveredBase64))
        logger.info("Decoded    : ${recovered}")

        // Assert
        assert plaintext != cipherText
        assert plaintext == recovered
    }

    @Test
    public void testShouldDecryptFromOpenSSLRawWithSalt() throws Exception {
        // Arrange
        File file = new File("src/test/resources/salted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromHeader(encryptedBytes)
        logger.info("Extracted salt hex:   ${saltHex.padLeft(saltHex.length() * 2)}")

        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD, saltHex)
        logger.info("Using password: ${PASSWORD} and salt: ${saltHex}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        byte[] cipherBytes = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedBytes)
        logger.info("Cipher text: ${Hex.encodeHexString(cipherBytes)} ${cipherBytes.length * 2}")

        // Act
        byte[] recoveredBytes = encryptor.decrypt(cipherBytes)
        String recovered = new String(recoveredBytes)
        logger.info("Recovered: ${recovered} | ${Hex.encodeHexString(recoveredBytes)}")

        // Assert
        assert plaintext == recovered
    }

    @Test
    public void testShouldDecryptFromOpenSSLRawWithoutSalt() throws Exception {
        // Arrange
        File file = new File("src/test/resources/unsalted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromHeader(encryptedBytes)
        logger.info("Extracted salt hex: ${saltHex}")

        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD, saltHex)
        logger.info("Using password: ${PASSWORD} and salt: ${saltHex}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        byte[] cipherBytes = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedBytes)
        logger.info("Cipher text: ${Hex.encodeHexString(cipherBytes)} ${cipherBytes.length * 2}")

        // Act
        byte[] recoveredBytes = encryptor.decrypt(cipherBytes)
        logger.info("Recovered  : ${Hex.encodeHexString(recoveredBytes)}")

        String recovered = new String(recoveredBytes)
        logger.info("Decoded    : ${recovered}")

        // Assert
        assert plaintext != cipherBytes
        assert plaintext == recovered
    }

    @Test
    public void testShouldDecryptFromOpenSSLBase64WithoutSalt() throws Exception {
        // Arrange
        File file = new File("src/test/resources/unsalted.enc")
        String encryptedContentBase64 = file.text
        logger.info("Read encrypted text: ${encryptedContentBase64}")

        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContentBase64)
        logger.info("Extracted salt hex: ${saltHex}")

        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD, saltHex)
        logger.info("Using password: ${PASSWORD} and salt: ${saltHex}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContentBase64)
        logger.info("Cipher text: ${cipherText}")

        // Act
        String recoveredBase64 = encryptor.decrypt(cipherText)
        logger.info("Recovered  : ${recoveredBase64}")

        String recovered = new String(decoder.decode(recoveredBase64))
        logger.info("Decoded    : ${recovered}")

        // Assert
        assert plaintext != encryptedContentBase64
        assert plaintext == recovered
    }

    @Test
    public void testShouldDecryptFromOpenSSLBase64WithSalt() throws Exception {
        // Arrange
        File file = new File("src/test/resources/salted.enc")
        String encryptedContentBase64 = file.text
        logger.info("Read encrypted text: ${encryptedContentBase64}")

        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContentBase64)
        logger.info("Extracted salt hex: ${saltHex}")

        OpenSSLPBEEncryptor encryptor = new OpenSSLPBEEncryptor(PASSWORD, saltHex)
        logger.info("Using password: ${PASSWORD} and salt: ${saltHex}")

        byte[] ivBytes = encryptor.parametersWithIV.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContentBase64)
        logger.info("Cipher text: ${cipherText}")

        // Act
        String recoveredBase64 = encryptor.decrypt(cipherText)
        logger.info("Recovered  : ${recoveredBase64}")

        String recovered = new String(decoder.decode(recoveredBase64))
        logger.info("Decoded    : ${recovered}")

        // Assert
        assert plaintext != encryptedContentBase64
        assert plaintext == recovered
    }

    @Test
    public void testShouldExtractSaltFromRawHeader() throws Exception {
        // Arrange
        File file = new File("src/test/resources/salted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        /* The contents contain the header and salt (ASCII encoded) concatenated with the body (raw) */
        byte[] headerAndSaltBytes = encryptedBytes[0..<HEADER_LEN + SALT_LEN] as byte[]
        logger.info("Header and salt: ${fb(headerAndSaltBytes)}")

        final String EXPECTED_SALT_HEX = Hex.encodeHexString(headerAndSaltBytes[HEADER_LEN..-1] as byte[])
        logger.info(" Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromHeader(encryptedBytes)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldExtractSaltFromBase64Header() throws Exception {
        // Arrange
        String encryptedContentsBase64 = new File("src/test/resources/salted.enc").text
        logger.info("Read encrypted content: ${encryptedContentsBase64}")

        /* The contents contain the header and salt (Base64 encoded) concatenated with the body (Base64 encoded) */
        String headerAndSaltBase64 = encryptedContentsBase64[0..<HEADER_AND_SALT_BASE_64_LEN]
        byte[] headerAndSaltBytes = decoder.decode(headerAndSaltBase64)
        // The Base64 encoding includes two non-"=" padding characters
        headerAndSaltBytes = headerAndSaltBytes[0..-2]
        logger.info("Header and salt: ${fb(headerAndSaltBytes)}")

        final String EXPECTED_SALT_HEX = Hex.encodeHexString(headerAndSaltBytes[HEADER_LEN..<-1] as byte[])
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContentsBase64)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromMissingBase64Header() throws Exception {
        // Arrange
        String encryptedContentsBase64 = new File("src/test/resources/unsalted.enc").text
        logger.info("Read encrypted content: ${encryptedContentsBase64}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContentsBase64)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromMissingRawHeader() throws Exception {
        // Arrange
        File file = new File("src/test/resources/unsalted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromHeader(encryptedBytes)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromNullHeader() throws Exception {
        // Arrange
        String encryptedContents = null
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContents)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromEmptyHeader() throws Exception {
        // Arrange
        String encryptedContents = ""
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContents)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromTooShortBase64Header() throws Exception {
        // Arrange
        String encryptedContents = "Short"
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContents)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldNotExtractSaltFromTooShortRawHeader() throws Exception {
        // Arrange
        String encryptedContents = "Short"
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_SALT_HEX = ""
        logger.info("Expected salt hex: ${EXPECTED_SALT_HEX}")

        // Act
        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromHeader(encryptedContents.bytes)
        logger.info("Extracted salt hex: ${saltHex}")

        // Assert
        assert saltHex == EXPECTED_SALT_HEX
    }

    @Test
    public void testShouldExtractCipherTextFromBase64Body() throws Exception {
        // Arrange
        String encryptedContents = new File("src/test/resources/salted.enc").text
        logger.info("Read encrypted content: ${encryptedContents}")

        // The encrypted contents are Base64(header + salt + cipherText) and the salt/cipher text boundary is inside a group, so extracting the cipher text is not just a slice operation
        byte[] encryptedBytes = decoder.decode(encryptedContents.trim())[HEADER_LEN + SALT_LEN..-1]
        final String EXPECTED_CIPHER_TEXT = encoder.encodeToString(encryptedBytes)
        logger.info(" Expected cipher text: ${EXPECTED_CIPHER_TEXT}")

        // Act
        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContents)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldExtractCipherTextFromRawBody() throws Exception {
        // Arrange
        File file = new File("src/test/resources/salted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        final String EXPECTED_CIPHER_TEXT = Hex.encodeHexString(encryptedBytes[HEADER_LEN + SALT_LEN..-1] as byte[])
        logger.info("Expected cipher text: ${EXPECTED_CIPHER_TEXT.padLeft(encryptedBytes.length * 2)}")

        // Act
        byte[] cipherBytes = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedBytes)
        String cipherText = Hex.encodeHexString(cipherBytes)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldExtractCipherTextFromUnsaltedBase64Body() throws Exception {
        // Arrange
        String encryptedContentsBase64 = new File("src/test/resources/unsalted.enc").text
        logger.info("Read encrypted content: ${encryptedContentsBase64}")

        final String EXPECTED_CIPHER_TEXT = encryptedContentsBase64
        logger.info("Expected cipher text: ${EXPECTED_CIPHER_TEXT}")

        // Act
        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContentsBase64)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldExtractCipherTextFromUnsaltedRawBody() throws Exception {
        File file = new File("src/test/resources/unsalted_raw.enc")
        byte[] encryptedBytes = file.bytes
        logger.info("Read encrypted bytes: ${Hex.encodeHexString(encryptedBytes)}")

        final String EXPECTED_CIPHER_TEXT = Hex.encodeHexString(encryptedBytes)
        logger.info("Expected cipher text: ${EXPECTED_CIPHER_TEXT.padLeft(encryptedBytes.length * 2)}")

        // Act
        byte[] cipherBytes = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedBytes)
        String cipherText = Hex.encodeHexString(cipherBytes)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldNotExtractCipherTextFromNullBody() throws Exception {
        // Arrange
        String encryptedContents = null
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_CIPHER_TEXT = ""
        logger.info("Expected cipher text: ${EXPECTED_CIPHER_TEXT}")

        // Act
        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContents as String)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldNotExtractCipherTextFromEmptyBody() throws Exception {
        // Arrange
        String encryptedContents = ""
        logger.info("Read encrypted content: ${encryptedContents}")

        final String EXPECTED_CIPHER_TEXT = ""
        logger.info("Expected cipher text: ${EXPECTED_CIPHER_TEXT}")

        // Act
        String cipherText = OpenSSLPBEEncryptor.extractCipherTextFromBody(encryptedContents)
        logger.info("Extracted cipher text: ${cipherText}")

        // Assert
        assert cipherText == EXPECTED_CIPHER_TEXT
    }

    @Test
    public void testShouldDeriveKeyFromPasswordWithBase64EncodedSalt() throws Exception {
        // Arrange
        logger.info("Using password: ${PASSWORD}")

        final String EXPECTED_SALT_HEX = "07D44FC1CB631369"
        final String RAW_SALT_ASCII = new String(Hex.decodeHex(EXPECTED_SALT_HEX.toCharArray()), "ASCII")
        logger.info("Using salt: ${EXPECTED_SALT_HEX.toLowerCase()} | ${RAW_SALT_ASCII}")
        logger.info("Salt bytes: ${h2b(EXPECTED_SALT_HEX)}")

        final String EXPECTED_KEY_HEX = "3614FE0535490EAF07BAA28D1CA2D5682BAEAA0293482F5B19627ECA0A9FA6F4"
        logger.info("Expected key: ${EXPECTED_KEY_HEX.toLowerCase()}")
        final String EXPECTED_IV_HEX = "4D9FCB0F18DEFEB8D96AFF13CF9C2DF3"
        logger.info("Expected IV: ${EXPECTED_IV_HEX.toLowerCase()}")

        String encryptedContentsBase64 = new File("src/test/resources/salted.enc").text
        logger.info("Read encrypted content: ${encryptedContentsBase64}")

        String saltHex = OpenSSLPBEEncryptor.extractHexSaltFromBase64Header(encryptedContentsBase64)
        logger.info("Read salt hex: ${saltHex}")

        // Act
        ParametersWithIV cp = OpenSSLPBEEncryptor.deriveKeyFromPassword(PASSWORD, saltHex) as ParametersWithIV

        byte[] keyBytes = (cp.parameters as KeyParameter).key
        logger.info("Derived key: ${Hex.encodeHexString(keyBytes)} | ${encoder.encodeToString(keyBytes)}")

        byte[] ivBytes = cp.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        // Assert
        assert Arrays.equals(keyBytes, Hex.decodeHex(EXPECTED_KEY_HEX.toCharArray()))
        assert Arrays.equals(ivBytes, Hex.decodeHex(EXPECTED_IV_HEX.toCharArray()))
    }

    @Test
    public void testShouldDeriveKeyFromPasswordWithRawSalt() throws Exception {
        // Arrange
        logger.info("Using password: ${PASSWORD}")

        Hex asciiDecoder = new Hex(CharEncoding.US_ASCII)
        Hex defaultDecoder = new Hex()

        final String EXPECTED_SALT_HEX = "4D41C78350EE0CE8"

        // It does not matter what hex decoder encoding we use to translate the hex salt to bytes
        byte[] asciiDecodedBytes = asciiDecoder.decode(EXPECTED_SALT_HEX) as byte[]
        logger.info("  ASCII decoded salt: ${fb(asciiDecodedBytes)}")

        def defaultDecodedBytes = defaultDecoder.decode(EXPECTED_SALT_HEX) as byte[]
        logger.info("Default decoded salt: ${fb(defaultDecodedBytes)}")

        assert Arrays.equals(asciiDecodedBytes, defaultDecodedBytes)

        final String RAW_SALT_ASCII = h2a(EXPECTED_SALT_HEX)
        logger.info("Using salt: ${s(EXPECTED_SALT_HEX.toLowerCase())} | ${RAW_SALT_ASCII}")
        logger.info("Salt bytes: ${h2b(EXPECTED_SALT_HEX)}")
        logger.info("Salt ASCII: ${fb(RAW_SALT_ASCII.getBytes("US-ASCII"))}")

        final String EXPECTED_KEY_HEX = "9C876867E3E914DE8E6249D1C5B4EC21DBCEB8A3F1A09579C8C5AE08B73DCB2E"
        logger.info("Expected key: ${EXPECTED_KEY_HEX.toLowerCase()}")
        final String EXPECTED_IV_HEX = "C3A9B16EA80F76CEDA1DB445A62F1BC2"
        logger.info("Expected IV: ${EXPECTED_IV_HEX.toLowerCase()}")

        // Act
        ParametersWithIV cp = OpenSSLPBEEncryptor.deriveKeyFromPassword(PASSWORD, EXPECTED_SALT_HEX) as ParametersWithIV

        byte[] keyBytes = (cp.parameters as KeyParameter).key
        logger.info("Derived key: ${Hex.encodeHexString(keyBytes)} | ${encoder.encodeToString(keyBytes)}")

        byte[] ivBytes = cp.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        // Assert
        assert Arrays.equals(keyBytes, Hex.decodeHex(EXPECTED_KEY_HEX.toCharArray()))
        assert Arrays.equals(ivBytes, Hex.decodeHex(EXPECTED_IV_HEX.toCharArray()))
    }

    @Test
    public void testShouldDeriveKeyFromPasswordWithoutSalt() throws Exception {
        // Arrange
        logger.info("Using password: ${PASSWORD}")

        final String EXPECTED_KEY_HEX = "711E85689CE7AFF6F410AEA43ABC5446842F685B84879B2E00F977C22B9E9A7D"
        logger.info("Expected key: ${EXPECTED_KEY_HEX.toLowerCase()}")
        final String EXPECTED_IV_HEX = "0C90ABF8ECE84B92BAA2CD448EC760F0"
        logger.info("Expected IV: ${EXPECTED_IV_HEX.toLowerCase()}")

        // Act
        ParametersWithIV cp = OpenSSLPBEEncryptor.deriveKeyFromPassword(PASSWORD) as ParametersWithIV

        byte[] keyBytes = (cp.parameters as KeyParameter).key
        logger.info("Derived key: ${Hex.encodeHexString(keyBytes)} | ${encoder.encodeToString(keyBytes)}")

        byte[] ivBytes = cp.IV
        logger.info("Derived IV: ${Hex.encodeHexString(ivBytes)} | ${encoder.encodeToString(ivBytes)}")

        // Assert
        assert Arrays.equals(keyBytes, Hex.decodeHex(EXPECTED_KEY_HEX.toCharArray()))
        assert Arrays.equals(ivBytes, Hex.decodeHex(EXPECTED_IV_HEX.toCharArray()))
    }
}