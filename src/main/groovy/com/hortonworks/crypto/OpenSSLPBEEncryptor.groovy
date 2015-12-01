package com.hortonworks.crypto

import org.apache.commons.codec.binary.Hex
import org.apache.log4j.Logger
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.jce.provider.BouncyCastleProvider

import java.security.Security

/**
 * Created by alopresto on 11/24/15.
 */
class OpenSSLPBEEncryptor {
    private static final Logger logger = Logger.getLogger(OpenSSLPBEEncryptor.class)

    private static final String HEADER = "Salted__"
    private static final int HEADER_LEN = HEADER.length()
    private static final int SALT_LEN = 8
    private static final int HEADER_AND_SALT_BASE_64_LEN = 4 * Math.ceil((HEADER_LEN + SALT_LEN) / 3.0)

    // The header symbol will not contain padding because it is not the end of the string, and the last character may be different in the actual encoded string
    private static
    final String HEADER_BASE_64 = Base64.encoder.encodeToString(HEADER.getBytes("US-ASCII")).replaceAll("=", "")[0..<-1]

    static {
        Security.addProvider(new BouncyCastleProvider())
    }

    ParametersWithIV parametersWithIV

    static final int KEY_LENGTH_BITS = 256
    static final int IV_LENGTH_BITS = 128

    OpenSSLPBEEncryptor(String password, String salt = "") {
        parametersWithIV = deriveKeyFromPassword(password, salt) as ParametersWithIV
    }

    /**
     * Returns a String containing the cipher text Base64 encoded.
     *
     * @param plaintext a String containing the plaintext (Base64 encoded)
     * @return the Base64 encoded cipher text
     */
    String encrypt(String plaintext) {
        byte[] plainBytes = Base64.decoder.decode(plaintext)
        byte[] cipherBytes = encrypt(plainBytes)
        return Base64.encoder.encodeToString(cipherBytes)
    }

    /**
     * Returns the cipher text.
     * @param plainBytes the plain bytes
     * @return the encrypted bytes
     */
    byte[] encrypt(byte[] plainBytes) {
        PaddedBufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new AESEngine()))

        try {
            bufferedBlockCipher.init(true, parametersWithIV)
            byte[] cipherBytes = processBytes(plainBytes, bufferedBlockCipher)
            return cipherBytes
        } catch (Exception e) {
            logger.fatal("Failed to encrypt message", e)
            throw e
        }
    }

    /**
     * Returns a String containing the Base64 encoded plaintext.
     *
     * @param plaintext a String containing the cipher text (Base64 encoded)
     * @return the Base64 encoded plaintext
     */
    String decrypt(String cipherText) {
        byte[] cipherBytes = Base64.decoder.decode(cipherText.trim())
        byte[] plainBytes = decrypt(cipherBytes)
        return Base64.encoder.encodeToString(plainBytes)
    }

    byte[] decrypt(byte[] cipherBytes) {
        PaddedBufferedBlockCipher bufferedBlockCipher = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new AESEngine()))

        try {
            bufferedBlockCipher.init(false, parametersWithIV)
            byte[] plainBytes = processBytes(cipherBytes, bufferedBlockCipher)
            return plainBytes
        } catch (Exception e) {
            logger.fatal("Failed to decrypt message", e)
            throw e
        }
    }

    /**
     * Returns the processed byte[] from the cipher (encrypting/decrypting depending on the cipher mode).
     *
     * @param inputBytes the source byte[]
     * @param bufferedBlockCipher the initialized cipher
     * @return the processed byte[]
     */
    private static byte[] processBytes(byte[] inputBytes, PaddedBufferedBlockCipher bufferedBlockCipher) {
/** Copied */
        int inputOffset = 0;
        int inputLength = inputBytes.length;

        int maximumOutputLength = bufferedBlockCipher.getOutputSize(inputLength);
        byte[] outputBytes = new byte[maximumOutputLength];
        int outputOffset = 0;
        int outputLength = 0;

        int bytesProcessed;

        bytesProcessed = bufferedBlockCipher.processBytes(
                inputBytes, inputOffset, inputLength,
                outputBytes, outputOffset
        );
        outputOffset += bytesProcessed;
        outputLength += bytesProcessed;

        bytesProcessed = bufferedBlockCipher.doFinal(outputBytes, outputOffset);
        outputLength += bytesProcessed;

        if (outputLength == outputBytes.length) {
            return outputBytes;
        } else {
            byte[] truncatedOutput = new byte[outputLength];
            System.arraycopy(
                    outputBytes, 0,
                    truncatedOutput, 0,
                    outputLength
            );
            return truncatedOutput;
        }
/** End copied */
    }

    static CipherParameters deriveKeyFromPassword(final String password, final String salt = "") {
        OpenSSLPBEParametersGenerator gen = new OpenSSLPBEParametersGenerator();
        // The salt is not safe to pass around in regular string format, so it is hex encoded
        byte[] saltBytes = Hex.decodeHex(salt.toCharArray())
        gen.init(password.bytes, saltBytes);
        CipherParameters cp = gen.generateDerivedParameters(KEY_LENGTH_BITS, IV_LENGTH_BITS);
        return cp;
    }

    static String extractHexSaltFromBase64Header(final String headerBase64) {
        // If the header is null, empty, or too short to contain the salt, return an empty string
        if (!headerBase64 || headerBase64.length() < HEADER_AND_SALT_BASE_64_LEN) {
            return ""
        }
        return Hex.encodeHexString(extractSaltFromBase64Header(headerBase64))
    }

    static String extractHexSaltFromHeader(byte[] headerBytes) {
        // If the header is null, empty, or too short to contain the salt, return an empty string
        if (!headerBytes || headerBytes.length < HEADER_LEN + SALT_LEN) {
            return ""
        }
        return Hex.encodeHexString(extractSaltFromRawHeader(headerBytes))
    }

    static String extractHexSaltFromHexHeader(final String hexHeader) {
        // If the header is null, empty, or too short to contain the salt, return an empty string
        if (!hexHeader || hexHeader.length() < (HEADER_LEN + SALT_LEN) * 2) {
            return ""
        }
        return Hex.encodeHexString(extractSaltFromRawHeader(Hex.decodeHex(hexHeader.toCharArray())))
    }

    private static byte[] extractSaltFromBase64Header(final String header) {
        if (!header.startsWith(HEADER_BASE_64)) {
            return new byte[0]
        }
        // The contents contain the header and salt (Base64 encoded)
        String headerAndSaltBase64 = header[0..<HEADER_AND_SALT_BASE_64_LEN]
        byte[] headerAndSaltBytes = Base64.decoder.decode(headerAndSaltBase64)
        // The Base64 encoding includes two characters of the cipher text
        headerAndSaltBytes[HEADER_LEN..<-2]
    }

    private static byte[] extractSaltFromRawHeader(final byte[] header) {
        if (header[0..<HEADER_LEN] != (HEADER.getBytes("US-ASCII"))) {
            return new byte[0]
        }
        // The contents contain the header and salt
        header[HEADER_LEN..<HEADER_LEN + SALT_LEN]
    }

    /**
     * Extracts the cipher text from the encrypted body as a Base64 encoded string.
     *
     * @param body the full contents of the OpenSSL encrypted data, Base64 encoded
     * @return the cipher text, Base64 encoded
     */
    static String extractCipherTextFromBody(final String body) {
        // If the body is null or empty, return an empty string
        if (!body) {
            return ""
        }

        if (body.startsWith(HEADER_BASE_64)) {
            // Decode to bytes, extract, re-encode
            byte[] bytes = Base64.decoder.decode(body.trim())
            bytes = bytes[HEADER_LEN + SALT_LEN..-1]
            Base64.encoder.encodeToString(bytes)
        } else {
            return body
        }
    }

    /**
     * Extracts the cipher text from the encrypted body as a raw byte[].
     *
     * @param body the full contents of the OpenSSL encrypted data, raw bytes
     * @return the cipher text, raw bytes
     */
    static byte[] extractCipherTextFromBody(final byte[] body) {
        // If the body is null or empty, return an empty array
        if (!body) {
            return new byte[0]
        }

        if (body[0..<HEADER_LEN] as byte[] == HEADER.bytes) {
            return body[HEADER_LEN + SALT_LEN..-1]
        } else {
            return body
        }
    }
}
