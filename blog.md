# Decrypting OpenSSL Data in Apache NiFi

## Who Am I?

My name is Andy LoPresto and I am a software engineer on the HDF team at Hortonworks. I previously worked in information security (encryption in financial systems & device drivers, PKI, etc.) at Apple and was a security architect at TigerText. 

## The Issue

A question I've been asked many times over my career thus far is, "When should we encrypt something?" Now, the most correct first answer to any information security question is, "It depends," but people get tired of hearing that very quickly. So my default response to this question is, "Whenever you don't have a good reason not to."

Using encryption in high-level languages is usually straightforward in theory at this point, thanks to many helpful libraries such as [BouncyCastle](http://bouncycastle.org/), but can be more difficult in practice. Implementation details matter. Unless you have a Ph.D. in cryptography or discrete mathematics and an extensive background in software engineering (in which case you're not likely to be reading this blog), you should be relying on well-accepted standards and robust best practices, not implementing your own "custom" encryption algorithms. 

Recently we received a customer query on how to use the Encryption Processors to decrypt data in [Apache NiFi](https://nifi.apache.org). This should be straightforward, and the fact that it wasn't got me involved. 

If you're familiar with encryption concepts, you can [skip ahead](#putting-it-in-nifi) to the solution. For everyone else, I'm going to provide a more in-depth explanation to hopefully make this more accessbile. 

## Symmetric Encryption Overview

Our customer was using the EncryptContent processor in NiFi to try and decrypt some data that was encrypted in an external application. We determined that the data was encrypted with [OpenSSL](https://www.openssl.org/docs/) using AES-256-CBC. The full explanation on encryption algorithms could fill many books (and has), but there are a few important takeaways relevant to debugging this situation:

1. The encryption is symmetric, which means both endpoints must have access to the same key. 
1. The key must be 256 bits. 
1. The mode of operation is Cipher Block Chaining (CBC), which means an initialization vector (IV) must be used and identical on both sides. Wikipedia has an [excellent article](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) with diagrams explaining CBC. See footnotes on this piece for further thoughts on modes of operation. 

## Key Derivation Functions and Password Based Encryption

NiFi has an out-of-the-box capability to encrypt and decrypt data using AES-256-CBC, and the customer verified that data encrypted in NiFi could be decrypted successfully in NiFi. However, the externally-encrypted data was failing. This is when I got involved. 

I started by looking at the existing NiFi code for encryption. The [`EncryptContent processor`](https://github.com/apache/nifi/blob/f83e6d33c592e3a061b0bf6c41884c42f4971379/nifi-nar-bundles/nifi-standard-bundle/nifi-standard-processors/src/main/java/org/apache/nifi/processors/standard/EncryptContent.java) allows the user to select an algorithm and provide attributes to activate the encryption/decryption. Due to previous design decisions, the symmetric encryption capacity is limited to password-based encryption (PBE) provided by the [`PasswordBasedEncryptor`](https://github.com/apache/nifi/blob/f83e6d33c592e3a061b0bf6c41884c42f4971379/nifi-nar-bundles/nifi-standard-bundle/nifi-standard-processors/src/main/java/org/apache/nifi/processors/standard/util/PasswordBasedEncryptor.java) implementation of the `Encryptor` interface. This makes some sense -- remember above that the key must be 256 bits, usually represented as 32 hexadecimal characters. Unless you spend 12 hours a day typing test keys into a command-line (raises hand), your interaction with symmetric encryption probably relies on PBE. You remember a password and the algorithm makes use of a key derivation function (KDF) to translate the password into a suitable key. There are many different KDFs, but they are used to accomplish the same goal -- turning a secret value (like a password or master key) into a key valid for encryption. 

Note that many KDFs rely on a pseudo-random function like a keyed cryptographic hash function (e.g. [HMAC/SHA-256](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Examples_of_HMAC_.28MD5.2C_SHA1.2C_SHA256.29)) and can be used for non-encryption ends, such as storing (repeatedly) hashed passwords for identity verification in web applications. This is one of the core concepts in password hashing algorithms like [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2), [bcrypt](https://en.wikipedia.org/wiki/Bcrypt), and [scrypt](https://en.wikipedia.org/wiki/Scrypt). When using a KDF to protect a password or to derive keys from a password, the function should be intentionally slow in order to mitigate some risk from brute-force attacks. 

One more important fact when dealing with any kind of sensitive data hashing or key derivation -- the process must be deterministic (otherwise how would the other party get the same key from the same password?) and this cuts both ways. It is obviously necessary, but it also means that a malicious actor who figures out the password now has the key. People who want to break this encryption would then be well served to run all possible inputs through the (known) KDF and generate all possible outputs as mentioned above in a brute-force attack. Because `KDF(x)` will always yield `y`, attackers can precompute these values and retain them in lookup tables, making the attacks very fast. One mitigation strategy is to use a random element when generating the key and provide this random element alongside the cipher text for the other party to use as well. There is no need for the random element to be kept secret, as its purpose is only to greatly increase the cost of the attacker generating all possible outputs. We call this element a _salt_. If the salt is 8 ASCII characters, that is an additional _72 quadrillion_ (7.2057594e16) possibilities for each secret input value (ASCII values are 7-bit, or 128 combinations, raised to the 8th power). We say that a salt of this length has "56 bits of entropy" as there are 7*8 bits. Coincidentally, 8 bytes of ASCII is what OpenSSL uses as the salt. 

## NiFi PasswordBasedEncryptor

When I examined the PasswordBasedEncryptor, I could see that it accepted a `password` as a property from the processor and an `algorithm`. The `providerName` is a reference to the JCE provider that is loaded. In NiFi, this value is `BC`, referring to [BouncyCastle](http://www.bouncycastle.org), an excellent open source cryptography library for Java and C#.  

```java
public PasswordBasedEncryptor(final String algorithm, final String providerName, final char[] password) {
       super();
       try {
           // initialize cipher
           this.cipher = Cipher.getInstance(algorithm, providerName);
           int algorithmBlockSize = cipher.getBlockSize();
           this.saltSize = (algorithmBlockSize > 0) ? algorithmBlockSize : DEFAULT_SALT_SIZE;
           
           // initialize SecretKey from password
           PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
           SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, providerName);
           this.secretKey = factory.generateSecret(pbeKeySpec);
       } catch (Exception e) {
           throw new ProcessException(e);
       }
   }
   ...
``` 

Let's step through the code above, line by line. First, we get an instance of the specified cipher from the provider. NiFi's algorithm for PBE is an enum called `EncryptionMethod.MD5_256AES` (it actually supports 20 PBE algorithms by default). This resolves to `"PBEWITHMD5AND256BITAES-CBC-OPENSSL"`. This means "password based encryption using MD5 for key derivation and AES-256-CBC for encryption as OpenSSL does it". 

The cipher object contains information about how it operates, so we can get the block size (symmetric ciphers can operate as [stream ciphers](https://en.wikipedia.org/wiki/Stream_cipher) or [block ciphers](https://en.wikipedia.org/wiki/Block_cipher), and we already know this is CBC, so it is a block cipher). 

This legacy design decision is a little confusing, as it retrieves the block size and uses that as the salt size. While there is nothing wrong with using 16 bytes (the block size for AES) as a salt size, there is no interdependency between the two, as the salt is only used in the key derivation, not the encryption/decryption. 

The next line declares a `PBEKeySpec` instance containing the password. [`KeySpec`s](http://docs.oracle.com/javase/7/docs/api/java/security/spec/KeySpec.html) are "specifications", or containers, for sensitive values used in generating keys in Java cryptography. A `SecretKeyFactory` is exactly what it sounds like -- using the key specification, the factory generates the secret key. 

Sounds good, right?

Unfortunately using this directly will still not decrypt something encrypted by OpenSSL on the command-line. Let's look at how OpenSSL encrypts the data and then return to our code. 

## OpenSSL

A simple OpenSSL command to encrypt some data follows this form:

`$ openssl enc <cipher> -e -k <password> <<< "This is a plaintext message."`

For `<cipher>`, you can see a list of supported options by running `$ openssl enc list`. We are using `aes-256-cbc` here (many of the ciphers have a shortcut where running `$ openssl aes-256-cbc` is identical to `$ openssl enc -aes-256-cbc`). `-e` instructs the tool to encrypt the data, and `-k` specifies the password. We can use `-in` and `-out` for input and output files, and `-a` as an optional flag to Base64 encode the output. Let's hold off on Base64 encoding for a second to inspect the output. 

Running the above command gives us some output on the command line. 

```bash
0s @ 18:38:15 $ openssl aes-256-cbc -e -k thisIsABadPassword <<< "This is a plaintext message."
Salted__i����_;�x$c��Sl���)Yλ��mG\�
                                    [�
```

I've put the output into a file (`plain.enc`) and then viewed a hex dump of the file:

```bash
0s @ 18:46:01 $ openssl aes-256-cbc -e -k thisIsABadPassword -in plain.txt -out plain.enc
0s @ 18:46:50 $ xxd plain.enc
0000000: 5361 6c74 6564 5f5f 2b87 b62e 9aa4 2596  Salted__+.....%.
0000010: ed73 5694 0f8a 4b18 d322 5671 3d2a 763b  .sV...K.."Vq=*v;
0000020: ad52 3c47 2da6 6b1e f51e da45 7cf0 67d1  .R<G-.k....E|.g.
```

Interesting that the first 8 bytes are readable -- and they say "Salted__". This is the header OpenSSL uses to indicate that the file contains a salt. The next 8 bytes are that salt (`2b87 b62e 9aa4 2596` in hex). We can verify this by using a nifty option `-p` that prints the key, IV, and salt used during encryption (here I specified the same salt using `-S` for consistency, but you can run it without this option to verify that it is random each time). 

**WARNING** For completeness, I will mention that you can obviously provide a constant salt with `-S` or even omit a salt entirely with `-nosalt` but this is **very bad** and you should not do it. Omitting a salt greatly reduces the key space the attacker needs to compute and weakens the security of your data. The code at the end of this post does handle unsalted decryption for legacy/backward compatibility, but again, do **not** do this.  

```bash
0s @ 18:51:15 $ openssl aes-256-cbc -e -k thisIsABadPassword -in plain.txt -out plain2.enc -p -S 2b87b62e9aa42596
salt=2B87B62E9AA42596
key=ECCD5A07F52BBAFEB4049AE8DFE10F7CF3BD481A1BEF065D5B4A5CE1AACB3B80
iv =0AE33920D6C1329A4661757D0F411249
0s @ 18:51:21 $ xxd plain.enc
0000000: 5361 6c74 6564 5f5f 2b87 b62e 9aa4 2596  Salted__+.....%.
0000010: ed73 5694 0f8a 4b18 d322 5671 3d2a 763b  .sV...K.."Vq=*v;
0000020: ad52 3c47 2da6 6b1e f51e da45 7cf0 67d1  .R<G-.k....E|.g.
```

So now we have a salt, and we have a key and IV value we can check our code against. This is critical. We already noted above that OpenSSL uses an 8 byte salt, and in our code we are using 16 bytes, so file this away as a potential sticking point. 

If you have any experience with crypto, you are noticing that the IV value is not present in the file. This surprised me as well. IV values, similar to salts, are necessary for decryption but not considered sensitive data and are routinely sent alongside the cipher text to allow the recipient to decrypt it. Here I relied on helpful information from really smart cryptographer [Thomas Pornin](http://security.stackexchange.com/a/29139/16485). The IV is dependent on the salt, and thus is generated at the same time the key is derived from the password and salt. Wait, let's go back to our code. We didn't generate any IV...

## Return to NiFi PasswordBasedEncryptor

We are now realizing the NiFi implementation of PBE and OpenSSL's implementation are not the same. The good news is, this explains why the externally-encrypted data was failing. The bad news is, that doesn't solve our problem. From here, I'll discuss the NiFi internal process and how I was able to write an adapter that was compatible with OpenSSL. 

NiFi's `EncryptContent` processor first initializes the PasswordBasedEncryptor in the `onTrigger` method. After instantiating the encryptor, a `callback` variable is declared which references an inner class implementing `StreamCallback` for either encryption or decryption depending on the processor property. It is within this callback that the actual byte processing happens, so let's examine them (in `PasswordBasedEncryptor`). 

The `getDecryptionCallback()` method simply returns a new instance of the class with no configuration, so let's start with `getEncryptionCallback()`. 

```java
@Override
public StreamCallback getEncryptionCallback() throws ProcessException {
    try {
        byte[] salt = new byte[saltSize];
        SecureRandom secureRandom = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
        secureRandom.setSeed(System.currentTimeMillis());
        secureRandom.nextBytes(salt);
        return new EncryptCallback(salt);
    } catch (Exception e) {
        throw new ProcessException(e);
    }
}
```

Here we can see that a new `byte[]` is initialized with the size of the salt determined during the constructor. A new `SecureRandom` instance (using `SHA1PRNG` as the random algorithm) is instantiated, seeded with the current time, and then read into the salt. 

### Side Note on Seeding Random

Using `java.security.SecureRandom` instead of `java.math.Random` is definitely the right choice here, but there are a couple issues with the current code. Both of the issues I point out below I learned about from two posts by Amit Sethi of Cigital. 

~~First, while it is good that the code explicitly specifies the instance of `SecureRandom` to be `SHA1PRNG` (because a call to `.getInstance()` will return whatever the Java properties specify), to be completely explicit, it should be `.getInstance("SHA1PRNG", "SUN")` because the Java cryptographic service provider (CSP) should be selected. [On most systems this will default to Sun](https://www.cigital.com/blog/proper-use-of-javas-securerandom/), but it can conceivably cause issues if a different CSP is prioritized. ~~

After [discussing with Joe Witt, Aldrin Piri, and Adam Taft](https://issues.apache.org/jira/browse/NIFI-1240), I've removed this comment. There are scenarios where the Sun CSP is not available (for example, IBM JRE) and we still need to run. In addition, the algorithm does not need to be specified, as in this use case, the `SecureRandom` is just generating a salt and the salt is provided on the wire. There is no compatibility issue between different providers in this case. 

Second, seeding the `SecureRandom` with the current time is most definitely not random and is predictable. `SecureRandom.nextBytes()` actually [self-seeds if the instance had not previously been seeded](https://www.cigital.com/blog/issues-when-using-java-securerandom/), and this manual seeding is decreasing the entropy used. These two issues will be resolved in an upcoming release, but are not related to the encryption issue we are addressing now. 

## The Callbacks

So we have an instance of `EncryptCallback` that was instantiated by passing in a `byte[] salt`. Let's see how that salt is used. 

The class has a single field (the salt), a constructor, and a method `public void process(final InputStream in, final OutputStream out) throws IOException`. This method contains three blocks of code I'll call _setup_, _process_, and _finish_. 

### Setup

```java
@Override
public void process(final InputStream in, final OutputStream out) throws IOException {
    final PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, 1000);
    try {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
    } catch (final Exception e) {
        throw new ProcessException(e);
    }

    out.write(salt);

    ...
```

That first line looks pretty interesting now, doesn't it? We see that a PBE parameter spec is being declared with our salt and a number. It's a good guess (and borne out by code inspection) that the second parameter is an iteration count. Remember above when we discussed increasing the cost of the key derivation to mitigate attacks? Variable iteration counts for KDFs allow the system to increase the cost of this operation to keep pace with improving hardware and attack optimizations. There is a world of discussion on the ever-continuing battle of cost on [Security StackExchange](http://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt), [again](http://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256/3993#3993), [Joseph Wynn](http://wildlyinaccurate.com/bcrypt-choosing-a-work-factor/), [Anthony Ferrara](http://blog.ircmaxell.com/2012/12/seven-ways-to-screw-up-bcrypt.html), [ECRYPT II](http://www.ecrypt.eu.org/ecrypt2/), and [hashCat](http://hashcat.net/oclhashcat/). 

That's all well and good for the security folks, but developers are probably banging their heads against the keyboard as this magic number is not recorded in the data, not synced between encrypt and decrypt, and causes the system to be tightly coupled and not backward compatible. This is one (of the many) reasons I like [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) as the cost factor is embedded in the record. So we will make another note to fix this in a future release (and provide backward compatibility), but we keep moving on. 

The `PBEParameterSpec` is passed into the `cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec)` call. This initializes the cipher to encrypt with the given key material, and the parameter spec is used to derive the key. Then the salt is written to the output stream, and the method is ready to encrypt the input data. 

### Process

```java
    ...
    final byte[] buffer = new byte[65536];
    int len;
    while ((len = in.read(buffer)) > 0) {
        final byte[] encryptedBytes = cipher.update(buffer, 0, len);
        if (encryptedBytes != null) {
            out.write(encryptedBytes);
        }
    }
    ...
```

The actual encrypting is fairly straightforward as things like the _substitution-permutation network_, _Rijndael S-boxes_, and the _invertible affine transformation_ are all handled behind the scenes by the cryptographic provider, in our case, BouncyCastle. The code is all [open source](http://www.bouncycastle.org/documentation.html) and the [cipher algorithm](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_cipher) is explained on Wikipedia, but the odds of a bug in this robust and globally-used library are miniscule compared to the consuming code, so we will stay in our sandbox. 

The code simply creates a `byte[]` buffer, continues reading from the `InputStream`, runs the buffer through the `cipher`, and writes the enciphered bytes out to the `OutputStream`. 

### Finish

```java
    ...
    try {
        out.write(cipher.doFinal());
    } catch (final IllegalBlockSizeException | BadPaddingException e) {
        throw new ProcessException(e);
    }
} // End of method

```

Calling `cipher.doFinal()` is a critical step in using the JCE ciphers. This is where the final padding (if any) will be applied, exceptions could be thrown, etc. 

At this point we have read the `InputStream`, encrypted the data, and written it back to the `OutputStream`. Let's quickly look at the `DecryptCallback`. 

## DecryptCallback

The `DecryptCallback` is almost identical to the `EncryptCallback`, except obviously performing the opposite operation. There is a default constructor and a `process` method which reads the salt from the `InputStream`, uses it to initialize the `cipher` (again with the magic iteration count), and then repeats the process from `EncryptCallback.process()` with the cipher set to decrypt. 

Hopefully at this point you have a solid understanding of the default NiFi internal encryption/decryption. Now we'll return to OpenSSL. 

## OpenSSL PBE KDF

I wrote a [prototype OpenSSL PBE AES-256-CBC encryptor](https://github.com/alopresto/opensslpbeencryptor) using [Groovy](http://www.groovy-lang.org) (it wasn't for direct inclusion in NiFi and I find Groovy to be a more expressive language and easier to test with when I'm writing proofs of concept, but every line here can be converted to pure Java, and usually automatically by the IDE). 

The first challenge when actually writing the code to be compatible with OpenSSL-encrypted data was "How does OpenSSL do KDF so we can get the right key and IV knowing only the password and salt?" Luckily, BouncyCastle once again does most of the work for us. The class `org.bouncycastle.crypto.generators.OpenSSLPBEParametersGenerator` does the magic. But we should understand what's happening, and with what we learned above, it's really not hard. 

While OpenSSL's documentation is notoriously sparse, the [`EVP_BytesToKey`](http://www.openssl.org/docs/crypto/EVP_BytesToKey.html) function is used to derive the key and IV from the password and salt. This function simply uses the MD5 hash of the password and salt to generate the key, then takes the MD5 of the key, password, and salt as the IV. From the documentation:

> If the total key and IV length is less than the digest length and MD5 is used then the derivation algorithm is compatible with PKCS#5 v1.5 otherwise a non standard extension is used to derive the extra data.

> Newer applications should use a more modern algorithm such as PBKDF2 as defined in PKCS#5v2.1 and provided by PKCS5_PBKDF2_HMAC.

Unhelpfully, while the `PKCS5_PBKDF2_HMAC` function is in the OpenSSL library, it is not exposed to the command line `enc` command and there is no setting to my knowledge to prefer it over `EVP_BytesToKey`. A simple C wrapper can be written to accomplish this, but we'll deal with the default custom process in our code. I'm thankful that [Ola Bini](https://olabini.com/blog/tag/evp_bytestokey/) ported this method to Java so we can see it even if BouncyCastle has it for us already. 

The Groovy code below generates a `CipherParameters` (actually a `ParametersWithIV` instance) containing the secret key and IV. 

```groovy
static CipherParameters deriveKeyFromPassword(final String password, final String salt = "") {
    OpenSSLPBEParametersGenerator gen = new OpenSSLPBEParametersGenerator();
    // The salt is not safe to pass around in regular string format, so it is hex encoded
    byte[] saltBytes = Hex.decodeHex(salt.toCharArray())
    gen.init(password.bytes, saltBytes);
    CipherParameters cp = gen.generateDerivedParameters(KEY_LENGTH_BITS, IV_LENGTH_BITS);
    return cp;
}
```

To decrypt the data, I used BouncyCastle's `PaddedBufferedBlockCipher` class wrapping an `AESEngine` in a `CBCBlockCipher`. Much like the ever-evolving heirarchy of `Reader` and `Stream` classes in Java, a little knowledge of what's available for plug-and-play makes your job easier. The `cipher.init()` call takes two parameters -- a `boolean` (`true` for encrypt, `false` for decrypt, although I probably could have made constants for self-documenting naming helpfulness) and the `ParametersWithIV` container. I delegate the actual byte processing to a method which simply iterates over the input bytes and feeds them to the cipher because I can reuse it identically for encryption. 

```groovy
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
```

I added a couple utility methods to read the salt and cipher text from the OpenSSL format in raw and Base64 encodings, and slapped a unit test suite on top. 

## Putting It In NiFI

I originally took the code discussed above and put it in a new `OpenSSLPBEEncryptor` in NiFi. After [discussing further with Joe Witt and Aldrin Piri](https://issues.apache.org/jira/browse/NIFI-1242), we agreed that the real issue was that the existing code used a non-standard KDF which was incompatible with OpenSSL. As the cipher algorithms available to users indicated OpenSSL compatibility, rather than provide a new encryptor, we decided to offer a choice of KDFs as a property in the processor. This allows backward compatibility with legacy NiFi KDF (MD5 @ 1000 iterations) and the OpenSSL MD5 PKCS#5 v1.5 KDF. With that choice, the code changes become minimal. 

Rather than using the BouncyCastle implementation, we can simply refactor the existing code to make the iteration count variable based on the KDF property. 

```java
 public PasswordBasedEncryptor(final String algorithm, final String providerName, final char[] password, KeyDerivationFunction kdf) {
        super();
        try {
            // initialize cipher
            this.cipher = Cipher.getInstance(algorithm, providerName);
            this.kdf = kdf;

            if (isOpenSSLKDF()) {
                this.saltSize = OPENSSL_EVP_SALT_SIZE;
                this.iterationsCount = OPENSSL_EVP_KDF_ITERATIONS;
            } else {
                int algorithmBlockSize = cipher.getBlockSize();
                this.saltSize = (algorithmBlockSize > 0) ? algorithmBlockSize : DEFAULT_SALT_SIZE;
            }

            // initialize SecretKey from password
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, providerName);
            this.secretKey = factory.generateSecret(pbeKeySpec);
        } catch (Exception e) {
            throw new ProcessException(e);
        }
    }
    
    ...
    
    
    public int getIterationsCount() {
        return iterationsCount;
    }

    private boolean isOpenSSLKDF() {
        return KeyDerivationFunction.OPENSSL_EVP_BYTES_TO_KEY.equals(kdf);
    }
```

With the new `kdf` parameter, the key generation and cipher initialization code stays identical. Only the `iterationsCount` and `saltSize` are handled differently. 

In the `DecryptCallback` we handle the custom salt format and initialize the `PBEParameterSpec` with the variable `iterationsCount`:
 
```java
@Override
public void process(final InputStream in, final OutputStream out) throws IOException {
    byte[] salt = new byte[saltSize];
    try {
        // If the KDF is OpenSSL, try to read the salt from the input stream
        if (isOpenSSLKDF()) {
            // The header and salt format is "Salted__salt x8b" in ASCII
            // Try to read the header and salt from the input
            byte[] header = new byte[PasswordBasedEncryptor.OPENSSL_EVP_HEADER_SIZE];
            // Mark the stream in case there is no salt
            in.mark(OPENSSL_EVP_HEADER_SIZE + 1);
            StreamUtils.fillBuffer(in, header);
            final byte[] headerMarkerBytes = OPENSSL_EVP_HEADER_MARKER.getBytes(StandardCharsets.US_ASCII);
            if (!Arrays.equals(headerMarkerBytes, header)) {
                // No salt present
                salt = new byte[0];
                // Reset the stream because we skipped 8 bytes of cipher text
                in.reset();
            }
        }
        StreamUtils.fillBuffer(in, salt);
    } catch (final EOFException e) {
        throw new ProcessException("Cannot decrypt because file size is smaller than salt size", e);
    }
    final PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, getIterationsCount());
    try {
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);
    } catch (final Exception e) {
        throw new ProcessException(e);
    }
    final byte[] buffer = new byte[65536];
    int len;
    while ((len = in.read(buffer)) > 0) {
        final byte[] decryptedBytes = cipher.update(buffer, 0, len);
        if (decryptedBytes != null) {
            out.write(decryptedBytes);
        }
    }
    try {
        out.write(cipher.doFinal());
    } catch (final Exception e) {
        throw new ProcessException(e);
    }
}
```

### Previous Process

Here is the original content of this section which documented the process behind the new implementation of the encryptor. 

Now that we have working code which reads the OpenSSL format and can decrypt it, the only step left is to package it in a way that NiFi likes. We don't need to add any properties to the `EncryptContent` processor as it already has `password` (if we wanted to provide non-PBE symmetric encryption, we would need a new property for the key. Again, a valuable feature for another day). The salt is embedded in the cipher text following the constant header, so we can extract that during the `DecryptCallback` and use it in conjunction with the password to derive the key and IV. 

In fact, all we need to do is provide a new implementation of the `Encryptor` interface called `OpenSSLPBEEncryptor`. We'll have to store the password internally, as we don't have all of the key derivation parameters at instantiation. When providing the `EncryptCallback`, we can generate a random 8 byte ASCII salt. In the callbacks themselves, we'll read the salt, use it and the password to derive the key and IV, and process the input bytes through the cipher the same as our existing `PasswordBasedEncryptor`. 

The last step is to add a value to the `EncryptionMethod` enum denoting our new KDF algorithm (the actual encryption using AES-256-CBC is identical to the standard implementation). Then in the `EncryptContent.onTrigger()` logic tree, we'll detect that type and instantiate our custom implementation instead of the "generic/legacy" `PasswordBasedEncryptor`. It would also be possible to contain all of the changes in `PasswordBasedEncryptor` and have branching logic based on the algorithm name in the constructor and callbacks, but I personally prefer to separate new code from things that are running in production if possible and semantically reasonable. 

## Other Important Things

This is already long enough, but there are a couple of cryptography things to mention. 

### The OpenSSL KDF

I don't know why it is the way it is, but it's not ideal. I'll let Thomas Pornin [explain succinctly](http://security.stackexchange.com/a/29139/16485):

> The process by which the password and salt are turned into the key and IV is not documented, but a look at the source code shows that it calls the OpenSSL-specific EVP_BytesToKey() function, which uses a custom key derivation function with some repeated hashing. This is a non-standard and not-well vetted construct (!) which relies on the MD5 hash function of dubious reputation (!!); that function can be changed on the command-line with the undocumented -md flag (!!!); the "iteration count" is set by the enc command to 1 and cannot be changed (!!!!). This means that the first 16 bytes of the key will be equal to MD5(password||salt), and that's it.

> This is quite weak ! Anybody who knows how to write code on a PC can try to crack such a scheme and will be able to "try" several dozens of millions of potential passwords per second (hundreds of millions will be achievable with a GPU). If you use "openssl enc", make sure your password has very high entropy ! (i.e. higher than usually recommended; aim for 80 bits, at least). Or, preferably, don't use it at all; instead, go for something more robust (GnuPG, when doing symmetric encryption for a password, uses a stronger KDF with many iterations of the underlying hash function).

As addressed earlier, using `$ openssl enc` mandates this KDF, and `PBKDF2` would be much better, but requires custom coding, so I expect it is almost non-existent in the wild. If someone expects NiFi to decrypt "OpenSSL PBE", this is the KDF they are using. 

### Authenticated Encryption with Associated Data

All of the discussion here revolved around symmetric encryption using PBE. Symmetric encryption provides _confidentiality_, in that an observer cannot determine the content of the message without the secret key, but does not provide _integrity_. Because of this, and especially with CBC, an attacker can manipulate the cipher text without knowing the content and this can have serious negative effects (known as a [Chosen Ciphertext Attack](https://en.wikipedia.org/wiki/Chosen-ciphertext_attack), this is the foundation for many of the previous attacks against SSL/TLS such as Lucky Thirteen or Bleichenbacher). The attacker can also intercept and manipulate the cipher text with some knowledge of the contents (perhaps gathered through cribbing) and corrupt the data without knowledge of the key.

To provide message integrity with symmetric encryption, a Message Authentication Code (MAC) is needed. Similar to a checksum, this "authentication tag" is calculated over the cipher text using an algorithm known to both parties and (usually) some secret value. [Hash-based MACs (HMAC)](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) are a common tool for this, but come with their own caveats:  

1. The key used for the HMAC calculation must be unrelated to the encryption key. This means two keys must be exchanged between the parties. 
1. The HMAC must be calculated over the cipher text, not plaintext.
1. The HMAC verification step must come before decryption.
1. The verification step must not introduce a timing attack vulnerability (Java is [especially prone to this](http://codahale.com/a-lesson-in-timing-attacks/) as String equality comparison short circuits on inequality by design and even `MessageDigest.isEquals()` was susceptible to this until Java SE 6 Update 17)

An alternate method to manually calculating the HMAC is to use a cipher which supports Authenticated Encryption with Associated Data (AEAD). These ciphers provide encryption and the authentication tag in a single operation and verify message integrity during decryption. Many of these ciphers are protected by patents (and thus not widely or freely available), but [Galois/Counter Mode](https://en.wikipedia.org/wiki/Galois/Counter_Mode) is now standard in AES. It is often used for TLS due to its performance. 

Unfortunately, it was only added as an encryption cipher for OpenSSL in 1.0.1 (TLS only) and many older versions (a number of clients still use 0.9.8zg) won't support it. OpenSSL's command-line `enc` tool still does not support it:

```bash
0s @ 00:34:30 $ ossl version
OpenSSL 1.0.2d 9 Jul 2015
0s @ 00:35:49 $ ossl enc -aes-256-gcm -e -a -in plain.txt -out gcm.enc -k thisIsABadPassword -p
AEAD ciphers not supported by the enc utility
```

However, if you are doing encryption and decryption only in code and **do not need compatibility** with the command-line tool, I _strongly recommend_ GCM over CBC. It is fast and addresses more security concerns with the authentication tag than CBC alone. 

### CBC IV Issue with OpenSSLPBEParametersGenerator

At one time I was trying to migrate from the sandbox to NiFi and use the BouncyCastle `OpenSSLPBEParametersGenerator` with a JCE `Cipher` rather than the wrapped BouncyCastle `PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine))` construct. I ran across a puzzling issue where the first block of the cipher text failed to decrypt but the rest of the message was fine. Obviously this is an IV issue, so I started looking at the IV in the cipher instance. The value was null, which was surprising, because I was passing the `IvParameterSpec` in as follows:

```groovy
        Cipher cipher = Cipher.getInstance("PBEWITHMD5AND256BITAES-CBC-OPENSSL", "BC")
        // Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        
        ParametersWithIV parametersWithIV = ((ParametersWithIV) gen.generateDerivedParameters(keyLengthBits, ivLengthBits));

        final byte[] keyBytesFromParameters = ((KeyParameter) parametersWithIV.getParameters()).getKey();
        SecretKey key = new SecretKeySpec(keyBytesFromParameters, "AES");

        IvParameterSpec ivParameterSpec = new IvParameterSpec(parametersWithIV.IV)
        logger.info("Created IvParameterSpec: ${Hex.encodeHexString(ivParameterSpec.IV)}")

        // This isn't even using the IVParameterSpec
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec)
        assert cipher.getIV() == ivParameterSpec.IV
```

Questioning my sanity, I switched to `AES/CBC/PKCS7Padding` and it immediately worked. What I eventually discovered is that using the `PBEWITHMD5AND256BITAES-CBC-OPENSSL` algorithm will demand that the IV is derived at the same time as the key using `PBEParameterSpec`. Just another gotcha to be aware of when switching between BouncyCastle and JCE ciphers. 

### JCE Unlimited Strength Cryptography

In order to use "strong" cryptography, you will need to install the [JCE Unlimited Strength Cryptography Policy Files](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html) for your version of Java. Here is a [brief explanation](http://crypto.stackexchange.com/a/20525/12569) of import restrictions on cryptography. The JCA discusses the [maximum key lengths](http://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html#importlimits) for each algorithm provided by the Oracle implementation. 

As noted in that table, AES 128 bit encryption is supported in a default JRE. However, when some people tried to review my work, they ran into issues with "illegal key size". Through some debugging, we determined that the key is not fully derived from the `SecretKeyFactory` when it is provided to `cipher.init()`. Rather, it is the byte representation of the **raw password** that is then combined with the salt `PBEParameterSpec` during `init`. The problem is that the key length check occurs *before* this process, so Java complains that 18 bytes (the length of `thisIsABadPassword`) is longer than 16 bytes (128 bits), and stops executing. Even switching to `PBEWITHMD5ANDDES-OPENSSL`, for which the key length is a paltry 8 bytes and one is for parity (seriously, don't use DES), will fail on a system without the Unlimited Strength Cryptography Policy files. If my usual password paranoia didn't extend into testing, I would have used a simple `password` and this would not have been discovered. 

After debugging on a system without the USC policies installed, this is our determination for PBE:

Cipher  | Password length | Should Work | Does Work
--------|-----------------|-------------|-----------
AES-128 |   <= 16 chars   |     YES     |    YES
AES-128 |    > 16 chars   |     YES     |     NO
AES-192 |   <= 16 chars   |      NO     |    YES
AES-192 |    > 16 chars   |      NO     |     NO
AES-256 |   <= 16 chars   |      NO     |    YES
AES-256 |    > 16 chars   |      NO     |     NO

We verified that the higher key sizes are actually being used by encrypting files with OpenSSL AES-256 bit and a password <= 16 characters and then decrypting successfully within NiFi. This is actually something that I've never come across before and have an open question on [Information Security Stack Exchange](http://security.stackexchange.com/questions/107321/why-does-java-allow-aes-256-bit-encryption-on-systems-without-jce-unlimited-stre) looking for more information. 

There is a way to get around this without requiring that all systems that run the tests install those files manually, but I am almost hesitant to post it because it is a hack and should not ever be used in a non-test system. 

Using reflection, we can override the policies and tell Java to go ahead and use the longer key. Place this code before the `cipher.init()` command:

```java
if (Cipher.getMaxAllowedKeyLength("AES") < 256) {
  try {
    Field field = Class.forName("javax.crypto.JceSecurity").
    getDeclaredField("isRestricted");
    field.setAccessible(true);
    field.set(null, java.lang.Boolean.FALSE);
  } catch (Exception e) {
    fail("Could not override JCE cryptography strength policy setting");
    fail(e.getMessage());
  }
}
```

Now the tests will run successfully, but this is no substitution for actually loading the policy files into any Java installation where strong cryptography is required. 

Rather than hack it like this, we used `Assume.assumeTrue()` statements to skip the tests on systems without the JCE USC policies installed. Aldrin also added custom validation to the processor to verify that the *combination* of algorithm key size and password length would be successful based on the system configuration. 
