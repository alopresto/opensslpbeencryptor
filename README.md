# OpenSSL PBE Encryption

This is a sandbox project to explore the password-based encryption used by the [OpenSSL EVP_BytesToKey](https://www.openssl.org/docs/manmaster/apps/enc.html) mechanism. Specifically, this Groovy code can encrypt and decrypt data compatible with OpenSSL's PBE for AES-256-CBC with/without salt and with/without Base64 encoding. The key and IV are derived from the password and salt using the MD5 KDF algorithm found here [Ola Bini](https://olabini.com/blog/tag/evp_bytestokey/) and described by [Thomas Pornin](http://security.stackexchange.com/a/29139/16485). 