#GOLANGDADDY go-tools-essential

See gotools.go to see how these functions work.

Functions with error possibility need to be passed a chan string for error reporting.

This error reporting infrastructure is intended to be used with go-multi-logger package.

##Tool Summary

```

// cryptobject stores RSA/AES encrypted objects

type CryptObject {...}

// keystore stores private keys RSA/ECDSA

type KeyStore struct {...}

// helper functions:

tools.Encode_base64(...)
tools.Decode_base64(...)
tools.Encode_hex(...)
tools.Decode_hex(...)

tools.Encode_gob(...)
tools.Decode_gob(...)
tools.Encode_json(...)
tools.Decode_json(...)

tools.Scrypt(...)
tools.SHA_256(...)
tools.SHA_512(...)
tools.SHA_3(...)
tools.SHA_1(...)
tools.SHA(...)

tools.Generate_ecdsa(...)

tools.Generate_rsa(...)
tools.Recover_rsa(...)
tools.Encrypt_rsa(...)
tools.Decrypt_rsa(...)

tools.Crypt_aes(...)
tools.Crypt_aes_cbc(...)

tools.Socket_open(...)

tools.File_open(...)
tools.URL_get(...)

tools.Time_now(...)
tools.Quit_slow(...)

```
