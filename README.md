#GOLANGDADDY go-tools-essential

See gotools.go to see how these functions work.

Functions with error possibility need to be passed a chan string for error reporting.

This error reporting infrastructure is intended to be used with go-multi-logger package.

##Tool Summary

```

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

tools.Generate_rsa(...)
tools.Recover_rsa(...)
tools.Encrypt_rsa(...)
tools.Decrypt_rsa(...)

tools.Crypt_aes(...)

tools.Time_now(...)
tools.Quit_slow(...)

```
