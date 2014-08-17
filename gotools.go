package tools

import (
		"os"
		"io"
		"time"
		"bytes"
		"crypto/rsa"
		"crypto/aes"
		"crypto/cipher"
		"encoding/gob"
		"encoding/json"
		"encoding/base64"
		"encoding/hex"
		"crypto/sha1"
		"crypto/sha256"
		"crypto/sha512"
		"crypto/rand"
		"code.google.com/p/go.crypto/sha3"
		"github.com/dchest/scrypt"
		)

type CryptObject struct {
	ID string
	Protected string
	Crypt string
	Time string
}

type KeyStore struct {
	ID string
	PublicKeyHash string
	EncryptedPrivateKey string
	EncodedPublicKey string
	decodedpublickey interface{}
	decodedprivatekey interface{}
}

var entropychannel chan chan string

func Entropy64() string {
	if entropychannel == nil {
		entropychannel = make(chan chan string, 9)
		go entropy_generator()
	}
	return entropy()[0:64]
}
func entropy() string {
	c := make(chan string)
	entropychannel <- c 
	return <- c
}
func entropy_generator() {
	iv := make([]byte, 512)
	x := []byte{}
	_, _ = rand.Read(iv)
	for {
			c := <- entropychannel
			_, err := rand.Read(iv)
			if err != nil {
				_, x = SHA(3, 128, Time_now(0), x)
				c <- string(x)
				continue
			}
			_, x = SHA(3, 128, "", append(iv, x...))
			c <- string(x)
		}
}

func Time_now(thelength int) string {
	t := time.Now()
	if thelength < 0 {
		const layout = "Jan 2, 2006 at 3:04pm (GMT)"
		return(t.Format(layout))
	}
	if thelength > 0 {
		req := t.Format("20060102150405")
		return(req[0:thelength])
	}
	return(t.Format("20060102150405"))
}

// ECDSA keygen

func Generate_ecdsa(derr chan string, key_length int, secret_key string) (bool, *KeyStore) {	
	private_key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		derr<-"TOOLS/KEYGEN/ECDSA: "+err.Error()
		return false, nil
	}
	keystore := &KeyStore{}
	keystore.ID = "ECDSA"
	keystore.decodedprivatekey = private_key
	keystore.decodedpublickey = &private_key.PublicKey
	ok, encoded_key := Encode_gob(derr, private_key)
	if ok {
		keystore.EncryptedPrivateKey = Encode_base64(Crypt_aes(derr, true, secret_key, encoded_key))
		okk, encoded_public_key := Encode_gob(derr, keystore.decodedpublickey)
		if okk {
			keystore.EncodedPublicKey = Encode_base64(encoded_public_key)
			keystore.PublicKeyHash = SHA_256(keystore.EncodedPublicKey)
			return true, keystore
		}
	}
	derr<-"TOOLS/KEYGEN/ECDSA: FAILED"
	return false, nil
}

// RSA keygen

func Recover_rsa(derr chan string, keystore *KeyStore, secret_key string) (bool, *rsa.PrivateKey) {
	ok, crypt_bytes := Decode_base64(derr, keystore.EncryptedPrivateKey)
	if !ok {
		derr<-"TOOLS/RECOVER/RSA: ENCODED KEY FAILED BASE64"
		return false, nil
	}
	plain_key := &rsa.PrivateKey{}
	okk := Decode_gob(derr, Crypt_aes(derr, false, secret_key, crypt_bytes), plain_key)
	if okk { return true, plain_key }
	derr<-"TOOLS/RECOVER/RSA: FAILED"
	return false, nil
}

func Generate_rsa(derr chan string, key_length int, secret_key string) (bool, *KeyStore) {	
	private_key, err := rsa.GenerateKey(rand.Reader, key_length)
	if err != nil {
		derr<-"TOOLS/KEYGEN/RSA: "+err.Error()
		return false, nil
	}
	keystore := &KeyStore{}
	keystore.ID = "RSA"
	keystore.decodedprivatekey = private_key
	keystore.decodedpublickey = &private_key.PublicKey
	ok, encoded_key := Encode_gob(derr, private_key)
	if ok {
		keystore.EncryptedPrivateKey = Encode_base64(Crypt_aes(derr, true, secret_key, encoded_key))
		okk, encoded_public_key := Encode_gob(derr, keystore.decodedpublickey)
		if okk {
			keystore.EncodedPublicKey = Encode_base64(encoded_public_key)
			keystore.PublicKeyHash = SHA_256(keystore.EncodedPublicKey)
			return true, keystore
		}
	}
	derr<-"TOOLS/KEYGEN/RSA: FAILED"
	return false, nil
}
	
// RSA encrypt / decrypt bytes
		
func Encrypt_rsa(derr chan string, public_key *rsa.PublicKey, data interface{}) *CryptObject {
	aes_key := Entropy64()
	cipher_bytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public_key, []byte(aes_key), []byte(""))
	if err != nil {
		derr<-"TOOLS/RSA/ENCRYPT: "+err.Error()
		return(nil)
	}
	cryptobject := &CryptObject{}
	cryptobject.Time = Time_now(0)
	cryptobject.Protected = Encode_base64(cipher_bytes)
	ok, encoded_object := Encode_gob(derr, data)
	if ok {
		cryptobject.Crypt = Encode_base64(Crypt_aes(derr, true, aes_key, encoded_object))
		return cryptobject
	}
	derr<-"TOOLS/RSA/ENCRYPT: FAILED"
	return nil
}

func Decrypt_rsa(derr chan string, private_key *rsa.PrivateKey, c *CryptObject, dest *interface{}) bool {
	ok, cipher_bytes := Decode_base64(derr, c.Protected)
	if !ok {
		derr<-"TOOLS/RSA/DECRYPT: CRYPTOBJECT KEY FAILS BASE64"
		return false
	}
	plainkey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private_key, cipher_bytes, []byte(""))
	if err != nil {
		derr<-"TOOLS/RSA/DECRYPT: THIS CRYPTOBJECT FAILS RSA"
		return false
	}
	okc, crypt_bytes := Decode_base64(derr, c.Crypt)
	if !okc {
		derr<-"TOOLS/RSA/DECRYPT: CRYPTOBJECT BODY FAILS BASE64"
		return false
	}
	ok = Decode_gob(derr, Crypt_aes(derr, false, string(plainkey), crypt_bytes), dest)
	if ok { return true }
	derr<-"TOOLS/RSA/DECRYPT: THIS CRYPTOBJECT FAILS AES"
	return false
}


// AES encrypt/decrypt
		
func Crypt_aes(derr chan string, encrypt bool, password string, text []byte) []byte {
	output := []byte{}
	_, key := SHA(3, 32, password, nil)
	block, err := aes.NewCipher(key)   
	if err != nil {
		derr<-"CANT GET NEW CIPHER"
		return([]byte("!"))
	}
	if encrypt {
		ciphertext := make([]byte, aes.BlockSize+len(string(text)))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {	
			derr<-"IO READER FAIL"
			return([]byte("!"))
		}
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
		output = ciphertext
	} else {
		if len(string(text)) < aes.BlockSize {
			derr<-"CIPHERTEXT IS TOO SHORT"
			return([]byte("!"))
		}
		iv := text[:aes.BlockSize]
		text = text[aes.BlockSize:]
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(text, text)
		output = text
	}
	return output
}
			
/// HASHING

func Scrypt(derr chan string, px string) []byte {
	_, h := SHA(3, 32, px, nil)
	b, err := scrypt.Key([]byte(px), h, 16384, 8, 1, 64)
	if err != nil { derr<-"TOOLS/SCRYPT "+err.Error() }
	return b
}

func SHA_1(input string) string {
	h, _ := SHA(1, 0, input, nil)
	return h
}

func SHA_256(input string) string {
	h, _ := SHA(2, 64, input, nil)
	return h
}

func SHA_512(input string) string {
	h, _ := SHA(2, 128, input, nil)
	return h
}

func SHA_3(input string) string {
	h, _ := SHA(3, 64, input, nil)
	return h
}

func SHA(i, l int, s string, b []byte) (string, []byte) {
	hash := sha1.New()
	if b != nil { s += string(b) }
	if l > 128 { l = 128 }
	switch(i) {
		case 1:	if l > 0 { l = 0 }
		case 2: if l <= 64 { hash = sha256.New() } else { hash = sha512.New() }
		case 3: if l <= 64 { hash = sha3.NewKeccak256() } else { hash = sha3.NewKeccak512() }
		default: hash = sha256.New()
	}
	hash.Write([]byte(s))
	output := hash.Sum(nil)
	if i > 1 { if l < len(output) { output = output[0:l] } }
	return hex.EncodeToString(output), output
}

		
// JSON marshalling

func Encode_json(derr chan string, i interface{}) (bool, []byte) {
	b, e := json.Marshal(i)
	if e != nil {
		derr<-"TOOLS/JSON/ENCODE: "+e.Error()
		return false, nil
	}
	return true, b
}

func Decode_json(derr chan string, b []byte, i interface{}) bool {
	e := json.Unmarshal(b, i)
	if e != nil {
		derr<-"TOOLS/JSON/DECODE: "+e.Error()
		return false
	}
	return true
}

// BASE64 encoding
		
func Encode_base64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func Decode_base64(derr chan string, s string) (bool, []byte) {
	data, e := base64.StdEncoding.DecodeString(s)
    if e != nil { 
		derr<-"TOOLS/BASE64/DECODE: "+e.Error()
		return false, nil
	}
    return true, data
}		

// HEX encoding

func Encode_hex(b []byte) string {
	return hex.EncodeToString(b)
}

func Decode_hex(derr chan string, s string) (bool, []byte) {
	b, e := hex.DecodeString(s)
	if e != nil {
		derr<-"TOOLS/HEX/DECODE: "+e.Error()
		return false, nil
	}
	return true, b
}

// GOB marshalling		
		
func Encode_gob(derr chan string, input interface{}) (bool, []byte) {
	if input == nil {
		derr<-"TOOLS/GOB/ENCODE: INPUT INTERFACE IS NIL"
		return false, nil
	}
	encoded := new(bytes.Buffer)
	encCache := gob.NewEncoder(encoded)
	encCache.Encode(input)
	return true, encoded.Bytes()
}

func Decode_gob(derr chan string, input []byte, data interface{}) bool {
	dCache := bytes.NewBuffer(input)
	decCache := gob.NewDecoder(dCache)
	e := decCache.Decode(data)
	if e != nil || data == nil {
		derr<-"TOOLS/GOB/DECODE: "+e.Error()
		return false
	}
	return true
}

// MISC

func Quit_slow(derr chan string, msg string) {
	derr<-"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	derr<-"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	derr<-msg
	time.Sleep(2 * time.Second)
	os.Exit(1)
}