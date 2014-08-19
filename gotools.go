package tools

import (
		"os"
		"io"
		"os/exec"
		"io/ioutil"
		"time"
		"bytes"
		"net/http"
		"crypto/rsa"
		"crypto/aes"
		"crypto/cipher"
		"crypto/elliptic"
		"crypto/ecdsa"
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
		"code.google.com/p/go.net/websocket"
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

func ID_weak() string {
	id, _ := SHA(1, 0, Entropy64(), nil)
	return id
}

func ID_strong() string {
	id, _ := SHA(2, 64, Entropy64(), nil)
	return id
}

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

// ECDSA

func Sign_gethash(derr chan string, object interface{}) (bool, []byte) {
	for {
		ok, encoded_object_bytes := Encode_gob(derr, object)
		if !ok { break }
		_, object_hash := SHA(3, 128, "", encoded_object_bytes)
		return true, object_hash
	}
	derr<-"TOOLS/SIGN/GETHASH: FAILED"
	return false, nil
}

func Sign_ecdsa(derr chan string, private_key *ecdsa.PrivateKey, object interface{}) (bool, []string) {
	ok, object_hash := Sign_gethash(derr, object)
	for {
		if !ok { break }
		a, b, err := ecdsa.Sign(rand.Reader, private_key, object_hash)
		if err != nil {
			derr<-err.Error()
			break
		}
		return true, []string{a.String(), b.String()}
	}
	derr<-"TOOLS/SIGN/ECDSA: FAILED"
	return false, nil
}

// ECDSA keygen

func Generate_ecdsa(derr chan string, secret_key string) (bool, *KeyStore) {	
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
	for {
		if !ok { break }
		crypt_ok, ciphertext := Crypt_aes(derr, true, secret_key, encoded_key)
		if !crypt_ok { break }
		keystore.EncryptedPrivateKey = Encode_base64(ciphertext)
		enc_ok, encoded_public_key := Encode_gob(derr, keystore.decodedpublickey)
		if !enc_ok { break }
		keystore.EncodedPublicKey = Encode_base64(encoded_public_key)
		keystore.PublicKeyHash = SHA_256(keystore.EncodedPublicKey)
		return true, keystore
	}
	derr<-"TOOLS/KEYGEN/ECDSA: FAILED"
	return false, nil
}

// RSA keygen

func Recover_rsa(derr chan string, keystore *KeyStore, secret_key string) (bool, *rsa.PrivateKey) {
	ok, crypt_bytes := Decode_base64(derr, keystore.EncryptedPrivateKey)
	for {
		if !ok { break }
		crypt_ok, plaintext := Crypt_aes(derr, false, secret_key, crypt_bytes)
		if !crypt_ok { break }
		plain_key := &rsa.PrivateKey{}
		dec_ok := Decode_gob(derr, plaintext, plain_key)
		if !dec_ok { break }
		return true, plain_key
	}
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
	keystore.ID = "ECDSA"
	keystore.decodedprivatekey = private_key
	keystore.decodedpublickey = &private_key.PublicKey
	ok, encoded_key := Encode_gob(derr, private_key)
	for {
		if !ok { break }
		crypt_ok, ciphertext := Crypt_aes(derr, true, secret_key, encoded_key)
		if !crypt_ok { break }
		keystore.EncryptedPrivateKey = Encode_base64(ciphertext)
		enc_ok, encoded_public_key := Encode_gob(derr, keystore.decodedpublickey)
		if !enc_ok { break }
		keystore.EncodedPublicKey = Encode_base64(encoded_public_key)
		keystore.PublicKeyHash = SHA_256(keystore.EncodedPublicKey)
		return true, keystore
	}
	derr<-"TOOLS/KEYGEN/RSA: FAILED"
	return false, nil
}
	
// RSA encrypt / decrypt bytes
		
func Encrypt_rsa(derr chan string, public_key *rsa.PublicKey, data interface{}) *CryptObject {
	for {
		aes_key := Entropy64()
		cipher_bytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public_key, []byte(aes_key), []byte(""))
		if err != nil {
			derr<-err.Error()
			break
		}
		cryptobject := &CryptObject{}
		cryptobject.Time = Time_now(0)
		cryptobject.Protected = Encode_base64(cipher_bytes)
		enc_ok, encoded_object := Encode_gob(derr, data)
		if !enc_ok { break }
		crypt_ok, ciphertext_bytes := Crypt_aes(derr, true, aes_key, encoded_object)
		if !crypt_ok { break }
		cryptobject.Crypt = Encode_base64(ciphertext_bytes)
		return cryptobject
	}
	derr<-"TOOLS/RSA/ENCRYPT: FAILED"
	return nil
}

func Decrypt_rsa(derr chan string, private_key *rsa.PrivateKey, c *CryptObject, dest *interface{}) bool {
	ok, cipher_bytes := Decode_base64(derr, c.Protected)
	for {
		if !ok { break }
		plainkey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, private_key, cipher_bytes, []byte(""))
		if err != nil {
			derr<-err.Error()
			break 
		}
		dec_ok, crypt_bytes := Decode_base64(derr, c.Crypt)
		if !dec_ok { break }
		crypt_ok, plaintext_bytes := Crypt_aes(derr, false, string(plainkey), crypt_bytes)
		if !crypt_ok { break }
		gob_ok := Decode_gob(derr, plaintext_bytes, dest)
		if !gob_ok { break }
		return true
	}
	derr<-"TOOLS/RSA/DECRYPT: FAILED"
	return false
}


// AES CBC MODE (compatible with cryptoJS)

func Crypt_aes_cbc(derr chan string, encrypt bool, password string, text []byte, iv []byte) (bool, string) {
	_, key := SHA(3, 32, password, nil)
	c, err := aes.NewCipher(key)
	if err != nil {
		derr<-"TOOLS/AES/CBC "+err.Error()
		return false, "!"
	}
	newbuffer := make([]byte, len(text))
	if encrypt {
		encrypter := cipher.NewCBCEncrypter(c, iv)
		encrypter.CryptBlocks(newbuffer, text)
		return true, Encode_base64(newbuffer)
	}
	decrypter := cipher.NewCBCDecrypter(c, iv)
	decrypter.CryptBlocks(text, newbuffer)
	return true, string(newbuffer)
}

// AES encrypt/decrypt
		
func Crypt_aes(derr chan string, encrypt bool, password string, text []byte) (bool, []byte) {
	output := []byte{}
	_, key := SHA(3, 32, password, nil)
	block, err := aes.NewCipher(key)   
	if err != nil {
		derr<-"TOOLS/AES "+err.Error()
		return false, nil
	}
	if encrypt {
		ciphertext := make([]byte, aes.BlockSize+len(string(text)))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {	
			derr<-"IO READER FAIL"
			return false, nil
		}
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
		output = ciphertext
	} else {
		if len(string(text)) < aes.BlockSize {
			derr<-"CIPHERTEXT IS TOO SHORT"
			return false, nil
		}
		iv := text[:aes.BlockSize]
		text = text[aes.BlockSize:]
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(text, text)
		output = text
	}
	return true, output
}
			
/// HASHING

func Scrypt(derr chan string, input string) (bool, []byte) {
	_, h := SHA(3, 32, input, nil)
	b, err := scrypt.Key([]byte(input), h, 16384, 8, 1, 64)
	if err != nil {
		derr<-"TOOLS/SCRYPT: "+err.Error()
		return false, nil
	}
	return true, b
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

func File_open(derr chan string, path string) (bool, []byte) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		derr<-err.Error()
		return false, nil
	}
	return true, b
}

func URL_get(derr chan string, url string) (bool, string) {
	resp, err := http.Get(url)
	if err != nil || resp == nil {
		derr<-"TOOLS/URL/GET: "+err.Error()
		return false, "!"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil || body == nil {
		derr<-"TOOLS/URL/GET: "+err.Error()
		return false, "!"
	}
	return true, string(body)
}

func Valid_hash(l int, x string) bool {
	if len(x) == l {
		_, err := hex.DecodeString(x)
		if err == nil { return true }
	}	
	return false
}

func Quit_slow(derr chan string, msg string) {
	derr<-"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	derr<-"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
	derr<-msg
	time.Sleep(2 * time.Second)
	os.Exit(1)
}

func Socket_open(derr chan string, protocol, route, port, ssl_certpath, ssl_keypath string, handlerfunc func(*websocket.Conn)) {
	derr<-"TOOLS/SOCKET/OPEN: "+protocol+" "+route+" "+port
	http.Handle("/"+route, websocket.Handler(handlerfunc))
	if protocol == "https://" {
		err := http.ListenAndServeTLS(port, ssl_certpath, ssl_keypath, nil)
		if err != nil { derr<-"TOOLS/SOCKET/OPEN: "+err.Error() }
	} else {
		err := http.ListenAndServe(port, nil)
		if err != nil { derr<-"TOOLS/SOCKET/OPEN: "+err.Error() }
	}
}

func String_array_stringify(parts []string) string {
	output := ""
	for x := range parts { if len(parts[x]) > 0 { output += parts[x]+" " } }
	return output
}

func Application_run(derr chan string, error_filepath string, commands []string) (chan bool, chan string) {
	derr<-"TOOLS/APP/RUN: "+String_array_stringify(commands)
	success_channel := make(chan bool, 2)
	return_channel := make(chan string, 2)
	go func(bool_channel chan bool, output_channel chan string) {
		for {
			error_file, err := os.Create(error_filepath)
			if err != nil { derr<-"TOOLS/APP/RUN: "+err.Error(); break }
			defer error_file.Close()
			cmd := exec.Command("./go")
			cmd.Stderr = error_file
			switch (len(commands)) {
				case 1: cmd = exec.Command(commands[0])
				case 2: cmd = exec.Command(commands[0], commands[1])
				case 3: cmd = exec.Command(commands[0], commands[1], commands[2])
				case 4: cmd = exec.Command(commands[0], commands[1], commands[2], commands[3])
				case 5: cmd = exec.Command(commands[0], commands[1], commands[2], commands[3], commands[4])
				default:	derr<-"TOOLS/APP/RUN: WRONG NUMBER OF COMMANDS"; break
			}
			start_err := cmd.Start()
			if start_err != nil { derr<-"TOOLS/APP/RUN: "+start_err.Error(); break }
			bool_channel <- true
			cmd.Wait()
			logfile := "!"
			logfile_bytes, err := ioutil.ReadFile(error_filepath)
			if err == nil {
				logfile = string(logfile_bytes)
				if len(logfile) > 600 { logfile = logfile[0:599] }
			}
			output_channel <- logfile
		}
		bool_channel <- false
	}(success_channel, return_channel)
	return success_channel, return_channel
}










