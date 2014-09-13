package tools

import (
		"fmt"
		"os"
		"os/exec"
		"io/ioutil"
		"time"
//		"errors"
		"strings"
		"strconv"
		"bytes"
		"net/url"
		"net/http"
		"crypto/rsa"
		"crypto/aes"
		"crypto/cipher"
		"crypto/elliptic"
		"crypto/ecdsa"
		"encoding/gob"
		"encoding/json"
		"encoding/xml"
		"encoding/base64"
//		"encoding/asn1"
		"encoding/hex"
		"crypto/sha1"
		"crypto/sha256"
		"crypto/sha512"
		"crypto/rand"
		"crypto/x509"
		"github.com/bmizerany/pat"
		"github.com/kennygrant/sanitize"
		"code.google.com/p/go.crypto/scrypt"
		"code.google.com/p/go.net/websocket"
		"github.com/mitchellh/mapstructure"
		"github.com/golangdaddy/go-multi-logger"
		"runtime"
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

func (keystore *KeyStore) Recover(derr chan string, secret_key string) (bool, *ecdsa.PrivateKey, *rsa.PrivateKey) {
	derr<-"TOOLS/KEYSTORE/RECOVER: USING KEY "+SHA_1(secret_key)
	for {
		if len(keystore.EncryptedPrivateKey) == 0 { derr<-"KEYSTORE SEEMS TO BE EMPTY"; break }
		ok, crypt_bytes := Decode_base64(derr, keystore.EncryptedPrivateKey); if !ok { break }
		ok, plain_text := Crypt_aes(derr, false, secret_key, crypt_bytes); if !ok { derr<-"TOOLS/KEYSTORE/RECOVER CANT DECRYPT"; break }
		if keystore.ID == "ECDSA" {	private_key, err := x509.ParseECPrivateKey(plain_text); if err == nil { return true, private_key, nil }; derr<-"TOOLS/RECOVER/ECDSA: "+err.Error() }
		if keystore.ID == "RSA" { private_key, err := x509.ParsePKCS1PrivateKey(plain_text); if err == nil { return true, nil, private_key }; derr<-"TOOLS/KEYSTORE/RECOVER: "+err.Error() }
		derr<-string(plain_text); derr<-keystore.EncryptedPrivateKey; break
	}
	derr<-"TOOLS/KEYSTORE/RECOVER "+keystore.ID+" FAILED"; return false, nil, nil
}

type EasyTime struct {
	Zone, Day_Name, Month_Name string
	Year, Month, Day int
	Hour, Minute, Second int
}

func (et *EasyTime) New() *EasyTime { return Time_easy() }

func Time_easy() *EasyTime {
	t := time.Now()
	zone, _ := t.Zone()
	day_name := t.Weekday()
	month_name := t.Month()
	return &EasyTime{zone, day_name.String(), month_name.String(), t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second()}	
}

var entropychannel chan chan string

func ID_weak() string {	id, _ := SHA(1, 0, Entropy64(), nil); return id }

func ID_strong() string { id, _ := SHA(2, 64, Entropy64(), nil); return id }

func Entropy64() string {
	if entropychannel == nil { entropychannel = make(chan chan string, 9); go entropy_generator() }
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
	if thelength < 0 { const layout = "Jan 2, 2006 at 3:04pm (GMT)"; return(t.Format(layout)) }
	if thelength > 0 { req := t.Format("20060102150405"); return(req[0:thelength]) }
	return(t.Format("20060102150405"))
}

// ECDSA

func Sign_gethash(derr chan string, object interface{}) (bool, []byte) {
	ok, encoded_object_bytes := Encode_json(derr, object); if ok { _, object_hash := SHA(2, 64, "", encoded_object_bytes); return true, object_hash }
	derr<-"TOOLS/SIGN/GETHASH: FAILED"; return false, nil
}

func Sign_ecdsa(derr chan string, private_key *ecdsa.PrivateKey, object map[string]interface{}) (bool, []string) {
	for {
		ok, object_hash := Sign_gethash(derr, object); if !ok { break }
		if private_key == nil { derr<-"TOOLS/SIGN/ECDSA PRIVATE KEY IS NIL"; break }
		a, b, err := ecdsa.Sign(rand.Reader, private_key, object_hash)
		if err != nil {	derr<-"TOOLS/SIGN/ECDSA: "+err.Error(); break }
		return true, []string{a.String(), b.String()}
	}
	derr<-"TOOLS/SIGN/ECDSA FAILED"; return false, nil
}

// KEYGEN

func Generate_openssl(derr chan string, key_length int, secret_key string) (bool,*KeyStore) {
	keyfile := "temp_rsa.key"
	derr<-"GETTING A NEW RSA KEY FROM OPENSSL"
	for {
		cmd := exec.Command("openssl", "genrsa", "-out", keyfile, IntToString(key_length))
		_, rsaerr := cmd.CombinedOutput()
		if rsaerr != nil { derr<-"ERROR LAUNCHING OPENSSL"; break }
		cmd = exec.Command("openssl", "rsa", "-in", keyfile, "-out", keyfile+".der", "-outform", "DER")
		_, rsaerr = cmd.CombinedOutput(); if rsaerr != nil { derr<-"ERROR CONVERTING OPENSSL KEY"; break }
		ok, privatekeyfile := File_read_bytes(derr, keyfile+".der"); if !ok { break }
		private_key, err := x509.ParsePKCS1PrivateKey(privatekeyfile); if err != nil { derr<-"ERROR OPENING OPENSSL PRIVATE KEY"; break }
		ok, new_keystore := keystore_privatekey(derr, private_key, "RSA", secret_key); if !ok { break }
		cmd = exec.Command("openssl", "rsa", "-in", keyfile, "-pubout")
		publickey, rsa_err := cmd.CombinedOutput(); if rsa_err != nil { derr<-"ERROR OPENING OPENSSL PRIVATE KEY"; break }
		kkk := strings.Replace(string(publickey), "\n", "", -1)
		kk := strings.Split(kkk, "-")
		for k := range kk { if len(kk[k]) > 99 { new_keystore.EncodedPublicKey = kk[k] } }
		return true, new_keystore
	}
	derr<-"OPENSSL FAILED TO GENERATE NEW RSA KEY"; return false, nil
}

func Generate_ecdsa(derr chan string, secret_key string) (bool, *KeyStore) {
	derr<-"TOOLS/KEYGEN/ECDSA CREATING NEW KEYSTORE"
	for {
		private_key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader); if err != nil { derr<-"TOOLS/KEYGEN/ECDSA: "+err.Error(); break }
		ok, new_keystore := keystore_privatekey(derr, private_key, "ECDSA", secret_key); if !ok { break }
		return true, new_keystore
	}
	derr<-"TOOLS/KEYGEN/ECDSA FAILED"; return false, nil
}

func Generate_rsa(derr chan string, key_length int, secret_key string) (bool, *KeyStore) {
	derr<-"TOOLS/KEYGEN/RSA: CREATING NEW KEYSTORE "+IntToString(key_length)
	for {
		private_key, err := rsa.GenerateKey(rand.Reader, key_length); if err != nil { derr<-"TOOLS/KEYGEN/RSA: "+err.Error(); break }
		ok, new_keystore := keystore_privatekey(derr, private_key, "RSA", secret_key); if !ok { break }
		return true, new_keystore
	}
	derr<-"TOOLS/KEYGEN/RSA: FAILED"; return false, nil
}
	
func keystore_privatekey(derr chan string, private_key interface{}, key_id, secret_key string) (bool, *KeyStore) {
	for {
		keystore := &KeyStore{}
		keystore.ID = key_id
		if key_id == "ECDSA" {
			pk, ok := private_key.(*ecdsa.PrivateKey); if !ok { derr<-"TOOLS/NEW/KEYSTORE INTERFACE FAIL"; break }
			encoded_public_key, err := x509.MarshalPKIXPublicKey(pk.PublicKey); if err != nil { derr<-"TOOLS/NEW/KEYSTORE: "+err.Error(); break }
			encoded_private_key, err := x509.MarshalECPrivateKey(pk); if err != nil { derr<-"X509 FAILED"; break }
			ok, ciphertext := Crypt_aes(derr, true, secret_key, encoded_private_key); if !ok { break }
			keystore.EncryptedPrivateKey = Encode_base64(ciphertext)
			keystore.EncodedPublicKey = Encode_base64(encoded_public_key)		
		}
		if key_id == "RSA" {
			pk, ok := private_key.(*rsa.PrivateKey); if !ok { derr<-"TOOLS/NEW/KEYSTORE INTERFACE FAIL"; break }
			encoded_public_key, err := x509.MarshalPKIXPublicKey(pk.PublicKey); if err != nil { derr<-"TOOLS/NEW/KEYSTORE: "+err.Error(); break }
			encoded_private_key := x509.MarshalPKCS1PrivateKey(pk)
			ok, ciphertext := Crypt_aes(derr, true, secret_key, encoded_private_key); if !ok { break }
			keystore.EncryptedPrivateKey = Encode_base64(ciphertext)
			keystore.EncodedPublicKey = Encode_base64(encoded_public_key)
		}
		keystore.PublicKeyHash = SHA_256(keystore.EncodedPublicKey)	
		return true, keystore
	}
	derr<-"FAILED TO STORE "+key_id+" KEY IN KEYSTORE"; return false, nil
}	

// RSA encrypt / decrypt bytes

func Encrypt_rsa_encoded(derr chan string, public_key_encoded string, data interface{}) (bool, *CryptObject) {
	ok, key_bytes := Decode_base64(derr, public_key_encoded)
	if ok { new_key := &rsa.PublicKey{}; if Decode_gob(derr, key_bytes, new_key) { return Encrypt_rsa(derr, new_key, data) } }
	return false, nil
}

func Encrypt_rsa(derr chan string, public_key *rsa.PublicKey, data interface{}) (bool, *CryptObject) {
	for {
		aes_key := Entropy64()
		cipher_bytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, public_key, []byte(aes_key), []byte(""))
		if err != nil { derr<-err.Error(); break }
		cryptobject := &CryptObject{}
		cryptobject.Time = Time_now(0)
		cryptobject.Protected = Encode_base64(cipher_bytes)
		enc_ok, encoded_object := Encode_gob(derr, data); if !enc_ok { break }
		crypt_ok, ciphertext_bytes := Crypt_aes(derr, true, aes_key, encoded_object); if !crypt_ok { break }
		cryptobject.Crypt = Encode_base64(ciphertext_bytes)
		return true, cryptobject
	}
	derr<-"TOOLS/RSA/ENCRYPT: FAILED"
	return false, nil
}

func Decrypt_rsa(derr chan string, private_key *rsa.PrivateKey, c *CryptObject, dest interface{}) bool {
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

func Crypt_aes_cbc(derr chan string, encrypt bool, password, input_text, iv []byte) (bool, []byte) {
	c, err := aes.NewCipher(password)
	if err != nil { derr<-"TOOLS/AES/CBC "+err.Error(); return false, nil }
	if encrypt {
		encoded := "<<<<<<<<<<<<<<<<"+Encode_base64(input_text)
		for ii := 0; (len(encoded) % 16) != 0; ii++ { encoded = "<" + encoded }
		buf := make([]byte, len(encoded))
		crypter := cipher.NewCBCEncrypter(c, iv)
		crypter.CryptBlocks(buf, []byte(encoded))
		return true, buf
	}
	crypter := cipher.NewCBCDecrypter(c, iv)
	crypter.CryptBlocks(input_text, input_text)
	serialized := strings.Replace(string(input_text)[16:], "<", "", -1)
	ok, decoded_bytes := Decode_base64(derr, serialized); if !ok { return false, nil }
	return true, decoded_bytes
}

// AES encrypt/decrypt
		
func Crypt_aes(derr chan string, encrypt bool, password string, input_text []byte) (bool, []byte) {
	_, password_bytes := SHA(2, 32, password, nil)
	_, iv := SHA(2, 16, password, nil)
	return Crypt_aes_cbc(derr, encrypt, password_bytes, input_text, iv)
}
			
/// HASHING

func Digest_valid(derr chan string, digest string) bool {
	switch(len(digest)) {
		case 40: break
		case 64: break
		case 128: break
		default:
			derr<-"DIGEST INVALID, LENGTH "+IntToString(len(digest)); return false
	}
	ok, _ := Decode_hex(derr, digest); if ok { return true }
	derr<-"DIGEST INVALID, HEX DECODE FAILED"; return false
}

func Digest_object_quick(derr chan string, object interface{}) (bool, []byte) {
	ok, encoded := Encode_gob(derr, object)
	if !ok { return false, nil }; _, digest := SHA(3, 128, "", encoded)
	return true, digest
}

func Digest_object_gob(derr chan string, object interface{}) (bool, string) {
	ok, encoded := Encode_gob(derr, object)
	if !ok { return false, "" }; digest, _ := SHA(3, 128, "", encoded)
	return true, digest
}

func Digest_object_json(derr chan string, object interface{}) (bool, string) {
	ok, encoded := Encode_json(derr, object)
	if !ok { return false, "" }; digest, _ := SHA(3, 128, "", encoded)
	return true, digest
}

func Scrypt_128(derr chan string, input string) (bool, []byte) { return Scrypt(derr, input, 32) }
func Scrypt_256(derr chan string, input string) (bool, []byte) { return Scrypt(derr, input, 64) }
func Scrypt_512(derr chan string, input string) (bool, []byte) { return Scrypt(derr, input, 128) }

func Scrypt(derr chan string, input string, hash_length int) (bool, []byte) {
	_, h := SHA(3, 32, input, nil)
	if hash_length == 0 { derr<-"HASH LENGTH NEEDS TO BE BIGGER THAN ZERO"; return false, nil }
	b, err := scrypt.Key([]byte(input), h, 16384, 8, 1, hash_length)
	if err != nil { derr<-"TOOLS/SCRYPT: "+err.Error(); return false, nil }
	return true, b
}

func SHA_1(input string) string { h, _ := SHA(1, 0, input, nil); return h }
func SHA_256(input string) string { h, _ := SHA(2, 64, input, nil); return h }
func SHA_512(input string) string { h, _ := SHA(2, 128, input, nil); return h }
func SHA_3_256(input string) string { h, _ := SHA(3, 64, input, nil); return h }
func SHA_3_512(input string) string { h, _ := SHA(3, 128, input, nil); return h }

func SHA(i, l int, s string, b []byte) (string, []byte) {
	hash := sha1.New()
	if b != nil { s += string(b) }
	if l > 128 { l = 128 }
	switch(i) {
		case 1:	if l > 0 { l = 0 }
		case 2: if l <= 64 { hash = sha256.New() } else { hash = sha512.New() }
		//case 3: if l <= 64 { hash = sha3.NewKeccak256() } else { hash = sha3.NewKeccak512() }
		case 3: if l <= 64 { hash = sha256.New() } else { hash = sha512.New() }
		default: hash = sha256.New()
	}
	hash.Write([]byte(s))
	output := hash.Sum(nil)
	if i > 1 { if l < len(output) { output = output[0:l] } }
	return hex.EncodeToString(output), output
}

// MAPSTRUCTURE map[string]interface{} to struct, see github.com/mitchellh/mapstructure

func Decode_struct(derr chan string, src, dest interface{}) bool {
	err := mapstructure.Decode(src, dest); if err != nil { derr<-"TOOLS/DECODE/STRUCT: "+err.Error(); return false }; return true
}

// XML

func Encode_xml(derr chan string, i interface{}) (bool, []byte) {
	b, e := xml.Marshal(i)
	if e != nil { derr<-"TOOLS/XML/ENCODE: "+e.Error(); return false, nil }
	return true, b
}

func Decode_xml(derr chan string, b []byte, i interface{}) bool {
	e := xml.Unmarshal(b, i)
	if e != nil { derr<-"TOOLS/XML/DECODE: "+e.Error(); return false }
	return true
}
		
// JSON marshalling

func Encode_json(derr chan string, i interface{}) (bool, []byte) {
	b, e := json.Marshal(i)
	if e != nil { derr<-"TOOLS/JSON/ENCODE: "+e.Error(); return false, nil }
	return true, b
}

func Decode_json(derr chan string, b []byte, i interface{}) bool {
	e := json.Unmarshal(b, i)
	if e != nil { derr<-"TOOLS/JSON/DECODE: "+e.Error(); return false }
	return true
}

// BASE64 encoding
		
func Encode_base64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func Decode_base64(derr chan string, s string) (bool, []byte) {
	data, e := base64.StdEncoding.DecodeString(s)
    if e != nil { derr<-"TOOLS/BASE64/DECODE: "+s+" : "+e.Error(); return false, nil }
    return true, data
}		

// HEX encoding

func Encode_hex(b []byte) string { return hex.EncodeToString(b) }

func Decode_hex(derr chan string, s string) (bool, []byte) {
	b, e := hex.DecodeString(s)
	if e != nil { derr<-"TOOLS/HEX/DECODE: "+e.Error(); return false, nil }
	return true, b
}

// GOB marshalling		
		
func Encode_gob(derr chan string, input interface{}) (bool, []byte) {
	if input == nil { derr<-"TOOLS/GOB/ENCODE: INPUT INTERFACE IS NIL"; return false, nil }
	encoded := new(bytes.Buffer)
	encCache := gob.NewEncoder(encoded)
	encCache.Encode(input)
	return true, encoded.Bytes()
}

func Decode_gob(derr chan string, input []byte, data interface{}) bool {
	dCache := bytes.NewBuffer(input)
	decCache := gob.NewDecoder(dCache)
	e := decCache.Decode(data)
	if e != nil || data == nil { derr<-"TOOLS/GOB/DECODE: "+e.Error(); return false }
	return true
}

// MISC

func File_dir_list(derr chan string, path string) (bool, []string) {
	files, dir_err := ioutil.ReadDir(path)
	if dir_err != nil {	derr<-"TOOLS/DIR/LIST: "+dir_err.Error(); return false, nil }
	newlist := []string{}
	for _, f := range files { newlist = append(newlist, f.Name()) }
	return true, newlist
}

func File_write_string(derr chan string, file_path, payload string) bool {
	f, err := os.Create(file_path); defer f.Close();
	if err == nil { f.Write([]byte(payload)); return true }
	derr<-"TOOLS/FILE/WRITE/STRING: "+err.Error(); return false
}

func File_write_bytes(derr chan string, file_path string, payload []byte) bool {
	f, err := os.Create(file_path); defer f.Close();
	if err == nil { f.Write(payload); return true }
	derr<-"TOOLS/FILE/WRITE/BYTES: "+err.Error(); return false
}

func File_read_bytes(derr chan string, path string) (bool, []byte) {
	file_bytes, err := ioutil.ReadFile(path)
	if err != nil { derr<-err.Error(); return false, nil }
	return true, file_bytes
}

func File_read_string(derr chan string, path string) (bool, string) {
	file_bytes, err := ioutil.ReadFile(path)
	if err != nil { derr<-err.Error(); return false, "" }
	return true, string(file_bytes)
}

func File_makepath(derr chan string, path string) bool {
	if len(path) == 0 { derr<-"TOOLS/FILE/MAKEPATH PATH NOT SUPPLIED"; return false }
	parts := strings.Split(path, "/")
	prog := ""
	for p := range parts {
		if len(parts[p]) < 1 { continue }
		prog += parts[p]+"/"
		os.Mkdir(prog, 0700);
	}
	derr<-"CREATED DIRECTORIES "+path
	return true
}

func URL_post(derr chan string, target_url string, values_map map[string]string) (bool, string) {
	client := &http.Client{}
	values := make(url.Values)
	for k, v := range values_map { values.Set(k, v) }
	request, _ := http.NewRequest("POST", target_url, strings.NewReader(values.Encode()))
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	response, do_err := client.Do(request)
	if do_err != nil { derr<-"TOOLS/URL/POST: "+do_err.Error(); return false, "" }
	defer response.Body.Close()
	server_response, err := ioutil.ReadAll(response.Body)
	if err != nil { derr<-"TOOLS/URL/POST: "+do_err.Error(); return false, "" }
	return true, string(server_response)
}

func URL_get(derr chan string, url string) (bool, string) { ok, b := URL_get_bytes(derr, url); if ok { return true, string(b) }; return false, "" }
func URL_get_bytes(derr chan string, url string) (bool, []byte) {
	for {
		resp, err := http.Get(url)
		if resp != nil { if resp.Body != nil { defer resp.Body.Close() } }
		if err != nil || resp == nil { derr<-"TOOLS/URL/GET: "+err.Error(); break }
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil || body == nil { derr<-"TOOLS/URL/GET: "+err.Error(); break }
		return true, body
	}
	derr<-"TOOLS/URL/GET FAILED TO GET RESOURCE"
	return false, nil
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

func Socket_http(derr chan string, routes []string, handler_function func(http.ResponseWriter, *http.Request)) string {
	derr<-"TOOLS/SOCKET/HTTP STARTING NEW SERVER"
	mux := pat.New()
	for _, route := range routes {
		if string(route[0]) != "/" { Quit_slow(derr, "TOOLS/SOCKET/HTTP INVALID ROUTE SUPPLIED ("+route+")") }
		mux.Get(route, http.HandlerFunc(handler_function))
	}
	http_err := http.ListenAndServe(":80", mux)
	if http_err != nil { return "TOOLS/SOCKET/HTTP: "+http_err.Error() }
	return "TOOLS/SOCKET/HTTP UNEXPECTEDLY CLOSED"
}

func Socket_open(derr chan string, ssl bool, route string, port int, ssl_certpath, ssl_keypath string, handlerfunc func(*websocket.Conn)) {
	port_string := ":"+IntToString(port)
	if string(route[0]) != "/" { route = "/"+route }
	derr<-"TOOLS/SOCKET/OPEN: "+port_string+route
	http.Handle(route, websocket.Handler(handlerfunc))
	go func() {
		if ssl {
			err := http.ListenAndServeTLS(port_string, ssl_certpath, ssl_keypath, nil)
			if err != nil { derr<-"TOOLS/SOCKET/OPEN: "+err.Error() }
		} else {
			err := http.ListenAndServe(port_string, nil)
			if err != nil { derr<-"TOOLS/SOCKET/OPEN: "+err.Error() }
		}
		derr<-"TOOLS/SOCKET/OPEN: CLOSED SOCKET "+port_string+route
	}()
}

func Socket_dial(derr chan string, url, origin string) (bool, *websocket.Conn) {
	ws, err := websocket.Dial(url, "", origin)
	if err != nil { derr<-"TOOLS/SOCKET/DIAL: "+err.Error(); return false, nil }
	return true, ws
}

// STRINGS

func IntToString(i int) string { return strconv.Itoa(i) }

func String_array_stringify(parts []string) string {
	output := ""
	for x := range parts { if len(parts[x]) > 0 { output += parts[x]+" " } }
	return output
}

func Application_run(derr chan string, error_filepath string, commands []string) (chan bool) {
	success_channel := make(chan bool, 2)
	go func(derr chan string, bool_channel chan bool) {
		for {
			error_file, err := os.Create(error_filepath)
			if err != nil { derr<-"TOOLS/APP/RUN: "+err.Error(); break }
			defer error_file.Close()
			cmd := exec.Command("./go")
			switch (len(commands)) {
				case 1: cmd = exec.Command(commands[0])
				case 2: cmd = exec.Command(commands[0], commands[1])
				case 3: cmd = exec.Command(commands[0], commands[1], commands[2])
				case 4: cmd = exec.Command(commands[0], commands[1], commands[2], commands[3])
				case 5: cmd = exec.Command(commands[0], commands[1], commands[2], commands[3], commands[4])
				default:	derr<-"TOOLS/APP/RUN WRONG NUMBER OF COMMANDS"; break
			}
			cmd.Stderr = error_file
			derr<-"TOOLS/APP/RUN STARTING APPLICATION..."
			derr<-"TOOLS/APP/RUN "+String_array_stringify(cmd.Args)
			start_err := cmd.Start()
			if start_err != nil { derr<-"TOOLS/APP/RUN: "+start_err.Error(); break }
			bool_channel <- true
			derr<-"TOOLS/APP/RUN WAITING FOR APP TO FINISH..."; 
			err = cmd.Wait(); derr<-"PROGRAM HAS FINISHED"
			ok, output_bytes := File_read_string(derr, error_filepath)
			if ok { if len(output_bytes) > 0 { derr<-"TOOLS/APP/RUN(OUTPUT) "+string(output_bytes); bool_channel <- false; return }; bool_channel <- true; return }
			derr<-"TOOLS/APP/RUN: "+err.Error(); return
		}
		bool_channel <- false
	}(derr, success_channel)
	return success_channel
}

func CharSet_select(set_type string) string {
	switch(set_type) {
		case "base58": return "AaBbCcDdEeFfGgHhiJjKkLMmNnoPpQqRrSsTtUuVvWwXxYyZz987654321"
		case "int": return "0987654321"
		case "float": return "-0.987654321"
		case "alpha_lower": return "abcdefghijklmnopqrstuvwxyz"
		case "alpha_upper": return "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		case "alpha": return CharSet_select("alpha_lower") + CharSet_select("alpha_upper")
		case "beta": return CharSet_select("alpha")+":/&=$£*#!?',;() _@"+CharSet_select("float")
	}
	return "!"
}

func Sleep(seconds int) { for seconds > 0 { seconds--; time.Sleep(time.Second) } } 

func Format_float(f float64, l int) string { return(strconv.FormatFloat(f, 'f', l, 64)) }
func Logger(devmode, ssl bool, host string, port_num int, route, appid, origin string) *mlog.MultiLogger { return mlog.Connect(devmode, ssl, host, port_num, route, appid, origin) }
func Print(s string) { fmt.Println(s) }
func Serve(res http.ResponseWriter, s string) { fmt.Fprintf(res, "%v", s) }
func Uppercase(s string) string { return strings.ToUpper(s) }
func Lowercase(s string) string { return strings.ToLower(s) }
func MaxCPU() { runtime.GOMAXPROCS(runtime.NumCPU()) }
func Parse_sanitize(input string) string { return strings.ToLower(sanitize.HTML(input)) }

func Parse_safe(derr chan string, in string) (bool, string) {
	derrp := "TOOLS/PARSE/SAFE: "
	input := in
	in = strings.ToLower(sanitize.HTML(in))
	if len(in) < 40 && len(in) > 0 {
		in = strings.Replace(in, " ", "", -1)
		for ch := range in { if !strings.Contains(CharSet_select("alpha_lower"), string(in[ch])) { derr<-derrp+"UNSAFE INPUT CHARACTERS"; return false, "" } }
		if in == input { return true, input }
	}
	derr<-derrp+"ABORTED EVIL INPUT ("+in+")"; return false, ""
}

func Parse_email(derr chan string, email string) bool {
	for {
		if len(email) < 6 { break }
		if len(email) > 100 { break }
		if !strings.Contains(email, "@") { break }
		if !strings.Contains(email, ".") { break }
		s := strings.Split(email, "@")
		if len(s) != 2 { break }
		s = strings.Split(email, ".")
		if len(s) < 2 { break }
		emailset := "@_-+"+CharSet_select("alpha")+CharSet_select("float")
		for x := range email { if !strings.Contains(emailset, string(email[x])) { derr<-"EMAIL DOESNT MATCH EMAIL CHARSET"; return(false) } }
		return(true)
	}
	return(false)
}
