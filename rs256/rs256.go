package rs256

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"net/http"
	"os"
)

var keyCache = make(map[string][]byte)

func FetchRsaPublicKey(url string) (*rsa.PublicKey, error) {
	var k *rsa.PublicKey

	r, err := http.Get(url)
	if err != nil {
		return k, err
	}

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return k, err
	}

	return x509.ParsePKCS1PublicKey(raw)
}

func HashDigest(b []byte) []byte {
	hash := sha256.New()
	hash.Write(b)
	return hash.Sum(nil)
}

func Signature(b []byte, priv *rsa.PrivateKey) []byte {
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, HashDigest(b), nil)

	if err != nil {
		panic(err)
	}

	return sig
}

func VerifySignature(b, sig []byte, pub *rsa.PublicKey) bool {
	return rsa.VerifyPSS(pub, crypto.SHA256, HashDigest(b), sig, nil) == nil
}

func ParsePrivateBytes(b []byte) *rsa.PrivateKey {
	k, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		panic(err)
	}

	return k
}

func GeneratePrivateKey() (k *rsa.PrivateKey) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return
}

func MarshallPrivateKey(k *rsa.PrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(k)
}

func ParsePublicBytes(b []byte) *rsa.PublicKey {
	k, err := x509.ParsePKCS1PublicKey(b)
	if err != nil {
		panic(err)
	}

	return k
}

func MarshallPublicKey(k *rsa.PublicKey) []byte {
	return x509.MarshalPKCS1PublicKey(k)
}

// load the key or create one if none exists
func LoadKeyBytes(fp string) ([]byte, error) {
	if bytes, ok := keyCache[fp]; ok {
		return bytes, nil
	}

	// create a new private key if it is not at the location
	if _, err := os.Stat(fp); os.IsNotExist(err) {
		k := GeneratePrivateKey()
		b := MarshallPrivateKey(k)
		err := SaveBytes(b, fp)

		if err != nil {
			panic(err)
		}
	}

	f, err := os.Open(fp)

	if err != nil {
		return []byte{}, err
	}

	defer f.Close()

	bytes, err := io.ReadAll(f)

	if err != nil {
		return []byte{}, err
	}

	keyCache[fp] = bytes

	return bytes, nil
}

func SaveBytes(b []byte, fp string) error {
	f, err := os.Create(fp)

	if err != nil {
		panic(err)
	}

	defer f.Close()

	_, err = f.Write(b)

	if err != nil {
		panic(err)
	}

	return nil
}
