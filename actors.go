package jwt

import (
	"crypto/rsa"
	b64 "encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/gosqueak/jwt/rs256"
)

type Audience struct {
	pub  *rsa.PublicKey
	Name string
}

func NewAudience(pub *rsa.PublicKey, indentifier string) Audience {
	return Audience{pub, indentifier}
}

func (a Audience) IsValid(jwt Jwt) bool {
	if jwt.Body.Audience != a.Name || jwt.Expired() {
		return false
	}

	return rs256.VerifySignature(
		append(toBytes(jwt.Header), toBytes(jwt.Body)...),
		jwt.Signature,
		a.pub,
	)
}

type Issuer struct {
	priv *rsa.PrivateKey
	Name string
}

func NewIssuer(priv *rsa.PrivateKey, indentifier string) Issuer {
	return Issuer{priv, indentifier}
}

func (i Issuer) PublicKey() *rsa.PublicKey {
	return &i.priv.PublicKey
}

func (i Issuer) MintToken(sub, aud string, duration time.Duration) Jwt {
	exp := strconv.Itoa(int(time.Now().Add(duration).Unix()))

	return Jwt{
		Header{Alg, Typ},
		Body{sub, aud, i.Name, exp, NewJwtId()},
		[]byte{},
	}
}

// this method is non-deterministic
func (i Issuer) StringifyJwt(jwt Jwt) string {
	enc := b64.RawURLEncoding

	var parts = make([]string, 0, 3)

	h := toBytes(jwt.Header)
	b := toBytes(jwt.Body)

	parts = append(parts,
		enc.EncodeToString(h),
		enc.EncodeToString(b),
		enc.EncodeToString(rs256.Signature(append(h, b...), i.priv)),
	)

	return strings.Join(parts, ".")
}
