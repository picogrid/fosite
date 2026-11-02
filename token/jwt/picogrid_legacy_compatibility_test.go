// Copyright © 2026 Picogrid
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// This fixture was signed with go-jose/v3 v3.0.5 CompactSerialize, independently
// of this fork. Only the public key is retained; expiry is 2100-01-01.
const legacyJOSE3CompactToken = `eyJhbGciOiJSUzI1NiIsImtpZCI6ImxlZ2FjeS1qb3NlLXYzIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiaHR0cHM6Ly9sZWdpb24uZXhhbXBsZS9pbnRlZ3JhdGlvbiJdLCJleHAiOjQxMDI0NDQ4MDAsImV4dHJhIjp7ImNvdW50IjozLCJsYWJlbCI6InVuaXQtw7EifSwiaWF0IjoxNzA0MDY3MjAwLCJuYmYiOjE3MDQwNjcyMDAsIm9yZ2FuaXphdGlvbl9pZCI6ImxlZ2FjeS1vcmciLCJzY29wZSI6IiIsInN1YiI6ImludGVncmF0aW9uOmxlZ2FjeSJ9.Jwh9xIvlen6AvXspgSLSqITutEly91AELWcbt1_6jK7GUn4AZoyDsTAELrcF6zsgiYQGNrVvOhN5XEs7IX4V08Dh1caooTg4sI3qXBDAY96RIib1UoVQJTDLnyX3FhzBwT2eS-cNIVLzhh6sK_BOhs6UDft2Ivf-lQqdQqmRFOemhInk2DiyleNNYCPhP29LVKbSZsAa5AonyjyIDmZKNCAaB71wcPRkroeT8D81JOUY5jcq6ZR5-lA6iSnSW4KInlDe6gitLefyZL4fF6nzlrzqsEKSiy9GnXt2KoEFoHoR-xCF86uoMJ6FLqbvzv7-xp31QDFczbmUbMmInbg4aA`
const legacyJOSE3PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxrkc8ujyrEz1QMZvPNJN
XsBd7s1MnMIzzj/OFblf0s1+FvZ9VvJcHcbz+wJZRG5MYxX7MdIjlLTwOAcosi0j
l7ol3Utf4eaeyZkaWoM/KLRSVbzL/Q7m0pKq0l59fwe76dANKmIcpSkCBh6mHxg3
3PSimMLA7OVK94VCBs2wHWM948z0H2skssQ39YuIPcz8c2jDWdIGFVA9WMM5QdoW
0KTp3GbKnmrqF/Oa3/3R7vWeCKpHf2KiKfy4jc6WFtPqhheBpJ4kFZBXfH3EfAJI
SN9jVxDNshljmp9ntHcQ6Vr2NHqEDQZCBcYnDjCnvaTz9LrLDQ27wM6ToOsx4guj
TQIDAQAB
-----END PUBLIC KEY-----
`

func TestPicogridLegacyJOSE3RS256TokenRemainsValid(t *testing.T) {
	block, _ := pem.Decode([]byte(legacyJOSE3PublicKey))
	if block == nil {
		t.Fatal("invalid test public key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseWithClaims(legacyJOSE3CompactToken, MapClaims{}, func(token *Token) (interface{}, error) {
		if token.Method != jose.RS256 || token.Header["kid"] != "legacy-jose-v3" {
			t.Fatal("legacy algorithm or key ID changed")
		}
		return key, nil
	})
	if err != nil || !parsed.Valid() {
		t.Fatalf("legacy token rejected: %v", err)
	}
	if parsed.Claims["sub"] != "integration:legacy" || parsed.Claims["organization_id"] != "legacy-org" || parsed.Claims["scope"] != "" {
		t.Fatalf("legacy claims changed: %#v", parsed.Claims)
	}
	if !parsed.Claims.VerifyAudience("https://legion.example/integration", true) || !parsed.Claims.VerifyExpiresAt(4102444799, true) {
		t.Fatal("legacy audience or numeric dates changed")
	}
	extra, ok := parsed.Claims["extra"].(map[string]interface{})
	if !ok || extra["label"] != "unit-ñ" || extra["count"] != int64(3) {
		t.Fatalf("legacy JSON claims changed: %#v", extra)
	}
	parts := strings.Split(legacyJOSE3CompactToken, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker"}`))
	if _, err := Parse(strings.Join(parts, "."), func(*Token) (interface{}, error) { return key, nil }); err == nil {
		t.Fatal("tampered legacy payload accepted")
	}
}

func TestPicogridRS256OutputVerifiesWithStandardLibrary(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	token := NewWithClaims(jose.RS256, MapClaims{"sub": "integration:new", "organization_id": "new-org", "exp": int64(4102444800), "scope": ""})
	token.Header["kid"] = "legion-oauth-key"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("non-compact token: %d parts", len(parts))
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "integration:new" || claims["organization_id"] != "new-org" || claims["scope"] != "" || claims["exp"] != float64(4102444800) {
		t.Fatalf("wire claims changed: %#v", claims)
	}
}
