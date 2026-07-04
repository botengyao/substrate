// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8sjwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAudience = "test-audience"

// fakeIssuer is an in-process OIDC issuer: it serves the discovery document
// and a mutable JWKS, and counts discovery fetches.
type fakeIssuer struct {
	server  *httptest.Server
	fetches atomic.Int64

	mu   sync.Mutex
	keys []jwkT
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		f.fetches.Add(1)
		writeJSON(t, w, oidcConfigT{JWKSURI: f.server.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(t, w, jwkSetT{Keys: f.keys})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// setKeys replaces the JWKS content, simulating key rotation.
func (f *fakeIssuer) setKeys(t *testing.T, keys ...*rsa.PrivateKey) {
	t.Helper()
	var jwks []jwkT
	for i, k := range keys {
		jwks = append(jwks, jwkT{
			KeyType: "RSA",
			KeyID:   keyID(i),
			RSAN:    base64.RawURLEncoding.EncodeToString(k.PublicKey.N.Bytes()),
			RSAE:    base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.PublicKey.E)).Bytes()),
		})
	}
	f.mu.Lock()
	f.keys = jwks
	f.mu.Unlock()
}

func keyID(i int) string {
	return fmt.Sprintf("key-%d", i)
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Errorf("encoding response: %v", err)
	}
}

func generateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	return key
}

// signJWT builds an RS256 Kubernetes-style JWT signed by key.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string, now time.Time) string {
	t.Helper()
	header, err := json.Marshal(parseHeader{Algorithm: "RS256", KeyID: kid})
	if err != nil {
		t.Fatalf("marshaling header: %v", err)
	}
	claims, err := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": "system:serviceaccount:default:test",
		"aud": audience,
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"iat": now.Unix(),
	})
	if err != nil {
		t.Fatalf("marshaling claims: %v", err)
	}
	toBeSigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := hashBytes(crypto.SHA256.New(), []byte(toBeSigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		t.Fatalf("signing JWT: %v", err)
	}
	return toBeSigned + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func TestVerifier_ValidToken(t *testing.T) {
	issuer := newFakeIssuer(t)
	key := generateKey(t)
	issuer.setKeys(t, key)
	now := time.Now()

	v := NewVerifier(nil)
	jwt := signJWT(t, key, keyID(0), issuer.server.URL, testAudience, now)
	claims, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "system:serviceaccount:default:test" {
		t.Errorf("unexpected subject %q", claims.Subject)
	}
}

func TestVerifier_CachesKeysAcrossRequests(t *testing.T) {
	issuer := newFakeIssuer(t)
	key := generateKey(t)
	issuer.setKeys(t, key)
	now := time.Now()

	v := NewVerifier(nil)
	for i := range 5 {
		jwt := signJWT(t, key, keyID(0), issuer.server.URL, testAudience, now)
		if _, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now); err != nil {
			t.Fatalf("Verify #%d: %v", i, err)
		}
	}
	if got := issuer.fetches.Load(); got != 1 {
		t.Errorf("issuer fetched %d times for 5 verifications, want 1", got)
	}
}

func TestVerifier_RefetchesOnKeyRotation(t *testing.T) {
	issuer := newFakeIssuer(t)
	oldKey := generateKey(t)
	issuer.setKeys(t, oldKey)
	now := time.Now()

	v := NewVerifier(nil)
	jwt := signJWT(t, oldKey, keyID(0), issuer.server.URL, testAudience, now)
	if _, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now); err != nil {
		t.Fatalf("Verify with old key: %v", err)
	}

	// Rotate: new JWKS holds both keys, tokens are now signed by key-1.
	newKey := generateKey(t)
	issuer.setKeys(t, oldKey, newKey)
	later := now.Add(keyRefetchInterval + time.Second)
	jwt = signJWT(t, newKey, keyID(1), issuer.server.URL, testAudience, later)
	if _, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, later); err != nil {
		t.Fatalf("Verify with rotated key: %v", err)
	}
	if got := issuer.fetches.Load(); got != 2 {
		t.Errorf("issuer fetched %d times, want 2 (initial + rotation)", got)
	}
}

func TestVerifier_UnknownKeyIDRefetchIsThrottled(t *testing.T) {
	issuer := newFakeIssuer(t)
	key := generateKey(t)
	issuer.setKeys(t, key)
	now := time.Now()

	v := NewVerifier(nil)
	jwt := signJWT(t, key, keyID(0), issuer.server.URL, testAudience, now)
	if _, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// A burst of tokens with a bogus key ID must not cause a fetch per
	// request: within the throttle window they fail without refetching.
	bogus := signJWT(t, key, "no-such-kid", issuer.server.URL, testAudience, now)
	for range 5 {
		soon := now.Add(time.Second)
		if _, err := v.Verify(context.Background(), bogus, issuer.server.URL, testAudience, soon); err == nil {
			t.Fatal("Verify with bogus key ID unexpectedly succeeded")
		}
	}
	if got := issuer.fetches.Load(); got != 1 {
		t.Errorf("issuer fetched %d times during bogus-kid burst, want 1", got)
	}

	// Once the window passes, one refetch happens (and still fails).
	later := now.Add(keyRefetchInterval + time.Second)
	if _, err := v.Verify(context.Background(), bogus, issuer.server.URL, testAudience, later); err == nil {
		t.Fatal("Verify with bogus key ID unexpectedly succeeded")
	}
	if got := issuer.fetches.Load(); got != 2 {
		t.Errorf("issuer fetched %d times after throttle window, want 2", got)
	}
}

func TestVerifier_RejectsBadSignature(t *testing.T) {
	issuer := newFakeIssuer(t)
	key := generateKey(t)
	issuer.setKeys(t, key)
	now := time.Now()

	v := NewVerifier(nil)
	// Signed by an unrelated key but claiming the served key's ID.
	jwt := signJWT(t, generateKey(t), keyID(0), issuer.server.URL, testAudience, now)
	if _, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now); err == nil {
		t.Fatal("Verify unexpectedly accepted a forged signature")
	}
}

func TestVerifier_RejectsWrongAudience(t *testing.T) {
	issuer := newFakeIssuer(t)
	key := generateKey(t)
	issuer.setKeys(t, key)
	now := time.Now()

	v := NewVerifier(nil)
	jwt := signJWT(t, key, keyID(0), issuer.server.URL, "other-audience", now)
	_, err := v.Verify(context.Background(), jwt, issuer.server.URL, testAudience, now)
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("Verify = %v, want audience error", err)
	}
}
