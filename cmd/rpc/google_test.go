package rpc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/canopy-network/canopy/lib"
	"github.com/julienschmidt/httprouter"
)

// testGoogleProvider spins up a local 'Google like' OAuth provider returning signed id tokens
type testGoogleProvider struct {
	privateKey *rsa.PrivateKey
	authURL    string
	tokenURL   string
	jwksURL    string
	server     *httptest.Server
}

// newTestGoogleProvider() starts a local provider whose jwks is backed by a fresh RSA key
func newTestGoogleProvider(t *testing.T) *testGoogleProvider {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	p := &testGoogleProvider{privateKey: privateKey}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			// mimic the consent page: redirect straight back with a code
			http.Redirect(w, r, "http://callback?code=test-code&state="+r.URL.Query().Get("state"), http.StatusFound)
		case "/token":
			bz, err := json.Marshal(map[string]string{
				"access_token": "test-access-token",
				"id_token":     p.idToken("test-client"),
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(bz)
		case "/jwks":
			bz, err := json.Marshal(map[string]any{
				"keys": []map[string]string{{
					"kty": "RSA",
					"kid": "test-key",
					"use": "sig",
					"n":   base64.RawURLEncoding.EncodeToString(p.privateKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.privateKey.PublicKey.E)).Bytes()),
				}},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(bz)
		default:
			http.NotFound(w, r)
		}
	}))
	p.authURL = p.server.URL + "/auth"
	p.tokenURL = p.server.URL + "/token"
	p.jwksURL = p.server.URL + "/jwks"
	t.Cleanup(p.server.Close)
	return p
}

// idToken() returns a signed RS256 id token for the given audience
func (p *testGoogleProvider) idToken(audience string) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key"})
	claims, _ := json.Marshal(map[string]any{
		"iss": googleIssuer,
		"aud": audience,
		"exp": time.Now().Add(time.Hour).Unix(),
		"nbf": time.Now().Unix(),
	})
	return p.sign(header, claims)
}

// sign() base64url encodes and RS256 signs the two JWT parts
func (p *testGoogleProvider) sign(header, claims []byte) string {
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// testServer() returns an rpc server configured against the local provider
func testServer(t *testing.T, p *testGoogleProvider) *Server {
	t.Helper()
	config := lib.DefaultConfig()
	config.GoogleClientId = "test-client"
	config.GoogleClientSecret = "test-secret"
	config.GoogleRedirectURL = "http://callback"
	config.GoogleEndpointsOverride = lib.GoogleEndpointsOverride{
		AuthURL:  p.authURL,
		TokenURL: p.tokenURL,
		JWKSURL:  p.jwksURL,
	}
	return &Server{
		config:         config,
		logger:         lib.NewDefaultLogger(),
		googleSessions: newGoogleSessionStore(),
		googleStates:   newGoogleLoginStates(),
	}
}

// reSign() replaces the token claims, mutates them and re-signs the token
func reSign(t *testing.T, token string, mutate func(claims map[string]any)) string {
	t.Helper()
	parts := strings.Split(token, ".")
	claimsBz, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err = json.Unmarshal(claimsBz, &claims); err != nil {
		t.Fatal(err)
	}
	mutate(claims)
	if claimsBz, err = json.Marshal(claims); err != nil {
		t.Fatal(err)
	}
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(claimsBz) + "." + parts[2]
}

// tamperClaims() flips a byte inside the claims part breaking the signature
func tamperClaims(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	claims[0] ^= 0xFF
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(claims) + "." + parts[2]
}

// TestVerifyIDToken covers the happy path and the rejection paths of id token verification
func TestVerifyIDToken(t *testing.T) {
	p := newTestGoogleProvider(t)
	valid := p.idToken("test-client")

	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{"valid token", valid, false},
		{"malformed token", "not-a-token", true},
		{"tampered claims", tamperClaims(t, valid), true},
		{"expired", reSign(t, valid, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), true},
		{"wrong audience", reSign(t, valid, func(c map[string]any) { c["aud"] = "other-client" }), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims, err := verifyIDToken(test.token, p.jwksURL, "test-client")
			if test.wantErr != (err != nil) {
				t.Fatalf("verifyIDToken() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && claims.Audience != "test-client" {
				t.Fatalf("unexpected audience %q", claims.Audience)
			}
		})
	}
}

// TestGoogleLoginFlow covers the login redirect, the code exchange and the session lookup
func TestGoogleLoginFlow(t *testing.T) {
	p := newTestGoogleProvider(t)
	s := testServer(t, p)

	// an unconfigured server must bounce the user back to the wallet with an error message
	unconfigured := &Server{
		config:         lib.DefaultConfig(),
		logger:         lib.NewDefaultLogger(),
		googleSessions: newGoogleSessionStore(),
		googleStates:   newGoogleLoginStates(),
	}
	recorder := httptest.NewRecorder()
	unconfigured.GoogleLogin(recorder, httptest.NewRequest(http.MethodGet, GoogleLoginRoutePath, nil), httprouter.Params{})
	if recorder.Code != http.StatusFound {
		t.Fatalf("GoogleLogin() status = %d, want %d", recorder.Code, http.StatusFound)
	}
	if location := recorder.Header().Get("Location"); !strings.Contains(location, "googleError=") {
		t.Fatalf("GoogleLogin() location = %q, want a googleError redirect", location)
	}

	// a configured server must redirect to the consent page with an anti-forgery state
	recorder = httptest.NewRecorder()
	s.GoogleLogin(recorder, httptest.NewRequest(http.MethodGet, GoogleLoginRoutePath, nil), httprouter.Params{})
	if recorder.Code != http.StatusFound {
		t.Fatalf("GoogleLogin() status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing GoogleLogin() location: %v", err)
	}
	if location.Query().Get("client_id") != "test-client" {
		t.Fatalf("GoogleLogin() client_id = %q, want test-client", location.Query().Get("client_id"))
	}
	state := location.Query().Get("state")
	if state == "" {
		t.Fatal("GoogleLogin() missing state")
	}

	// the callback exchanges the code, verifies the id token and creates a session
	recorder = httptest.NewRecorder()
	s.GoogleCallback(recorder, httptest.NewRequest(http.MethodGet, GoogleCallbackRoutePath+"?code=test-code&state="+state, nil), httprouter.Params{})
	if recorder.Code != http.StatusFound {
		t.Fatalf("GoogleCallback() status = %d, want %d", recorder.Code, http.StatusFound)
	}
	location, err = url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing GoogleCallback() location: %v", err)
	}
	sessionToken := location.Query().Get("googleSession")
	if sessionToken == "" {
		t.Fatalf("GoogleCallback() location = %q, want a googleSession redirect", recorder.Header().Get("Location"))
	}

	// the session endpoint must resolve the token into the authenticated user
	recorder = httptest.NewRecorder()
	s.GoogleSession(recorder, httptest.NewRequest(http.MethodGet, GoogleSessionRoutePath+"?token="+sessionToken, nil), httprouter.Params{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("GoogleSession() status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var user googleUser
	if err = json.Unmarshal(recorder.Body.Bytes(), &user); err != nil {
		t.Fatalf("unmarshaling session response: %v", err)
	}

	// an unknown or replayed token must be rejected
	recorder = httptest.NewRecorder()
	s.GoogleSession(recorder, httptest.NewRequest(http.MethodGet, GoogleSessionRoutePath+"?token=unknown", nil), httprouter.Params{})
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("GoogleSession(unknown) status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}

	// replaying the callback with the same state must be rejected
	recorder = httptest.NewRecorder()
	s.GoogleCallback(recorder, httptest.NewRequest(http.MethodGet, GoogleCallbackRoutePath+"?code=test-code&state="+state, nil), httprouter.Params{})
	if location := recorder.Header().Get("Location"); !strings.Contains(location, "googleError=") {
		t.Fatalf("GoogleCallback(replay) location = %q, want a googleError redirect", location)
	}

	// the anti-forgery state is single use
	if s.googleStates.consume(state) {
		t.Fatal("state was not consumed")
	}
}

// TestGoogleSessionStore covers session expiry
func TestGoogleSessionStore(t *testing.T) {
	store := newGoogleSessionStore()
	token := store.create(googleUser{Email: "user@example.com", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if _, ok := store.get(token); !ok {
		t.Fatal("get(valid token) = false, want true")
	}
	expired := store.create(googleUser{Email: "user@example.com", ExpiresAt: time.Now().Add(-time.Hour).Unix()})
	if _, ok := store.get(expired); ok {
		t.Fatal("get(expired token) = true, want false")
	}
}
