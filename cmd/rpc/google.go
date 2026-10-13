package rpc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/canopy-network/canopy/lib"
	"github.com/julienschmidt/httprouter"
)

/* This file implements 'Sign in with Google' OAuth 2.0 login for the web wallet */

const (
	// the hard coded Google OAuth 2.0 endpoints (may be overridden in the config for testing)
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleJWKSURL  = "https://www.googleapis.com/oauth2/v3/certs"

	// the issuer values Google puts inside its id tokens
	googleIssuer  = "https://accounts.google.com"
	googleIssuer2 = "accounts.google.com"

	// googleLoginStateLifetimeMS is how long a login state value may sit unused before it expires
	googleLoginStateLifetimeMS = 10 * 60 * 1000

	// googleSessionLifetime is how long a completed login stays valid
	googleSessionLifetime = 24 * time.Hour
)

// googleUser is the authenticated identity extracted from a verified Google id token
type googleUser struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Picture   string `json:"picture"`
	ExpiresAt int64  `json:"expiresAt"`
}

// googleSessionStore holds the authenticated Google users keyed by an opaque session token
type googleSessionStore struct {
	mux      sync.Mutex
	sessions map[string]googleUser
}

// newGoogleSessionStore() returns an empty session store
func newGoogleSessionStore() *googleSessionStore {
	return &googleSessionStore{sessions: make(map[string]googleUser)}
}

// create() generates a new session token for the user and stores it
func (g *googleSessionStore) create(user googleUser) (token string) {
	token = randomToken()
	g.mux.Lock()
	defer g.mux.Unlock()
	// purge expired sessions so the map does not grow without bound
	for t, u := range g.sessions {
		if time.Now().Unix() > u.ExpiresAt {
			delete(g.sessions, t)
		}
	}
	g.sessions[token] = user
	return
}

// get() returns the user behind the token if the session is still valid
func (g *googleSessionStore) get(token string) (user googleUser, ok bool) {
	g.mux.Lock()
	defer g.mux.Unlock()
	user, ok = g.sessions[token]
	if !ok {
		return
	}
	if time.Now().Unix() > user.ExpiresAt {
		delete(g.sessions, token)
		return googleUser{}, false
	}
	return
}

// googleLoginStates holds single-use anti-forgery state values keyed by the value itself
type googleLoginStates struct {
	mux    sync.Mutex
	states map[string]time.Time
}

// newGoogleLoginStates() returns an empty login state store
func newGoogleLoginStates() *googleLoginStates {
	return &googleLoginStates{states: make(map[string]time.Time)}
}

// create() generates a new anti-forgery state value
func (g *googleLoginStates) create() (state string) {
	state = randomToken()
	g.mux.Lock()
	defer g.mux.Unlock()
	// purge expired states so the map does not grow without bound
	for s, expiry := range g.states {
		if time.Now().After(expiry) {
			delete(g.states, s)
		}
	}
	g.states[state] = time.Now().Add(googleLoginStateLifetimeMS * time.Millisecond)
	return
}

// consume() validates and deletes a state value returning true if it was fresh
func (g *googleLoginStates) consume(state string) (ok bool) {
	g.mux.Lock()
	defer g.mux.Unlock()
	expiry, found := g.states[state]
	if !found {
		return
	}
	delete(g.states, state)
	return time.Now().Before(expiry)
}

// randomToken() returns a cryptographically secure random hex string
func randomToken() string {
	bz := make([]byte, 32)
	if _, err := rand.Read(bz); err != nil {
		panic(err)
	}
	return hex.EncodeToString(bz)
}

// googleEndpoints() returns the OAuth endpoints honoring the config override
func (s *Server) googleEndpoints() (authURL, tokenURL, jwksURL string) {
	authURL, tokenURL, jwksURL = googleAuthURL, googleTokenURL, googleJWKSURL
	if o := s.config.GoogleEndpointsOverride; o.AuthURL != "" {
		authURL = o.AuthURL
	}
	if o := s.config.GoogleEndpointsOverride; o.TokenURL != "" {
		tokenURL = o.TokenURL
	}
	if o := s.config.GoogleEndpointsOverride; o.JWKSURL != "" {
		jwksURL = o.JWKSURL
	}
	return
}

// googleRedirectURL() returns the redirect url registered for the OAuth client
func (s *Server) googleRedirectURL() string {
	if s.config.GoogleRedirectURL != "" {
		return s.config.GoogleRedirectURL
	}
	return strings.TrimSuffix(s.config.AdminRPCUrl, "/") + GoogleCallbackRoutePath
}

// walletBaseURL() returns the public url of the web wallet derived from the admin rpc url
func (s *Server) walletBaseURL() string {
	if u, err := url.Parse(s.config.AdminRPCUrl); err == nil && u.Host != "" {
		u.Host = fmt.Sprintf("%s:%s", u.Hostname(), s.config.WalletPort)
		return strings.TrimSuffix(u.String(), "/")
	}
	return "http://localhost:" + s.config.WalletPort
}

// GoogleLogin redirects the browser to the Google OAuth consent page
func (s *Server) GoogleLogin(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if !s.config.GoogleOAuthConfigured() {
		http.Redirect(w, r, s.walletBaseURL()+"?googleError="+
			url.QueryEscape("Google login is not configured on this node"), http.StatusFound)
		return
	}
	// generate the anti-forgery state and send the user to the consent page
	authURL, _, _ := s.googleEndpoints()
	state := s.googleStates.create()
	redirect := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		authURL,
		url.QueryEscape(s.config.GoogleClientId),
		url.QueryEscape(s.googleRedirectURL()),
		url.QueryEscape("openid email profile"),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// GoogleCallback completes the OAuth login: it exchanges the code for tokens, verifies the
// id token and redirects the browser back to the web wallet with a session token
func (s *Server) GoogleCallback(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	params := r.URL.Query()
	// send the user back to the wallet with a readable error message
	fail := func(msg string) {
		http.Redirect(w, r, s.walletBaseURL()+"?googleError="+url.QueryEscape(msg), http.StatusFound)
	}
	// Google signals a user-side failure such as a denied consent
	if errParam := params.Get("error"); errParam != "" {
		fail("Google sign in failed: " + errParam)
		return
	}
	// the state must match the one generated during GoogleLogin
	if !s.googleStates.consume(params.Get("state")) {
		fail("Google sign in failed: invalid state")
		return
	}
	// exchange the authorization code for tokens
	idToken, err := s.exchangeGoogleCode(params.Get("code"))
	if err != nil {
		s.logger.Errorf("google code exchange failed: %s", err.Error())
		fail("Google sign in failed: invalid authorization code")
		return
	}
	// verify the id token signature and claims
	claims, err := s.verifyGoogleIDToken(idToken)
	if err != nil {
		s.logger.Errorf("google id token verification failed: %s", err.Error())
		fail("Google sign in failed: could not verify identity")
		return
	}
	// create the wallet session and hand it back to the wallet
	token := s.googleSessions.create(googleUser{
		Email:     claims.Email,
		Name:      claims.Name,
		Picture:   claims.Picture,
		ExpiresAt: time.Now().Add(googleSessionLifetime).Unix(),
	})
	http.Redirect(w, r, s.walletBaseURL()+"?googleSession="+token, http.StatusFound)
}

// GoogleSession responds with the authenticated Google user behind a session token
func (s *Server) GoogleSession(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	user, ok := s.googleSessions.get(r.URL.Query().Get("token"))
	if !ok {
		write(w, lib.NewError(lib.NoCode, lib.RPCModule, "invalid or expired google session"), http.StatusUnauthorized)
		return
	}
	write(w, user, http.StatusOK)
}

// exchangeGoogleCode swaps the OAuth authorization code for the id token
func (s *Server) exchangeGoogleCode(code string) (idToken string, err error) {
	if code == "" {
		return "", errors.New("empty authorization code")
	}
	_, tokenURL, _ := s.googleEndpoints()
	form := url.Values{
		"code":          {code},
		"client_id":     {s.config.GoogleClientId},
		"client_secret": {s.config.GoogleClientSecret},
		"redirect_uri":  {s.googleRedirectURL()},
		"grant_type":    {"authorization_code"},
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).PostForm(tokenURL, form)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	bz, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bz))
	}
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	if err = json.Unmarshal(bz, &tokenResponse); err != nil {
		return "", err
	}
	if tokenResponse.IDToken == "" {
		return "", errors.New("token response missing id_token")
	}
	return tokenResponse.IDToken, nil
}

// googleIDTokenClaims is the subset of claims of a Google id token relevant for the wallet login
type googleIDTokenClaims struct {
	Issuer   string `json:"iss"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Picture  string `json:"picture"`
}

// verifyGoogleIDToken validates the RS256 signature against the provider JWKS and the standard claims
func (s *Server) verifyGoogleIDToken(idToken string) (claims *googleIDTokenClaims, err error) {
	_, _, jwksURL := s.googleEndpoints()
	claims, err = verifyIDToken(idToken, jwksURL, s.config.GoogleClientId)
	if err != nil {
		return nil, err
	}
	if claims.Issuer != googleIssuer && claims.Issuer != googleIssuer2 {
		return nil, fmt.Errorf("unexpected issuer %q", claims.Issuer)
	}
	return claims, nil
}

// verifyIDToken parses and verifies a signed JWT issued for [clientID] using the keys at [jwksURL]
func verifyIDToken(idToken, jwksURL, clientID string) (claims *googleIDTokenClaims, err error) {
	// a JWT is three base64url encoded parts separated by dots
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed id token")
	}
	// decode the header and ensure the algorithm is RS256
	headerBz, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("malformed id token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err = json.Unmarshal(headerBz, &header); err != nil {
		return nil, fmt.Errorf("malformed id token header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported id token algorithm %q", header.Alg)
	}
	// fetch the JSON Web Key Set and pick the signing key
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetching jwks failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	bz, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}
	var keySet struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err = json.Unmarshal(bz, &keySet); err != nil {
		return nil, fmt.Errorf("malformed jwks: %w", err)
	}
	// decode the modulus and exponent of the matching key into a public key
	var signingKey *rsa.PublicKey
	for _, k := range keySet.Keys {
		if k.Kid != header.Kid || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("malformed jwks modulus: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("malformed jwks exponent: %w", err)
		}
		signingKey = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		break
	}
	if signingKey == nil {
		return nil, errors.New("no matching signing key")
	}
	// verify the PKCS#1 v1.5 signature over the signed content
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("malformed id token signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(signingKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, fmt.Errorf("id token signature verification failed: %w", err)
	}
	// decode and validate the claims
	claimsBz, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("malformed id token claims: %w", err)
	}
	claims = new(googleIDTokenClaims)
	if err = json.Unmarshal(claimsBz, claims); err != nil {
		return nil, fmt.Errorf("malformed id token claims: %w", err)
	}
	if claims.Expiry <= time.Now().Unix() {
		return nil, errors.New("id token expired")
	}
	if claims.Audience != clientID {
		return nil, fmt.Errorf("unexpected audience %q", claims.Audience)
	}
	return claims, nil
}
