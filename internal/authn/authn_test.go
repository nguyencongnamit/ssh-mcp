package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

// issuer is a minimal OIDC provider: discovery document plus JWKS.
type issuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	is := &issuer{key: k}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": is.srv.URL, "jwks_uri": is.srv.URL + "/keys",
			"authorization_endpoint": is.srv.URL + "/auth", "token_endpoint": is.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	is.srv = httptest.NewServer(mux)
	t.Cleanup(is.srv.Close)
	return is
}

func (is *issuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	base := map[string]any{"iss": is.srv.URL, "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
	for k, v := range claims {
		base[k] = v
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: is.key},
		(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(base)
	obj, err := sig.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := obj.CompactSerialize()
	return s
}

const (
	tenant = "11111111-2222-3333-4444-555555555555"
	oid    = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

func verify(t *testing.T, a *Authenticator, tok string) (string, []string, error) {
	t.Helper()
	ti, err := a.Verify(context.Background(), tok, nil)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Fatalf("error does not wrap ErrInvalidToken: %v", err)
		}
		return "", nil, err
	}
	id, ok := FromTokenInfo(ti)
	if !ok {
		t.Fatal("no identity in token info")
	}
	return id.Key(), id.Groups, nil
}

func TestEntra(t *testing.T) {
	is := newIssuer(t)
	a, err := New(context.Background(), nil, &OIDCConfig{Issuer: is.srv.URL, Audience: "api://ssh-mcp", TenantID: tenant, RequiredScope: "Diagnose"})
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]any{"aud": "api://ssh-mcp", "tid": tenant, "oid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
		"scp": "Diagnose Other", "groups": []string{"g1"}, "roles": []string{"Oncall"}, "preferred_username": "Alice@Example.test"}
	key, groups, err := verify(t, a, is.sign(t, good))
	if err != nil || key != "user:"+oid || len(groups) != 2 {
		t.Fatalf("good token: key=%q groups=%v err=%v", key, groups, err)
	}
	for name, mut := range map[string]map[string]any{
		"wrong tenant":   {"tid": "99999999-2222-3333-4444-555555555555"},
		"wrong audience": {"aud": "api://other"},
		"missing scope":  {"scp": "Other"},
		"oid not a GUID": {"oid": "alice"},
		"expired":        {"exp": time.Now().Add(-time.Hour).Unix()},
	} {
		c := map[string]any{}
		for k, v := range good {
			c[k] = v
		}
		for k, v := range mut {
			c[k] = v
		}
		if _, _, err := verify(t, a, is.sign(t, c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenericDefaults(t *testing.T) {
	is := newIssuer(t)
	a, err := New(context.Background(), nil, &OIDCConfig{Issuer: is.srv.URL, Audience: "api://default", RequiredScope: "ssh-mcp"})
	if err != nil {
		t.Fatal(err)
	}
	if a.provider != ProviderGeneric {
		t.Fatalf("provider = %q, want generic when tenant_id is empty", a.provider)
	}
	// Okta-style: case-sensitive sub, scp as an array, groups as names.
	key, groups, err := verify(t, a, is.sign(t, map[string]any{
		"aud": []string{"api://default"}, "sub": "00uAbC123xyz", "scp": []string{"openid", "ssh-mcp"},
		"groups": []string{"oncall"}, "email": "bob@example.test"}))
	if err != nil || key != "user:00uAbC123xyz" || len(groups) != 1 || groups[0] != "oncall" {
		t.Fatalf("okta-style token: key=%q groups=%v err=%v", key, groups, err)
	}
	// RFC 9068 "scope" string works too.
	if _, _, err := verify(t, a, is.sign(t, map[string]any{"aud": "api://default", "sub": "x1", "scope": "openid ssh-mcp"})); err != nil {
		t.Fatalf("scope string: %v", err)
	}
	for name, c := range map[string]map[string]any{
		"no scope":         {"aud": "api://default", "sub": "x1"},
		"email as subject": {"aud": "api://default", "sub": "bob@example.test", "scope": "ssh-mcp"},
		"missing subject":  {"aud": "api://default", "scope": "ssh-mcp"},
		"wrong audience":   {"aud": "account", "sub": "x1", "scope": "ssh-mcp"},
	} {
		if _, _, err := verify(t, a, is.sign(t, c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestGenericNestedClaims(t *testing.T) {
	is := newIssuer(t)
	// Keycloak-style: roles nested under realm_access.
	a, err := New(context.Background(), nil, &OIDCConfig{Provider: "generic", Issuer: is.srv.URL, Audience: "ssh-mcp",
		GroupsClaim: "realm_access.roles", UsernameClaim: "preferred_username"})
	if err != nil {
		t.Fatal(err)
	}
	key, groups, err := verify(t, a, is.sign(t, map[string]any{"aud": "ssh-mcp",
		"sub": "f3c1e2d4-0000-4000-8000-000000000001", "realm_access": map[string]any{"roles": []string{"sre", "dev"}}}))
	if err != nil || key != "user:f3c1e2d4-0000-4000-8000-000000000001" || len(groups) != 2 {
		t.Fatalf("keycloak-style token: key=%q groups=%v err=%v", key, groups, err)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, c := range map[string]OIDCConfig{
		"no audience":           {Issuer: "x"},
		"entra without tenant":  {Provider: "entra", Issuer: "x", Audience: "a"},
		"entra with claim knob": {Issuer: "x", Audience: "a", TenantID: tenant, GroupsClaim: "roles"},
		"generic with tenant":   {Provider: "generic", Issuer: "x", Audience: "a", TenantID: tenant},
		"unknown provider":      {Provider: "okta", Issuer: "x", Audience: "a"},
	} {
		if err := (&Authenticator{}).configure(&c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
