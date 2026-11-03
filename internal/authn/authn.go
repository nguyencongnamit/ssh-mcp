// Package authn turns a bearer token into an identity.
//
// Two kinds of token are accepted on the same endpoint:
//   - Bot tokens ("smcp_..."), issued by `ssh-mcp token create`, stored hashed,
//     expiring, revocable.
//   - OIDC access or ID tokens (JWTs) for people. Signature, issuer, audience
//     and expiry are verified against the issuer's published keys.
//     With provider "entra" (the default when tenant_id is set) the caller
//     is keyed on the immutable object ID within one tenant, and group
//     object IDs ("groups") and app-role names ("roles") become groups.
//     With provider "generic" (Okta, Keycloak, Google, Auth0, ...) the
//     claims are configurable; the subject defaults to "sub".
package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"

	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
)

// Providers.
const (
	ProviderEntra   = "entra"
	ProviderGeneric = "generic"
)

// OIDCConfig configures people sign-in.
type OIDCConfig struct {
	// Provider is "entra" or "generic". Empty means entra when TenantID is
	// set, generic otherwise.
	Provider string `yaml:"provider"`
	// Issuer, e.g. https://login.microsoftonline.com/<tenant-id>/v2.0
	Issuer string `yaml:"issuer"`
	// Audience is the API's application ID URI or client ID. It must be in
	// the token's "aud" claim.
	Audience string `yaml:"audience"`
	// RequiredScope, if set, must appear in the "scp" or "scope" claim.
	RequiredScope string `yaml:"required_scope"`
	// TenantID must equal the token's "tid" claim (entra only).
	TenantID string `yaml:"tenant_id"`

	// Generic provider claim names. A dotted name reads a nested claim, for
	// example "realm_access.roles" on Keycloak.
	SubjectClaim  string `yaml:"subject_claim"`  // default "sub"; must be immutable
	GroupsClaim   string `yaml:"groups_claim"`   // default "groups"
	UsernameClaim string `yaml:"username_claim"` // default "preferred_username", then "email"
}

// Authenticator verifies tokens.
type Authenticator struct {
	Store    *store.Store
	verifier *oidc.IDTokenVerifier
	scope    string
	tenant   string
	provider string
	subject  string
	groups   string
	username string
}

// New builds an Authenticator. oidcCfg may be nil (bot tokens only).
func New(ctx context.Context, st *store.Store, oidcCfg *OIDCConfig) (*Authenticator, error) {
	a := &Authenticator{Store: st}
	if oidcCfg != nil && oidcCfg.Issuer != "" {
		if err := a.configure(oidcCfg); err != nil {
			return nil, err
		}
		p, err := oidc.NewProvider(ctx, oidcCfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", oidcCfg.Issuer, err)
		}
		a.verifier = p.Verifier(&oidc.Config{ClientID: oidcCfg.Audience})
	}
	return a, nil
}

// configure validates the OIDC settings and fills in defaults.
func (a *Authenticator) configure(c *OIDCConfig) error {
	a.provider = strings.ToLower(c.Provider)
	if a.provider == "" {
		a.provider = ProviderGeneric
		if c.TenantID != "" {
			a.provider = ProviderEntra
		}
	}
	if c.Audience == "" {
		return errors.New("oidc.audience is required")
	}
	switch a.provider {
	case ProviderEntra:
		if c.TenantID == "" {
			return errors.New("oidc.tenant_id is required for provider entra")
		}
		if c.SubjectClaim != "" || c.GroupsClaim != "" || c.UsernameClaim != "" {
			return errors.New("oidc.*_claim settings apply to provider generic only")
		}
		a.tenant = strings.ToLower(c.TenantID)
	case ProviderGeneric:
		if c.TenantID != "" {
			return errors.New("oidc.tenant_id applies to provider entra only")
		}
		a.subject = orDefault(c.SubjectClaim, "sub")
		a.groups = orDefault(c.GroupsClaim, "groups")
		a.username = c.UsernameClaim
	default:
		return fmt.Errorf("oidc.provider %q: want entra or generic", c.Provider)
	}
	a.scope = c.RequiredScope
	return nil
}

// identityKey is where the identity rides inside auth.TokenInfo.Extra.
const identityKey = "ssh-mcp.identity"

// Verify implements auth.TokenVerifier.
func (a *Authenticator) Verify(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if strings.HasPrefix(token, store.TokenPrefix) {
		name, exp, err := a.Store.LookupToken(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
		}
		id := identity.Identity{Kind: identity.KindBot, Name: name}
		return &auth.TokenInfo{UserID: id.Key(), Expiration: exp, Extra: map[string]any{identityKey: id}}, nil
	}
	if a.verifier == nil {
		return nil, fmt.Errorf("%w: unknown token type", auth.ErrInvalidToken)
	}
	tok, err := a.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	var raw map[string]any
	if err := tok.Claims(&raw); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", auth.ErrInvalidToken, err)
	}
	id, err := a.identityFrom(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", auth.ErrInvalidToken, err)
	}
	return &auth.TokenInfo{UserID: id.Key(), Expiration: tok.Expiry, Extra: map[string]any{identityKey: id}}, nil
}

// identityFrom maps verified claims to an identity. Signature, issuer,
// audience and expiry have already been checked.
func (a *Authenticator) identityFrom(c map[string]any) (identity.Identity, error) {
	if a.scope != "" && !hasScope(c, a.scope) {
		return identity.Identity{}, fmt.Errorf("missing scope %q", a.scope)
	}
	if a.provider == ProviderEntra {
		// Authorization keys on the immutable object ID within our tenant
		// only. preferred_username/upn/email are mutable, for display.
		tid, _ := c["tid"].(string)
		if a.tenant == "" || !strings.EqualFold(tid, a.tenant) {
			return identity.Identity{}, errors.New("wrong tenant")
		}
		oid, _ := c["oid"].(string)
		oid = strings.ToLower(oid)
		if _, err := identity.NormalizeKey(identity.KindUser + ":" + oid); err != nil || !identity.IsGUID(oid) {
			return identity.Identity{}, errors.New("token has no valid oid")
		}
		// Group overage (>200 groups) omits "groups"; the caller then
		// matches no group rules. That fails closed.
		groups := append(strList(c["groups"]), strList(c["roles"])...)
		return identity.Identity{
			Kind: identity.KindUser, Name: oid, Groups: groups,
			Display: strings.ToLower(firstNonEmpty(str(c["preferred_username"]), str(c["upn"]), str(c["email"]))),
		}, nil
	}
	sub := str(claim(c, a.subject))
	if _, err := identity.NormalizeKey(identity.KindUser + ":" + sub); err != nil {
		return identity.Identity{}, fmt.Errorf("claim %q is not a usable subject", a.subject)
	}
	display := str(claim(c, a.username))
	if a.username == "" {
		display = firstNonEmpty(str(c["preferred_username"]), str(c["email"]))
	}
	return identity.Identity{
		Kind: identity.KindUser, Name: sub, Groups: strList(claim(c, a.groups)),
		Display: strings.ToLower(display),
	}, nil
}

// claim reads a possibly dotted claim name from nested objects.
func claim(c map[string]any, name string) any {
	if name == "" {
		return nil
	}
	if v, ok := c[name]; ok {
		return v
	}
	var cur any = c
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// strList accepts a JSON array of strings or a single string.
func strList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// FromTokenInfo extracts the identity set by Verify.
func FromTokenInfo(ti *auth.TokenInfo) (identity.Identity, bool) {
	if ti == nil {
		return identity.Identity{}, false
	}
	id, ok := ti.Extra[identityKey].(identity.Identity)
	return id, ok
}

// hasScope looks in "scp" (Entra, Okta: string or array) and "scope"
// (RFC 9068: space-separated string).
func hasScope(c map[string]any, want string) bool {
	for _, k := range []string{"scp", "scope"} {
		var have []string
		if s, ok := c[k].(string); ok {
			have = strings.Fields(s)
		} else {
			have = strList(c[k])
		}
		for _, s := range have {
			if s == want {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
