// Package authn turns a bearer token into an identity.
//
// Two kinds of token are accepted on the same endpoint:
//   - Bot tokens ("smcp_..."), issued by `ssh-mcp token create`, stored hashed,
//     expiring, revocable.
//   - Entra ID access tokens (OIDC JWTs) for people. Signature, issuer,
//     audience and expiry are verified against the tenant's published keys.
//     Group object IDs ("groups" claim) and app-role names ("roles" claim)
//     become the identity's groups.
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

// OIDCConfig configures people sign-in.
type OIDCConfig struct {
	// Issuer, e.g. https://login.microsoftonline.com/<tenant-id>/v2.0
	Issuer string `yaml:"issuer"`
	// Audience is the API's application ID URI or client ID.
	Audience string `yaml:"audience"`
	// RequiredScope, if set, must appear in the "scp" claim.
	RequiredScope string `yaml:"required_scope"`
	// TenantID must equal the token's "tid" claim.
	TenantID string `yaml:"tenant_id"`
}

// Authenticator verifies tokens.
type Authenticator struct {
	Store    *store.Store
	verifier *oidc.IDTokenVerifier
	scope    string
	tenant   string
}

// New builds an Authenticator. oidcCfg may be nil (bot tokens only).
func New(ctx context.Context, st *store.Store, oidcCfg *OIDCConfig) (*Authenticator, error) {
	a := &Authenticator{Store: st}
	if oidcCfg != nil && oidcCfg.Issuer != "" {
		if oidcCfg.Audience == "" || oidcCfg.TenantID == "" {
			return nil, errors.New("oidc.audience and oidc.tenant_id are required")
		}
		p, err := oidc.NewProvider(ctx, oidcCfg.Issuer)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", oidcCfg.Issuer, err)
		}
		a.verifier = p.Verifier(&oidc.Config{ClientID: oidcCfg.Audience})
		a.scope = oidcCfg.RequiredScope
		a.tenant = strings.ToLower(oidcCfg.TenantID)
	}
	return a, nil
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
	var claims struct {
		PreferredUsername string   `json:"preferred_username"`
		UPN               string   `json:"upn"`
		Email             string   `json:"email"`
		OID               string   `json:"oid"`
		TID               string   `json:"tid"`
		Groups            []string `json:"groups"`
		Roles             []string `json:"roles"`
		Scp               string   `json:"scp"`
	}
	if err := tok.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", auth.ErrInvalidToken, err)
	}
	if a.scope != "" && !hasScope(claims.Scp, a.scope) {
		return nil, fmt.Errorf("%w: missing scope %q", auth.ErrInvalidToken, a.scope)
	}
	// Authorization keys on the immutable object ID within our tenant only.
	// preferred_username/upn/email are mutable and used for display.
	if a.tenant == "" || !strings.EqualFold(claims.TID, a.tenant) {
		return nil, fmt.Errorf("%w: wrong tenant", auth.ErrInvalidToken)
	}
	oid := strings.ToLower(claims.OID)
	if _, err := identity.NormalizeKey(identity.KindUser + ":" + oid); err != nil {
		return nil, fmt.Errorf("%w: token has no valid oid", auth.ErrInvalidToken)
	}
	// Group overage (>200 groups) omits "groups"; the caller then simply
	// matches no group rules. That fails closed.
	groups := append(append([]string{}, claims.Groups...), claims.Roles...)
	id := identity.Identity{
		Kind: identity.KindUser, Name: oid, Groups: groups,
		Display: strings.ToLower(firstNonEmpty(claims.PreferredUsername, claims.UPN, claims.Email)),
	}
	return &auth.TokenInfo{UserID: id.Key(), Expiration: tok.Expiry, Extra: map[string]any{identityKey: id}}, nil
}

// FromTokenInfo extracts the identity set by Verify.
func FromTokenInfo(ti *auth.TokenInfo) (identity.Identity, bool) {
	if ti == nil {
		return identity.Identity{}, false
	}
	id, ok := ti.Extra[identityKey].(identity.Identity)
	return id, ok
}

func hasScope(scp, want string) bool {
	for _, s := range strings.Fields(scp) {
		if s == want {
			return true
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
