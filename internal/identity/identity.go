// Package identity carries the authenticated caller through a request.
package identity

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Kind of caller.
const (
	KindUser = "user"
	KindBot  = "bot"
)

// Identity is who is calling.
type Identity struct {
	Kind string
	// Name is the immutable subject for users (the Entra object ID, or the
	// configured subject claim of a generic OIDC provider), the token name
	// for bots. Policy rules, rate limits and the kill switch key on it.
	Name string
	// Display is a human label (UPN or email) for logs only. It is mutable
	// and never used for authorization.
	Display string
	Groups  []string
	// Client is the MCP client name reported at initialize, informational.
	Client string
}

// Key is the stable identifier used for policy, rate limits and kill switch.
func (i Identity) Key() string { return i.Kind + ":" + i.Name }

type ctxKey struct{}

// With stores id in ctx.
func With(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the identity in ctx.
func From(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

var (
	botNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	oidRe     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// subjectRe admits OIDC subjects such as Okta "00u1a2b3c4", Google
	// numeric IDs and Auth0 "auth0|abc". '@' is excluded so an email address
	// is never mistaken for a stable subject.
	subjectRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.|+=-]{0,254}$`)
)

// IsGUID reports whether s is a lowercase GUID (an Entra object ID).
func IsGUID(s string) bool { return oidRe.MatchString(s) }

// NormalizeKey validates an identity key typed by an admin ("bot:<name>" or
// "user:<subject>") and returns it in canonical form. A GUID subject is
// lowercased (Entra object IDs); other subjects are case-sensitive.
func NormalizeKey(k string) (string, error) {
	kind, name, ok := strings.Cut(strings.TrimSpace(k), ":")
	if !ok {
		return "", fmt.Errorf("identity %q: want bot:<name> or user:<subject>", k)
	}
	switch strings.ToLower(kind) {
	case KindBot:
		if !botNameRe.MatchString(name) {
			return "", fmt.Errorf("identity %q: bad bot name", k)
		}
		return KindBot + ":" + name, nil
	case KindUser:
		if n := strings.ToLower(name); oidRe.MatchString(n) {
			return KindUser + ":" + n, nil
		}
		if !subjectRe.MatchString(name) {
			return "", fmt.Errorf("identity %q: users are keyed by their immutable subject (Entra object ID or OIDC sub), not by name or email", k)
		}
		return KindUser + ":" + name, nil
	}
	return "", fmt.Errorf("identity %q: unknown kind %q", k, kind)
}
