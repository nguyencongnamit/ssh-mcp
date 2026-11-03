package identity

import "testing"

func TestNormalizeKey(t *testing.T) {
	ok := map[string]string{
		"bot:triage-bot": "bot:triage-bot",
		"user:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE": "user:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", // Entra oid: lowercased
		"user:00uAbC123xyz":                         "user:00uAbC123xyz",                         // Okta sub: case kept
		"user:auth0|5f7c8ec7c33c6c":                 "user:auth0|5f7c8ec7c33c6c",
		"user:104857364829173645201":                "user:104857364829173645201", // Google
		" USER:00uAbC123xyz ":                       "user:00uAbC123xyz",
	}
	for in, want := range ok {
		got, err := NormalizeKey(in)
		if err != nil || got != want {
			t.Errorf("NormalizeKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"alice", "user:alice@example.test", "user:", "user:-x", "user:a b", "user:a/b",
		"bot:", "bot:a b", "group:x", "user:" + string(make([]byte, 300)),
	} {
		if got, err := NormalizeKey(in); err == nil {
			t.Errorf("NormalizeKey(%q) = %q, want error", in, got)
		}
	}
}

func TestContext(t *testing.T) {
	if _, ok := From(t.Context()); ok {
		t.Fatal("identity in empty context")
	}
	id := Identity{Kind: KindBot, Name: "b"}
	got, ok := From(With(t.Context(), id))
	if !ok || got.Key() != "bot:b" {
		t.Fatalf("got %+v %v", got, ok)
	}
	if !IsGUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee") || IsGUID("x") {
		t.Fatal("IsGUID")
	}
}
