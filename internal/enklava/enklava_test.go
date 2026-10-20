package enklava

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// table mimics sc_auth: fixed-width columns whose cells contain spaces and
// non-ASCII text.
var table = func() string {
	row := func(cells ...any) string {
		return fmt.Sprintf("%-9s%-51s%-5s%-12s%-12s%-14s%-21s%-6s\n", cells...)
	}
	return row("Key Type", "Public Key Hash", "Prot", "Label", "Common Name", "Email Address", "Valid To", "Valid") +
		row("p-256-ne", "SHA256:"+strings.Repeat("a", 43), "none", "work laptop", "work laptop", "", "20. 10. 2027., 14:17", "YES") +
		row("p-256-ne", "SHA256:"+strings.Repeat("b", 43), "bio", "ključ", "ključ", "", "20. 10. 2027., 14:17", "YES") +
		"\n"
}()

func TestParseIdentities(t *testing.T) {
	got, err := ParseIdentities(table)
	if err != nil {
		t.Fatal(err)
	}
	want := []Identity{
		{Label: "work laptop", Hash: "SHA256:" + strings.Repeat("a", 43), Protection: "none", Type: "p-256-ne"},
		{Label: "ključ", Hash: "SHA256:" + strings.Repeat("b", 43), Protection: "bio", Type: "p-256-ne"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestParseIdentitiesEmpty(t *testing.T) {
	got, err := ParseIdentities("Key Type Public Key Hash Prot Label Common Name\n")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestParseIdentitiesRejectsUnknownHeader(t *testing.T) {
	if _, err := ParseIdentities("No identities found\n"); !errors.Is(err, ErrUnexpectedOutput) {
		t.Fatalf("got %v", err)
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{
		"Test Mac":     "Test-Mac",
		"nkl-mbp":      "nkl-mbp",
		"Nikolin Mač!": "Nikolin-Ma--",
		"":             "mac",
	} {
		if got := SafeName(in); got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestKeyTitle(t *testing.T) {
	if got := KeyTitle("Test-Mac", "SHA256:ab/cd+ef0123456789"); got != "enklava-Test-Mac-ab-cd-ef0123" {
		t.Fatalf("got %q", got)
	}
}

func TestAllowedSigners(t *testing.T) {
	got := AllowedSigners([]string{"a@x ssh-ed25519 OLD"}, []string{"a@x", "b@x"}, "sk-ecdsa", "AAAA")
	if want := "a@x ssh-ed25519 OLD\na@x,b@x sk-ecdsa AAAA\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got := AllowedSigners([]string{"a@x ssh-ed25519 OLD"}, []string{"a@x"}, "", ""); got != "a@x ssh-ed25519 OLD\n" {
		t.Fatalf("missing key: got %q", got)
	}
}

func TestExpand(t *testing.T) {
	t.Setenv("HOME", "/Users/test")
	for in, want := range map[string]string{
		"~/.ssh/id": "/Users/test/.ssh/id",
		"/abs/id":   "/abs/id",
		"~user/id":  "~user/id",
	} {
		if got := Expand(in); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}
