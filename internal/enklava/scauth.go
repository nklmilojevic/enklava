package enklava

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"unicode/utf8"
)

type Identity struct {
	Label      string
	Hash       string
	Protection string
	Type       string
}

var (
	ErrUnexpectedOutput = errors.New("unexpected sc_auth output")
	ErrNoIdentity       = errors.New("no identity has this label")
)

type AmbiguousError struct {
	Label string
	Count int
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%d identities are labelled %q", e.Count, e.Label)
}

// Identities lists the SSH identities sc_auth knows, with hashes in the
// given encoding: b64 for SSH fingerprints, hex for keychain hashes.
func (t Tools) Identities(encoding string) ([]Identity, error) {
	out, err := output(exec.Command(t.ScAuth, "list-ctk-identities", "-t", "ssh", "-e", encoding))
	if err != nil {
		return nil, fmt.Errorf("sc_auth could not list identities: %w", err)
	}
	return ParseIdentities(out)
}

// ParseIdentities reads sc_auth's fixed-width table. Its cells may contain
// spaces (labels, localized dates), so columns are cut at the header's
// offsets.
func ParseIdentities(table string) ([]Identity, error) {
	lines := strings.Split(table, "\n")
	header := lines[0]
	h := column(header, "Public Key Hash")
	p := column(header, "Prot")
	l := column(header, "Label")
	c := column(header, "Common Name")
	if h < 0 || p < 0 || l < 0 || c < 0 {
		return nil, ErrUnexpectedOutput
	}

	var identities []Identity
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := []rune(line)
		identities = append(identities, Identity{
			Label:      cell(row, l, c),
			Hash:       cell(row, h, p),
			Protection: cell(row, p, l),
			Type:       cell(row, 0, h),
		})
	}
	return identities, nil
}

// column is the rune offset of name in the header, or -1.
func column(header, name string) int {
	i := strings.Index(header, name)
	if i < 0 {
		return -1
	}
	return utf8.RuneCountInString(header[:i])
}

func cell(row []rune, from, to int) string {
	from, to = min(from, len(row)), min(to, len(row))
	if from >= to {
		return ""
	}
	return strings.Trim(string(row[from:to]), " ")
}

// HashFor returns the hash of the one identity with exactly this label. It
// fails with ErrNoIdentity when none has it and *AmbiguousError when several
// do.
func (t Tools) HashFor(label, encoding string) (string, error) {
	identities, err := t.Identities(encoding)
	if err != nil {
		return "", err
	}
	var matches []string
	for _, identity := range identities {
		if identity.Label == label {
			matches = append(matches, identity.Hash)
		}
	}
	switch len(matches) {
	case 0:
		return "", ErrNoIdentity
	case 1:
		return matches[0], nil
	default:
		return "", &AmbiguousError{Label: label, Count: len(matches)}
	}
}

// CreateIdentity makes a new P-256 key inside the Secure Enclave.
func (t Tools) CreateIdentity(label, protection string) error {
	_, err := output(exec.Command(t.ScAuth, "create-ctk-identity", "-l", label, "-k", "p-256-ne", "-t", protection))
	return err
}
