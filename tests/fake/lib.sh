# shellcheck shell=bash
# Shared state for the fake Apple tools. Identities live in $FAKE_STATE as
# "label<TAB>protection" rows; every hash is derived from the label.
db=$FAKE_STATE/identities
touch "$db"

hex_of() { printf '%s' "$1" | sha256sum | cut -c1-64; }
ssh_hash_of() { printf 'SHA256:%s' "$(hex_of "$1" | cut -c1-43)"; }
keychain_hash_of() { hex_of "$1" | tr a-f A-F; }
public_line_of() { printf 'sk-ecdsa-sha2-nistp256@openssh.com AAAA%s ssh:\n' "$(hex_of "$1")"; }
