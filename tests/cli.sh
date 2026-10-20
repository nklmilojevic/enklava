#!/usr/bin/env bash
# CLI tests against fake Apple tools.
# Usage: tests/cli.sh <dir with enklava and enklava-sign> <tests/fake dir>
set -euo pipefail

bin=$1
fake=$2
failures=0

export ENKLAVA_SC_AUTH=$fake/sc_auth
export ENKLAVA_SSH_KEYGEN=$fake/ssh-keygen
export ENKLAVA_SSH_ADD=$fake/ssh-add
export ENKLAVA_SSH_AGENT=$fake/ssh-agent
export ENKLAVA_PBCOPY=$fake/pbcopy
export ENKLAVA_SCUTIL=$fake/scutil
export ENKLAVA_GH=$fake/gh
unset SSH_AUTH_SOCK SSH_AGENT_PID

reset() {
  root=$(mktemp -d)
  export HOME=$root/home FAKE_STATE=$root/state ENKLAVA_PROVIDER=$root/ssh-keychain.dylib
  mkdir -p "$HOME" "$FAKE_STATE"
  touch "$ENKLAVA_PROVIDER"
  unset FAKE_NO_STUB
}

run() {
  status=0
  output=$("$bin/enklava" "$@" 2>&1) || status=$?
}

fail() {
  printf 'FAIL %s: %s\n' "$test" "$1"
  [ -z "${output:-}" ] || printf '  output: %s\n' "$output"
  failures=$((failures + 1))
}

expect_status() { [ "$status" = "$1" ] || fail "exit status $status, expected $1"; }
expect_output() { [[ $output == *"$1"* ]] || fail "output lacks '$1'"; }
expect_quiet() { [ -z "$output" ] || fail "expected no output"; }
expect_file() { [ "$(cat "$1")" = "$2" ] || fail "$1 is '$(cat "$1")', expected '$2'"; }
expect_mode() { [ "$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1")" = "$2" ] || fail "$1 is not mode $2"; }
count() { grep -c "$1" "$2" || true; }

test="ensure creates the identity and a stub"
reset
run ensure --key-file '~/.ssh/id_test' --label test
expect_status 0
expect_output "created Secure Enclave identity test"
expect_output "wrote SSH stub $HOME/.ssh/id_test"
[ "$(head -n1 "$HOME/.ssh/id_test")" = "fake stub for test" ] || fail "stub was not installed"
expect_mode "$HOME/.ssh/id_test" 600
expect_mode "$HOME/.ssh/id_test.pub" 644
[ "$(cat "$FAKE_STATE/download.log")" != "" ] || fail "download was not scoped with KEYCHAIN_CERTIFICATES"

test="ensure is quiet and creates nothing the second time"
run ensure --key-file '~/.ssh/id_test' --label test
expect_status 0
expect_quiet
[ "$(count create-ctk-identity "$FAKE_STATE/sc_auth.log")" = 1 ] || fail "identity was created twice"

test="ensure passes the protection to sc_auth"
reset
run ensure --key-file "$HOME/k" --label bio-key --protection bio
expect_status 0
grep -q -- "-t bio" "$FAKE_STATE/sc_auth.log" || fail "protection was not passed"

test="ensure rejects an unknown protection"
reset
run ensure --key-file "$HOME/k" --label x --protection pin
expect_status 1
expect_output "must be none or bio"

test="labels match exactly, spaces included"
reset
run ensure --key-file "$HOME/a" --label "work laptop"
expect_status 0
run ensure --key-file "$HOME/b" --label work
expect_status 0
expect_output "created Secure Enclave identity work"
run list
expect_output "work laptop"$'\t'"SHA256:"
[ "$(cut -d' ' -f1,2 "$HOME/a.pub")" != "$(cut -d' ' -f1,2 "$HOME/b.pub")" ] || fail "both labels got the same key"

test="ensure refuses half a key pair"
reset
touch "$HOME/k"
run ensure --key-file "$HOME/k" --label x
expect_status 1
expect_output "must both exist or both be absent"

test="ensure refuses a stub that belongs to another identity"
reset
run ensure --key-file "$HOME/a" --label a
run ensure --key-file "$HOME/b" --label b
cp "$HOME/b.pub" "$HOME/a.pub"
run ensure --key-file "$HOME/a" --label a
expect_status 1
expect_output "is not the key of identity a"

test="ensure stops when a label is ambiguous"
reset
printf 'dup\tnone\ndup\tnone\n' >"$FAKE_STATE/identities"
run ensure --key-file "$HOME/k" --label dup
expect_status 1
expect_output '2 identities are labelled "dup"'
[ "$(count create-ctk-identity "$FAKE_STATE/sc_auth.log")" = 0 ] || fail "created an identity anyway"

test="ensure falls back to a public-key reference and stops its agent"
reset
export FAKE_NO_STUB=1
run ensure --key-file "$HOME/k" --label ref
expect_status 0
expect_output "wrote SSH public-key reference"
cmp -s "$HOME/k" "$HOME/k.pub" || fail "reference and .pub differ"
kill -0 "$(cat "$FAKE_STATE/agent.pid")" 2>/dev/null && fail "agent is still running"

test="pub prints and copies the public key"
reset
run ensure --key-file "$HOME/k" --label p
run pub --key-file "$HOME/k"
expect_status 0
[ "$output" = "$(cat "$HOME/k.pub")" ] || fail "printed key differs"
run pub --key-file "$HOME/k" --copy
expect_status 0
cmp -s "$FAKE_STATE/clipboard" "$HOME/k.pub" || fail "clipboard differs"

test="allowed-signers lists extras and the enclave key"
reset
run ensure --key-file "$HOME/k" --label s
run allowed-signers --key-file "$HOME/k" --principal a@x --principal b@x --extra "a@x ssh-ed25519 OLD" --output '~/.ssh/allowed_signers'
expect_status 0
expect_file "$HOME/.ssh/allowed_signers" "a@x ssh-ed25519 OLD
a@x,b@x $(cut -d' ' -f1,2 "$HOME/k.pub")"
expect_mode "$HOME/.ssh/allowed_signers" 644

test="allowed-signers leaves out a missing key"
reset
run allowed-signers --key-file "$HOME/missing" --principal a@x --extra "a@x ssh-ed25519 OLD" --output "$HOME/as"
expect_status 0
expect_file "$HOME/as" "a@x ssh-ed25519 OLD"

test="allowed-signers needs a principal for the key"
reset
run allowed-signers --key-file "$HOME/k" --output "$HOME/as"
expect_status 1

test="github add registers both types once"
reset
run ensure --key-file "$HOME/k" --label g
run github add --key-file "$HOME/k"
expect_status 0
expect_output "added signing key"
expect_output "added authentication key"
title="enklava-Test-Mac-$(grep -o 'SHA256:.*' <<<"$("$fake/ssh-keygen" -lf "$HOME/k.pub")" | cut -c8-19)"
grep -q "signing $title" "$FAKE_STATE/gh.log" || fail "signing title is not $title"
run github add --key-file "$HOME/k"
expect_status 0
expect_output "GitHub already has this signing key"
expect_output "GitHub already has this authentication key"
[ "$(wc -l <"$FAKE_STATE/gh.log" | tr -d ' ')" = 2 ] || fail "keys were added twice"

test="github add honours type and title"
reset
run ensure --key-file "$HOME/k" --label g
run github add --key-file "$HOME/k" --type signing --title mine
expect_status 0
expect_file "$FAKE_STATE/gh.log" "signing mine"

test="doctor passes on a healthy setup"
reset
run ensure --key-file "$HOME/k" --label d
run doctor --key-file "$HOME/k" --label d
expect_status 0
expect_output "ok    $HOME/k.pub matches d"

test="doctor fails without the identity or stub"
reset
run doctor --key-file "$HOME/k" --label d
expect_status 1
expect_output "FAIL  no identity is labelled d"
expect_output "FAIL  $HOME/k is missing"

test="unknown commands fail"
reset
run frobnicate
expect_status 1
expect_output "unknown command frobnicate"

test="enklava-sign signs a stub with the provider and no agent"
reset
run ensure --key-file "$HOME/k" --label sign
"$bin/enklava-sign" -Y sign -n git -f "$HOME/k" /dev/null
grep -q "provider=$ENKLAVA_PROVIDER agent= " "$FAKE_STATE/sign.log" || fail "$(cat "$FAKE_STATE/sign.log")"

test="enklava-sign signs a reference through a private agent"
reset
export FAKE_NO_STUB=1
run ensure --key-file "$HOME/k" --label sign
rm -f "$FAKE_STATE/agent.pid"
"$bin/enklava-sign" -Y sign -n git -f "$HOME/k" /dev/null
grep -q "agent=$FAKE_STATE/agent.sock loaded=yes" "$FAKE_STATE/sign.log" || fail "$(cat "$FAKE_STATE/sign.log")"
kill -0 "$(cat "$FAKE_STATE/agent.pid")" 2>/dev/null && fail "agent is still running"

test="enklava-sign passes verification through unchanged"
reset
printf 'a@x sk-ecdsa-sha2-nistp256@openssh.com AAAA\n' >"$HOME/allowed"
"$bin/enklava-sign" -Y verify -f "$HOME/allowed" -I a@x -n git -s /dev/null
grep -q "agent= " "$FAKE_STATE/sign.log" || fail "verification went through an agent"

if [ "$failures" -gt 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all CLI tests passed"
