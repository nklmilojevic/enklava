# shellcheck shell=bash
# enklava: Secure Enclave SSH identities on macOS, built on sc_auth and
# Apple's ssh-keychain.dylib. No secret ever leaves the enclave; the files
# this writes are a non-secret stub (or public-key reference) and its .pub.

SC_AUTH=${ENKLAVA_SC_AUTH:-/usr/sbin/sc_auth}
SSH_KEYGEN=${ENKLAVA_SSH_KEYGEN:-/usr/bin/ssh-keygen}
SSH_ADD=${ENKLAVA_SSH_ADD:-/usr/bin/ssh-add}
SSH_AGENT=${ENKLAVA_SSH_AGENT:-/usr/bin/ssh-agent}
PBCOPY=${ENKLAVA_PBCOPY:-/usr/bin/pbcopy}
SCUTIL=${ENKLAVA_SCUTIL:-/usr/sbin/scutil}
GH=${ENKLAVA_GH:-gh}
PROVIDER=${ENKLAVA_PROVIDER:-/usr/lib/ssh-keychain.dylib}

die() {
  printf 'enklava: %s\n' "$*" >&2
  exit 1
}

say() {
  printf 'enklava: %s\n' "$*"
}

usage() {
  cat <<'EOF'
Usage: enklava <command> [options]

Commands:
  ensure --key-file F --label L [--protection none|bio]
      Create the Secure Enclave identity and its SSH stub if missing.
      Prints nothing when everything is already in place.
  list
      List Secure Enclave identities available to SSH.
  pub --key-file F [--copy]
      Print (or copy) the public key.
  allowed-signers --output O [--key-file F --principal P...] [--extra LINE...]
      Write a Git allowed_signers file.
  github add --key-file F [--type signing|authentication|both] [--title T]
      Register the public key with GitHub through gh, skipping keys it has.
  doctor --key-file F --label L
      Check the tools, the identity and the stub. Exits non-zero on failure.
EOF
}

expand() {
  case $1 in
    \~/*) printf '%s\n' "$HOME/${1#\~/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# sc_auth prints a fixed-width table whose cells may contain spaces (labels,
# localized dates), so cut columns at the header's offsets.
identities() {
  "$SC_AUTH" list-ctk-identities -t ssh -e "$1" | awk '
    function trim(s) { gsub(/^ +| +$/, "", s); return s }
    NR == 1 {
      h = index($0, "Public Key Hash"); p = index($0, "Prot")
      l = index($0, "Label"); c = index($0, "Common Name")
      if (!h || !p || !l || !c) { print "enklava: unexpected sc_auth output" > "/dev/stderr"; exit 2 }
      next
    }
    NF {
      print trim(substr($0, l, c - l)) "\t" trim(substr($0, h, p - h)) "\t" \
        trim(substr($0, p, l - p)) "\t" trim(substr($0, 1, h - 1))
    }'
}

# Prints the hash of the identity with exactly this label. Returns 3 when no
# identity has it and 4 when several do.
hash_for() {
  local rows matches count
  rows=$(identities "$2") || return 2
  matches=$(printf '%s\n' "$rows" | awk -F'\t' -v label="$1" '$1 == label { print $2 }')
  count=$(printf '%s' "$matches" | grep -c . || true)
  case $count in
    0) return 3 ;;
    1) printf '%s\n' "$matches" ;;
    *)
      printf 'enklava: %s identities are labelled "%s"\n' "$count" "$1" >&2
      return 4
      ;;
  esac
}

fingerprint() {
  "$SSH_KEYGEN" -lf "$1" | awk '{ print $2 }'
}

# The public key line for the identity with this SHA256 hash, read from a
# throwaway agent that is killed as soon as it has been listed.
public_line_from_agent() {
  local keys line
  # shellcheck disable=SC2016 # expanded by the inner sh
  keys=$(SSH_SK_PROVIDER=$PROVIDER "$SSH_AGENT" sh -c '
    "$1" -K </dev/null >/dev/null 2>&1
    "$1" -L
    status=$?
    kill "$SSH_AGENT_PID" 2>/dev/null
    exit "$status"' sh "$SSH_ADD") || return 1
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    if [ "$(printf '%s\n' "$line" | "$SSH_KEYGEN" -lf /dev/stdin | awk '{ print $2 }')" = "$1" ]; then
      printf '%s\n' "$line"
      return 0
    fi
  done <<<"$keys"
  return 1
}

write_stub() {
  local key=$1 sha=$2 hex=$3 tmp found="" pub line
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # KEYCHAIN_CERTIFICATES scopes the download to this one identity.
  (cd "$tmp" && KEYCHAIN_CERTIFICATES=$hex "$SSH_KEYGEN" -w "$PROVIDER" -K -N "" </dev/null >/dev/null 2>&1) || true
  for pub in "$tmp"/*.pub; do
    [ -e "$pub" ] || continue
    if [ "$(fingerprint "$pub")" = "$sha" ]; then
      found=${pub%.pub}
      break
    fi
  done

  mkdir -p "$(dirname "$key")"
  if [ -n "$found" ]; then
    install -m 600 "$found" "$key"
    install -m 644 "$found.pub" "$key.pub"
    say "wrote SSH stub $key"
  else
    line=$(public_line_from_agent "$sha") || die "could not read the public key of $sha from ssh-keygen or ssh-agent"
    printf '%s\n' "$line" >"$tmp/reference"
    install -m 600 "$tmp/reference" "$key"
    install -m 644 "$tmp/reference" "$key.pub"
    say "wrote SSH public-key reference $key"
  fi
}

cmd_ensure() {
  local key="" label="" protection=none sha rc hex
  while [ $# -gt 0 ]; do
    case $1 in
      --key-file) key=$(expand "${2?--key-file needs a value}"); shift 2 ;;
      --label) label=${2?--label needs a value}; shift 2 ;;
      --protection) protection=${2?--protection needs a value}; shift 2 ;;
      *) die "ensure: unknown option $1" ;;
    esac
  done
  [ -n "$key" ] || die "ensure: --key-file is required"
  [ -n "$label" ] || die "ensure: --label is required"
  case $protection in
    none | bio) ;;
    *) die "ensure: --protection must be none or bio, not $protection" ;;
  esac
  if { [ -e "$key" ] && [ ! -e "$key.pub" ]; } || { [ ! -e "$key" ] && [ -e "$key.pub" ]; }; then
    die "$key and $key.pub must both exist or both be absent"
  fi

  sha=$(hash_for "$label" b64) && rc=0 || rc=$?
  case $rc in
    0) ;;
    3)
      "$SC_AUTH" create-ctk-identity -l "$label" -k p-256-ne -t "$protection" >/dev/null ||
        die "sc_auth could not create identity $label"
      sha=$(hash_for "$label" b64) || die "created identity $label but sc_auth does not list it"
      say "created Secure Enclave identity $label"
      ;;
    *) exit 1 ;;
  esac

  if [ -e "$key" ]; then
    [ "$(fingerprint "$key.pub")" = "$sha" ] ||
      die "$key.pub is not the key of identity $label ($sha); move it away and run ensure again"
    return 0
  fi

  hex=$(hash_for "$label" hex) || die "could not read the keychain hash of identity $label"
  write_stub "$key" "$sha" "$hex"
}

cmd_list() {
  [ $# -eq 0 ] || die "list takes no options"
  printf 'LABEL\tHASH\tPROTECTION\tTYPE\n'
  identities b64
}

cmd_pub() {
  local key="" copy=false
  while [ $# -gt 0 ]; do
    case $1 in
      --key-file) key=$(expand "${2?--key-file needs a value}"); shift 2 ;;
      --copy) copy=true; shift ;;
      *) die "pub: unknown option $1" ;;
    esac
  done
  [ -n "$key" ] || die "pub: --key-file is required"
  [ -f "$key.pub" ] || die "$key.pub not found; run enklava ensure first"
  if $copy; then
    "$PBCOPY" <"$key.pub"
    say "copied $key.pub to the clipboard"
  else
    cat "$key.pub"
  fi
}

cmd_allowed_signers() {
  local key="" output="" principals="" extras=() tmp
  while [ $# -gt 0 ]; do
    case $1 in
      --key-file) key=$(expand "${2?--key-file needs a value}"); shift 2 ;;
      --principal) principals=${principals:+$principals,}${2?--principal needs a value}; shift 2 ;;
      --extra) extras+=("${2?--extra needs a value}"); shift 2 ;;
      --output) output=$(expand "${2?--output needs a value}"); shift 2 ;;
      *) die "allowed-signers: unknown option $1" ;;
    esac
  done
  [ -n "$output" ] || die "allowed-signers: --output is required"
  [ -z "$key" ] || [ -n "$principals" ] || die "allowed-signers: --key-file needs at least one --principal"

  mkdir -p "$(dirname "$output")"
  tmp=$(mktemp "$output.XXXXXX")
  {
    if [ ${#extras[@]} -gt 0 ]; then
      printf '%s\n' "${extras[@]}"
    fi
    if [ -n "$key" ] && [ -f "$key.pub" ]; then
      printf '%s %s\n' "$principals" "$(cut -d' ' -f1,2 "$key.pub")"
    fi
  } >"$tmp"
  chmod 644 "$tmp"
  mv "$tmp" "$output"
}

machine_name() {
  local name
  name=$("$SCUTIL" --get LocalHostName 2>/dev/null) || name=$(hostname -s 2>/dev/null) || name=mac
  printf '%s' "${name:-mac}" | tr -c 'A-Za-z0-9-' '-'
}

cmd_github_add() {
  local key="" type=both title="" types algo body endpoint t
  while [ $# -gt 0 ]; do
    case $1 in
      --key-file) key=$(expand "${2?--key-file needs a value}"); shift 2 ;;
      --type) type=${2?--type needs a value}; shift 2 ;;
      --title) title=${2?--title needs a value}; shift 2 ;;
      *) die "github add: unknown option $1" ;;
    esac
  done
  [ -n "$key" ] || die "github add: --key-file is required"
  [ -f "$key.pub" ] || die "$key.pub not found; run enklava ensure first"
  case $type in
    both) types="signing authentication" ;;
    signing | authentication) types=$type ;;
    *) die "github add: --type must be signing, authentication or both" ;;
  esac
  if [ -z "$title" ]; then
    title="enklava-$(machine_name)-$(fingerprint "$key.pub" | sed 's/^SHA256://' | cut -c1-12 | tr '/+' '--')"
  fi
  read -r algo body _ <"$key.pub"

  for t in $types; do
    case $t in
      signing) endpoint=/user/ssh_signing_keys ;;
      authentication) endpoint=/user/keys ;;
    esac
    if "$GH" api --paginate "$endpoint" --jq '.[].key' |
      awk -v a="$algo" -v b="$body" '$1 == a && $2 == b { found = 1 } END { exit !found }'; then
      say "GitHub already has this $t key"
      continue
    fi
    "$GH" ssh-key add "$key.pub" --type "$t" --title "$title" >/dev/null ||
      die "gh could not add the $t key"
    say "added $t key \"$title\" to GitHub"
  done
}

cmd_doctor() {
  local key="" label="" failed=0 sha rc
  while [ $# -gt 0 ]; do
    case $1 in
      --key-file) key=$(expand "${2?--key-file needs a value}"); shift 2 ;;
      --label) label=${2?--label needs a value}; shift 2 ;;
      *) die "doctor: unknown option $1" ;;
    esac
  done
  [ -n "$key" ] || die "doctor: --key-file is required"
  [ -n "$label" ] || die "doctor: --label is required"

  ok() { printf 'ok    %s\n' "$1"; }
  fail() {
    printf 'FAIL  %s\n' "$1"
    failed=1
  }

  if [ -x "$SC_AUTH" ]; then ok "$SC_AUTH"; else fail "$SC_AUTH is missing"; fi
  if [ -x "$SSH_KEYGEN" ]; then ok "$SSH_KEYGEN"; else fail "$SSH_KEYGEN is missing"; fi
  if [ -e "$PROVIDER" ]; then ok "$PROVIDER"; else fail "$PROVIDER is missing (needs macOS 26 or later)"; fi

  sha=$(hash_for "$label" b64 2>/dev/null) && rc=0 || rc=$?
  case $rc in
    0) ok "identity $label ($sha)" ;;
    3) fail "no identity is labelled $label" ;;
    4) fail "several identities are labelled $label" ;;
    *) fail "sc_auth could not list identities" ;;
  esac

  if [ -e "$key" ] && [ -e "$key.pub" ]; then
    ok "$key and $key.pub"
    if [ "$rc" = 0 ]; then
      if [ "$(fingerprint "$key.pub")" = "$sha" ]; then
        ok "$key.pub matches $label"
      else
        fail "$key.pub does not match $label"
      fi
    fi
  elif [ -e "$key" ] || [ -e "$key.pub" ]; then
    fail "only one of $key and $key.pub exists"
  else
    fail "$key is missing; run enklava ensure"
  fi

  return "$failed"
}

case ${1:-} in
  ensure) shift; cmd_ensure "$@" ;;
  list) shift; cmd_list "$@" ;;
  pub) shift; cmd_pub "$@" ;;
  allowed-signers) shift; cmd_allowed_signers "$@" ;;
  github)
    [ "${2:-}" = add ] || die "usage: enklava github add --key-file F [--type T] [--title T]"
    shift 2
    cmd_github_add "$@"
    ;;
  doctor) shift; cmd_doctor "$@" ;;
  -h | --help | help) usage ;;
  "") usage >&2; exit 1 ;;
  *) printf 'enklava: unknown command %s\n\n' "$1" >&2; usage >&2; exit 1 ;;
esac
