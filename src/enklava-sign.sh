# shellcheck shell=bash
# Git's gpg.ssh.program: ssh-keygen with Apple's Secure Enclave provider.
# A real stub signs directly. A public-key reference needs the key in an
# agent, so it gets a private agent that dies with this command.

SSH_KEYGEN=${ENKLAVA_SSH_KEYGEN:-/usr/bin/ssh-keygen}
SSH_ADD=${ENKLAVA_SSH_ADD:-/usr/bin/ssh-add}
SSH_AGENT=${ENKLAVA_SSH_AGENT:-/usr/bin/ssh-agent}
export SSH_SK_PROVIDER=${ENKLAVA_PROVIDER:-/usr/lib/ssh-keychain.dylib}

key=""
previous=""
for argument in "$@"; do
  [ "$previous" = -f ] && key=$argument
  previous=$argument
done

first=""
if [ -n "$key" ] && [ -f "$key" ]; then
  read -r first _ <"$key" || true
fi

case $first in
  sk-*)
    # shellcheck disable=SC2016 # expanded by the inner sh
    exec "$SSH_AGENT" sh -c '
      add=$1 keygen=$2
      shift 2
      if ! "$add" -K </dev/null >/dev/null 2>&1; then
        echo "enklava-sign: ssh-add could not load the Secure Enclave keys" >&2
        kill "$SSH_AGENT_PID" 2>/dev/null
        exit 1
      fi
      "$keygen" "$@"
      status=$?
      kill "$SSH_AGENT_PID" 2>/dev/null
      exit "$status"' sh "$SSH_ADD" "$SSH_KEYGEN" "$@"
    ;;
  *) exec "$SSH_KEYGEN" "$@" ;;
esac
