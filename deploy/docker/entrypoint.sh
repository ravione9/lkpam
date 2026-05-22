#!/bin/sh
set -e

mkdir -p /data /recordings

# Share one vault master key across all containers when PAM_MASTER_KEY is unset.
KEYFILE=/data/.master_key
if [ -n "$PAM_MASTER_KEY" ]; then
  : # use env as-is
elif [ -f "$KEYFILE" ]; then
  export PAM_MASTER_KEY="$(cat "$KEYFILE")"
else
  export PAM_MASTER_KEY="$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '\n')"
  umask 077
  printf '%s' "$PAM_MASTER_KEY" > "$KEYFILE"
fi

chown -R pam:pam /data 2>/dev/null || true
# guacd runs as a different user; keep /recordings world-writable (do not chown to pam).
mkdir -p /recordings/ssh /recordings/rdp
chmod -R 0777 /recordings 2>/dev/null || true
chmod 600 "$KEYFILE" 2>/dev/null || true

exec su-exec pam "$@"
