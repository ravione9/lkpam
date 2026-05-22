#!/bin/sh
# guacd must write session recordings/typescript under /recordings; PAM app
# containers chown that volume to pam, so open permissions for the guacd user.
set -e
mkdir -p /recordings/ssh /recordings/rdp
chmod -R 0777 /recordings 2>/dev/null || true
exec /opt/guacamole/sbin/guacd -b 0.0.0.0 -L info -f
