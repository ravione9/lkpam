#!/bin/sh
# guacd must write session recordings/typescript under /recordings (shared pam-rec).
set -e
mkdir -p /recordings/ssh /recordings/rdp
chmod -R 0777 /recordings
echo "guacd-entrypoint: /recordings permissions set for guacd"
exec /opt/guacamole/sbin/guacd -b 0.0.0.0 -L info -f
