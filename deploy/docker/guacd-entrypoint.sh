#!/bin/sh
# guacd must write session recordings/typescript under /recordings (shared pam-rec).
# The pam-rec volume is also mounted into audit-service / rdp-proxy, which run as
# the unprivileged 'pam' user inside the pam-platform image. guacd here runs as
# root, so without an explicit umask, files created at runtime inherit mode 0600
# and audit-service hits EACCES (HTTP 403 "Could not load recording") whenever
# the user tries to play a NEW recording.
#
# umask 0 makes new files 0666 and new dirs 0777, matching what the initial
# chmod -R below sets — guarantees the audit container can always read whatever
# guacd writes.
set -e
umask 0
mkdir -p /recordings/ssh /recordings/rdp
chmod -R 0777 /recordings
echo "guacd-entrypoint: /recordings permissions set for guacd (umask 0)"
exec /opt/guacamole/sbin/guacd -b 0.0.0.0 -L info -f
