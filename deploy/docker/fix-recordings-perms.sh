#!/bin/sh
# guacd writes session recordings as root (often mode 0600). audit-service and
# other PAM services run as the unprivileged pam user on the shared pam-rec
# volume. Run these helpers as root so playback/download always works.

recordings_perms_once() {
	[ -d /recordings ] || return 0
	find /recordings -type d -exec chmod a+rwx {} + 2>/dev/null || true
	find /recordings -type f -exec chmod a+rw {} + 2>/dev/null || true
}

recordings_perms_loop() {
	recordings_perms_once
	while true; do
		sleep 5
		recordings_perms_once
	done
}
