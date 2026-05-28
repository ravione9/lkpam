package rdpproxy

import "strconv"

func rdpGuacParams(host string, port int, username, password, recDir, sessionID string, record bool) map[string]string {
	p := map[string]string{
		"hostname":                host,
		"port":                    strconv.Itoa(port),
		"username":                username,
		"password":                password,
		"ignore-cert":             "true",
		"color-depth":             "32",
		"security":                "any",
		"resize-method":           "display-update",
		"enable-wallpaper":        "false",
		"enable-theming":          "false",
		"enable-font-smoothing":   "true",
		"enable-full-window-drag": "false",
		"enable-desktop-composition": "true",
		"disable-auth":            "false",
		// RDP bitmap/GFX caching sends stale frames to session recordings — only the
		// initial desktop wallpaper is captured and opened apps never appear on replay.
		// See Apache Guacamole docs (disable-bitmap-caching / disable-gfx).
		"disable-bitmap-caching":    "true",
		"disable-offscreen-caching": "true",
		"disable-glyph-caching":     "true",
		"disable-gfx":               "true",
	}
	if record && recDir != "" && sessionID != "" {
		p["recording-path"] = recDir
		p["recording-name"] = sessionID
		p["create-recording-path"] = "true"
		p["recording-include-keys"] = "true"
	}
	return p
}
