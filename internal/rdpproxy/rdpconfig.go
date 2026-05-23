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
		"disable-auth":            "false",
	}
	if record && recDir != "" && sessionID != "" {
		p["recording-path"] = recDir
		p["recording-name"] = sessionID
		p["create-recording-path"] = "true"
	}
	return p
}
