package mfa

import (
	"encoding/base64"

	"github.com/skip2/go-qrcode"
)

// QRPNGDataURI returns a PNG QR code for content as a data: URI suitable for <img src>.
func QRPNGDataURI(content string, size int) (string, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, size)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), nil
}
