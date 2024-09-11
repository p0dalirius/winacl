package utils

import (
	"encoding/hex"
)

func ConvertRawBytesToHex(rawBytes []byte) string {
	return hex.EncodeToString(rawBytes)
}
