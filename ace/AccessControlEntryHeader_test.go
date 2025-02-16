package ace

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAccessControlEntryHeader_Involution(t *testing.T) {
	hexData := "1122abcd"
	header := &AccessControlEntryHeader{}
	rawBytes, err := hex.DecodeString(hexData)
	if err != nil {
		t.Errorf("Failed to decode hexData: %v", err)
	}
	header.Parse(rawBytes)
	data := header.ToBytes()
	if !bytes.Equal(data, rawBytes) {
		t.Errorf("AccessControlEntryHeader.ToBytes() failed: Output of header.ToBytes() is not equal to input rawBytes")
	}
}
