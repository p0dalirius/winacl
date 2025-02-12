package identity

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSID_Involution(t *testing.T) {
	hexData := "01020000000000052000000020020000"
	sid := &SID{}
	rawBytes, err := hex.DecodeString(hexData)
	if err != nil {
		t.Errorf("Failed to decode hexData: %v", err)
	}
	sid.FromBytes(rawBytes)
	data := sid.ToBytes()
	if !bytes.Equal(data, rawBytes) {
		t.Errorf("SID.ToBytes() failed: Output of sid.ToBytes() is not equal to input rawBytes")
	}
}

func TestSID_LookupName(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedName := "BUILTIN\\Administrators"
	actualName := sid.LookupName()
	if actualName != expectedName {
		t.Errorf("LookupName() failed: expected %s, got %s", expectedName, actualName)
	}
}

func TestSID_ToBytes(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	actualBytes := sid.ToBytes()
	if !strings.EqualFold(hex.EncodeToString(actualBytes), hex.EncodeToString(expectedBytes)) {
		t.Errorf("ToBytes() failed: expected %x, got %x", expectedBytes, actualBytes)
	}
}

func TestSID_FromStringToBytes(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	sid.FromString(sidString)
	expectedBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	actualBytes := sid.ToBytes()
	if !bytes.Equal(actualBytes, expectedBytes) {
		t.Errorf("ToBytes() failed: expected %x, got %x", expectedBytes, actualBytes)
	}
}

func TestSID_FromBytesToString(t *testing.T) {
	sid := &SID{}
	rawBytes, _ := hex.DecodeString("01020000000000052000000020020000")
	sid.FromBytes(rawBytes)
	expectedString := "S-1-5-32-544"
	actualString := sid.ToString()
	if actualString != expectedString {
		t.Errorf("FromBytes() failed: expected %s, got %s", expectedString, actualString)
	}
}

func TestSID_FromStringToString(t *testing.T) {
	sid := &SID{}
	sidString := "S-1-5-32-544"
	err := sid.FromString(sidString)
	if err != nil {
		t.Errorf("FromString() failed: %v", err)
	}
	expectedString := "S-1-5-32-544"
	actualString := sid.ToString()
	if actualString != expectedString {
		t.Errorf("FromString() failed: expected %s, got %s", expectedString, actualString)
	}
}
