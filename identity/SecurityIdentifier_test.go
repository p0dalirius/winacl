package identity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestSID_Involution(t *testing.T) {
	testSIDsinHexFormat := []string{
		"01050000000000051500000028bb82279261b9fe2474aa5d00020000",
		"01050000000000051500000028bb82279261b9fe2030303000000000",
		"01050000000000051500000028bb82279261b9fe2030303000000000",
		// "01050000000000051500000028bb82279261b9fe20", // Seems broken
		"01020000000000052000000020020000",
	}
	for _, hexData := range testSIDsinHexFormat {
		rawBytes, err := hex.DecodeString(hexData)
		if err != nil {
			t.Fatalf("Failed to decode hex string: %v", err)
		}

		var sid SID
		sid.FromBytes(rawBytes)

		serializedBytes := sid.ToBytes()

		if !bytes.Equal(rawBytes, serializedBytes) {
			hexData2 := hex.EncodeToString(serializedBytes)
			minLen := len(hexData2)
			if len(hexData) < minLen {
				minLen = len(hexData)
			}
			for k := 0; k < minLen; k++ {
				if hexData[k] == hexData2[k] {
					hexData = hexData[:k] + "_" + hexData[k+1:]
					hexData2 = hexData2[:k] + "_" + hexData2[k+1:]
				}
			}

			fmt.Println("source-----:", hexData)
			fmt.Println("serialized-:", hexData2)

			t.Errorf("Involution test failed: expected %s, got %s", hex.EncodeToString(rawBytes), hex.EncodeToString(serializedBytes))
		}
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
