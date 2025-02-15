package securitydescriptor

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestNtSecurityDescriptor_Involution(t *testing.T) {
	// --------------------------------------------------------------------------------------------------------------75a38
	testNtsdHex := "0100149ccc000000e800000014000000a000000004008c00030000000240140020000c00010100000000000100000000075a38002000000003000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2010100000000000100000000075a38002000000003000000bf3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e201010000000000010000000002002c000100000000002400ff010f0001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe2000000000000000"

	ntsd := &NtSecurityDescriptor{}
	ntsdBytes, err := hex.DecodeString(testNtsdHex)
	if err != nil {
		t.Errorf("Failed to decode testNtsdHex: %v", err)
	}
	ntsd.Parse(ntsdBytes)
	data := ntsd.ToBytes()
	hexData1 := hex.EncodeToString(data)
	if !strings.EqualFold(testNtsdHex, hexData1) {
		minLen := len(hexData1)
		if len(testNtsdHex) < minLen {
			minLen = len(testNtsdHex)
		}
		for k := 0; k < minLen; k++ {
			if hexData1[k] == testNtsdHex[k] {
				hexData1 = hexData1[:k] + "_" + hexData1[k+1:]
				testNtsdHex = testNtsdHex[:k] + "_" + testNtsdHex[k+1:]
			}
		}

		fmt.Println("output-:", hexData1)
		fmt.Println("input--:", testNtsdHex)

		t.Errorf("NtSecurityDescriptor.ToBytes() failed: Output of ntsd.ToBytes() is not equal to input hex string")
	}

	ntsd2 := &NtSecurityDescriptor{}
	ntsd2.Parse(data)
	data2 := ntsd2.ToBytes()
	hexData2 := hex.EncodeToString(data2)

	if !strings.EqualFold(testNtsdHex, hexData2) {
		t.Errorf("Involution failed: Output of ntsd2.ToBytes() is not equal to input hex string")
	}
}

// func TestNtSecurityDescriptor_Describe(t *testing.T) {
// 	testNtsdHex := "0100149ccc000000e800000014000000a000000004008c00030000000240140020000c00010100000000000100000000075a38002000000003000000be3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e2010100000000000100000000075a38002000000003000000bf3b0ef3f09fd111b6030000f80367c1a57a96bfe60dd011a28500aa003049e201010000000000010000000002002c000100000000002400ff010f0001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe2474aa5d0002000001050000000000051500000028bb82279261b9fe20"

// 	ntsd := &NtSecurityDescriptor{}
// 	ntsdBytes, err := hex.DecodeString(testNtsdHex)
// 	if err != nil {
// 		t.Errorf("Failed to decode testNtsdHex: %v", err)
// 	}
// 	ntsd.Parse(ntsdBytes)

// 	ntsd.Describe(0)
// }
