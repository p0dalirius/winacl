package ntsecuritydescriptor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type SystemAccessControlListHeader struct {
	Revision uint8
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16
}

func (sacl *SystemAccessControlListHeader) Parse(RawBytes []byte) error {
	// Parsing header
	if len(RawBytes) < 8 {
		return fmt.Errorf("invalid raw bytes length")
	}

	sacl.Revision = RawBytes[0]
	sacl.Sbz1 = RawBytes[1]
	sacl.AclSize = binary.LittleEndian.Uint16(RawBytes[2:4])
	sacl.AceCount = binary.LittleEndian.Uint16(RawBytes[4:6])
	sacl.Sbz2 = binary.LittleEndian.Uint16(RawBytes[6:8])

	return nil
}

func (sacl *SystemAccessControlListHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<SystemAccessControlListHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sacl.Revision)
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sacl.Sbz1)
	fmt.Printf("%s │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, sacl.AclSize)
	fmt.Printf("%s │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, sacl.AceCount)
	fmt.Printf("%s │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, sacl.Sbz2)
	fmt.Printf("%s └─\n", indentPrompt)
}
