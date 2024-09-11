package acl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type SystemAccessControlListHeader struct {
	Revision AccessControlListRevision
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (saclheader *SystemAccessControlListHeader) Parse(RawBytes []byte) error {
	// Parsing header
	if len(RawBytes) < 8 {
		return fmt.Errorf("invalid raw bytes length")
	}

	saclheader.RawBytes = RawBytes[:8]
	saclheader.RawBytesSize = 8

	saclheader.Revision.Parse(uint8(RawBytes[0]))
	saclheader.Sbz1 = RawBytes[1]
	saclheader.AclSize = binary.LittleEndian.Uint16(RawBytes[2:4])
	saclheader.AceCount = binary.LittleEndian.Uint16(RawBytes[4:6])
	saclheader.Sbz2 = binary.LittleEndian.Uint16(RawBytes[6:8])

	return nil
}

func (saclheader *SystemAccessControlListHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<SystemAccessControlListHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, saclheader.Revision.Value, saclheader.Revision.Name)
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, saclheader.Sbz1)
	fmt.Printf("%s │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, saclheader.AclSize)
	fmt.Printf("%s │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%08x\x1b[0m (%d)\x1b[0m\n", indentPrompt, saclheader.AceCount, saclheader.AceCount)
	fmt.Printf("%s │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, saclheader.Sbz2)
	fmt.Printf("%s └─\n", indentPrompt)
}
