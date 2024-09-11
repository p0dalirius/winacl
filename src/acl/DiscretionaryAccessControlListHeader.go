package acl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type DiscretionaryAccessControlListHeader struct {
	Revision AccessControlListRevision
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (daclheader *DiscretionaryAccessControlListHeader) Parse(RawBytes []byte) error {
	// Parsing header
	if len(RawBytes) < 8 {
		return fmt.Errorf("invalid raw bytes length")
	}

	daclheader.RawBytes = RawBytes[:8]
	daclheader.RawBytesSize = 8

	daclheader.Revision.Parse(uint8(RawBytes[0]))
	daclheader.Sbz1 = RawBytes[1]
	daclheader.AclSize = binary.LittleEndian.Uint16(RawBytes[2:4])
	daclheader.AceCount = binary.LittleEndian.Uint16(RawBytes[4:6])
	daclheader.Sbz2 = binary.LittleEndian.Uint16(RawBytes[6:8])

	return nil
}

func (daclheader *DiscretionaryAccessControlListHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<DiscretionaryAccessControlListHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, daclheader.Revision.Value, daclheader.Revision.Name)
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, daclheader.Sbz1)
	fmt.Printf("%s │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, daclheader.AclSize)
	fmt.Printf("%s │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%08x (%d)\x1b[0m\n", indentPrompt, daclheader.AceCount, daclheader.AceCount)
	fmt.Printf("%s │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, daclheader.Sbz2)
	fmt.Printf("%s └─\n", indentPrompt)
}
