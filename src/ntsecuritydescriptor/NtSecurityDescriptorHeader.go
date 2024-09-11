package ntsecuritydescriptor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type NtSecurityDescriptorHeader struct {
	Revision    uint8
	Sbz1        uint8
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32
	OffsetDacl  uint32
}

func (ntsd *NtSecurityDescriptorHeader) Parse(RawBytes []byte) error {
	// Parsing header
	if len(RawBytes) < 20 {
		return fmt.Errorf("invalid raw bytes length")
	}

	ntsd.Revision = RawBytes[0]
	ntsd.Sbz1 = RawBytes[1]
	ntsd.Control = binary.LittleEndian.Uint16(RawBytes[2:4])
	ntsd.OffsetOwner = binary.LittleEndian.Uint32(RawBytes[4:8])
	ntsd.OffsetGroup = binary.LittleEndian.Uint32(RawBytes[8:12])
	ntsd.OffsetSacl = binary.LittleEndian.Uint32(RawBytes[12:16])
	ntsd.OffsetDacl = binary.LittleEndian.Uint32(RawBytes[16:20])

	return nil
}

func (ntsd *NtSecurityDescriptorHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<NtSecurityDescriptorHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m    : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, ntsd.Revision)
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m        : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, ntsd.Sbz1)
	fmt.Printf("%s │ \x1b[93mControl\x1b[0m     : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, ntsd.Control)
	fmt.Printf("%s │ \x1b[93mOffsetOwner\x1b[0m : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetOwner)
	fmt.Printf("%s │ \x1b[93mOffsetGroup\x1b[0m : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetGroup)
	fmt.Printf("%s │ \x1b[93mOffsetSacl\x1b[0m  : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetSacl)
	fmt.Printf("%s │ \x1b[93mOffsetDacl\x1b[0m  : \x1b[96m0x%08x\x1b[0m\n", indentPrompt, ntsd.OffsetDacl)
	fmt.Printf("%s └─\n", indentPrompt)
}
