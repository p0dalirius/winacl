package ace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type AccessControlEntryHeader struct {
	AceType  AccessControlEntryType
	AceFlags AccessControlEntryFlag
	AceSize  uint16
}

func (aceheader *AccessControlEntryHeader) Parse(RawBytes []byte) {
	aceheader.AceType.Parse(int(RawBytes[0]))

	aceheader.AceFlags.Parse(int(RawBytes[1]))

	aceheader.AceSize = binary.LittleEndian.Uint16(RawBytes[2:4])
}

func (aceheader *AccessControlEntryHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<AccessControlEntryHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mAceType\x1b[0m  : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.AceType.Value, aceheader.AceType.Name)
	fmt.Printf("%s │ \x1b[93mAceFlags\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.AceFlags.Value, aceheader.AceFlags.Name)
	fmt.Printf("%s │ \x1b[93mAceSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, aceheader.AceSize)
	fmt.Printf("%s └─\n", indentPrompt)
}
