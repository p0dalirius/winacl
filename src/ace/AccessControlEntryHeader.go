package ace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type AccessControlEntryHeader struct {
	Type  AccessControlEntryType
	Flags AccessControlEntryFlag
	Size  uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (aceheader *AccessControlEntryHeader) Parse(RawBytes []byte) {
	aceheader.RawBytesSize = 0

	aceheader.Type.Parse(int(RawBytes[0]))

	aceheader.Flags.Parse(int(RawBytes[1]))

	aceheader.Size = binary.LittleEndian.Uint16(RawBytes[2:4])

	aceheader.RawBytesSize = 4
}

func (aceheader *AccessControlEntryHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<AccessControlEntryHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mType\x1b[0m  : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.Type.Value, aceheader.Type.Name)
	fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.Flags.Value, aceheader.Flags.Name)
	fmt.Printf("%s │ \x1b[93mSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, aceheader.Size)
	fmt.Printf("%s └─\n", indentPrompt)
}
