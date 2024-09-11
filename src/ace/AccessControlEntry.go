package ace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type AccessControlEntry struct {
	AceIndex uint16
	Header   AccessControlEntryHeader
	Mask     uint32
	Sid      string
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (ace *AccessControlEntry) Parse(RawBytes []byte) {
	ace.Header.Parse(RawBytes)

	ace.RawBytesSize = 0

	if ace.Header.AceType.Value == ACE_TYPE_ACCESS_ALLOWED {
		// Parsing ACE of type ACCESS_ALLOWED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask = binary.LittleEndian.Uint32(RawBytes[:4])
		RawBytes = RawBytes[4:]
		ace.RawBytesSize += 4

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.Sid = string(RawBytes)
	}
}

func (ace *AccessControlEntry) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlEntry #%d>\n", indentPrompt, ace.AceIndex)

	ace.Header.Describe(indent + 1)

	fmt.Printf("%s └─\n", indentPrompt)
}
