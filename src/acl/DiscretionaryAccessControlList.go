package acl

import (
	"fmt"
	"strings"
	"winacl/ace"
)

type DiscretionaryAccessControlList struct {
	Header  DiscretionaryAccessControlListHeader
	Entries []ace.AccessControlEntry
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (dacl *DiscretionaryAccessControlList) Parse(RawBytes []byte) {
	dacl.RawBytesSize = 0
	dacl.RawBytes = RawBytes

	dacl.Header.Parse(RawBytes)
	dacl.RawBytesSize += dacl.Header.RawBytesSize
	RawBytes = RawBytes[dacl.RawBytesSize:]

	// Parse all ACEs
	for index := 0; index < int(dacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		entry.Parse(RawBytes)
		entry.AceIndex = uint16(index + 1)
		dacl.Entries = append(dacl.Entries, entry)
		dacl.RawBytesSize += entry.RawBytesSize
		RawBytes = RawBytes[entry.RawBytesSize:]
	}
}

func (dacl *DiscretionaryAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<DiscretionaryAccessControlList>\n", indentPrompt)

	dacl.Header.Describe(indent + 1)

	for _, ace := range dacl.Entries {
		ace.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
