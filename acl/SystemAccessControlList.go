package acl

import (
	"fmt"
	"strings"
	"winacl/ace"
)

type SystemAccessControlList struct {
	Header  SystemAccessControlListHeader
	Entries []ace.AccessControlEntry
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (sacl *SystemAccessControlList) Parse(RawBytes []byte) {
	sacl.Header.Parse(RawBytes)

	sacl.RawBytesSize = 0
	sacl.RawBytes = RawBytes

	sacl.Header.Parse(RawBytes)
	sacl.RawBytesSize += sacl.Header.RawBytesSize
	RawBytes = RawBytes[sacl.RawBytesSize:]

	// Parse all ACEs
	for index := 0; index < int(sacl.Header.AceCount); index++ {
		entry := ace.AccessControlEntry{}
		entry.Parse(RawBytes)
		entry.Index = uint16(index + 1)
		sacl.Entries = append(sacl.Entries, entry)
		sacl.RawBytesSize += entry.RawBytesSize
		RawBytes = RawBytes[entry.RawBytesSize:]
	}

	sacl.RawBytes = sacl.RawBytes[:sacl.RawBytesSize]
}

func (sacl *SystemAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SystemAccessControlList>\n", indentPrompt)

	sacl.Header.Describe(indent + 1)

	for _, ace := range sacl.Entries {
		ace.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
