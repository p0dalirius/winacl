package object

import (
	"fmt"
	"strings"
	"winacl/guid"
)

type InheritedObjectType struct {
	Name string
	GUID guid.GUID
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (inheritedObjType *InheritedObjectType) Parse(RawBytes []byte) {
	inheritedObjType.RawBytes = RawBytes
	inheritedObjType.RawBytesSize = 16
	inheritedObjType.GUID.FromRawBytes(RawBytes)
}

func (inheritedObjType *InheritedObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<InheritedObjectType>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, inheritedObjType.GUID.ToFormatD())

	fmt.Printf("%s └─\n", indentPrompt)
}
