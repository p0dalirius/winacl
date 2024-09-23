package object

import (
	"fmt"
	"strings"

	"github.com/p0dalirius/winacl/guid"
)

type ObjectType struct {
	Name string
	GUID guid.GUID
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (objType *ObjectType) Parse(RawBytes []byte) {
	objType.RawBytes = RawBytes
	objType.RawBytesSize = 16
	objType.GUID.FromRawBytes(RawBytes)
}

func (objType *ObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<ObjectType>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mGUID\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, objType.GUID.ToFormatD())

	fmt.Printf("%s └─\n", indentPrompt)
}
