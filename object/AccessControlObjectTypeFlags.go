package object

import "encoding/binary"

// A set of bit flags that indicate whether the ObjectType and InheritedObjectType members are present. This parameter can be one or more of the following values.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace

const (
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE                          = 0x00000000 // Neither ObjectType nor InheritedObjectType are valid.
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT           = 0x00000001 // ObjectType is valid.
	ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 // InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.
)

type AccessControlObjectTypeFlags struct {
	Name  string
	Value uint32
}

func (acetype *AccessControlObjectTypeFlags) Parse(RawBytes []byte) {
	acetype.Value = binary.LittleEndian.Uint32(RawBytes[0:4])

	if acetype.Value == (ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT | ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) {
		acetype.Name = "OBJECT_TYPE_PRESENT|INHERITED_OBJECT_TYPE_PRESENT"
	} else if acetype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		acetype.Name = "INHERITED_OBJECT_TYPE_PRESENT"
	} else if acetype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		acetype.Name = "OBJECT_TYPE_PRESENT"
	} else if acetype.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		acetype.Name = "NONE"
	} else {
		acetype.Name = "?"
	}
}
