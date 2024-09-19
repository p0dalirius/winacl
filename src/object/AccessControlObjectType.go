package object

import (
	"fmt"
	"strings"
)

type AccessControlObjectType struct {
	Flags               AccessControlObjectTypeFlags
	ObjectType          ObjectType
	InheritedObjectType InheritedObjectType

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (aco *AccessControlObjectType) Parse(RawBytes []byte) {
	aco.RawBytesSize = 0

	aco.Flags.Parse(RawBytes[0:4])
	RawBytes = RawBytes[4:]
	aco.RawBytesSize += 4

	if aco.Flags.Value != ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		// Parse OBJECT_TYPE
		if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
			aco.ObjectType.Parse(RawBytes)
			aco.RawBytesSize += aco.ObjectType.RawBytesSize
			RawBytes = RawBytes[aco.ObjectType.RawBytesSize:]
		}

		// Parse INHERITED_OBJECT_TYPE
		if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
			aco.InheritedObjectType.Parse(RawBytes)
			aco.RawBytesSize += aco.InheritedObjectType.RawBytesSize
			// RawBytes = RawBytes[aco.InheritedObjectType.RawBytesSize:]
		}
	}
}

func (aco *AccessControlObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlObjectType>\n", indentPrompt)

	if aco.Flags.Value == (ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT | ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mObjectType\x1b[0m          : \x1b[96m%s\x1b[0m\n", indentPrompt, aco.ObjectType.GUID.ToFormatD())
		fmt.Printf("%s │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, aco.InheritedObjectType.GUID.ToFormatD())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, aco.InheritedObjectType.GUID.ToFormatD())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m      : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mObjectType\x1b[0m : \x1b[96m%s\x1b[0m\n", indentPrompt, aco.ObjectType.GUID.ToFormatD())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
	} else {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
