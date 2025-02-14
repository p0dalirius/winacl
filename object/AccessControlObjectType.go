package object

import (
	"fmt"
	"strings"
)

// AccessControlObjectType represents the access control object type.
type AccessControlObjectType struct {
	Flags               AccessControlObjectTypeFlags
	ObjectType          ObjectType
	InheritedObjectType InheritedObjectType

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse sets the Value of the AccessControlObjectType and looks up its name
// from a predefined map of ACE types to names. If the ACE type is not found
// in the map, it assigns the name as "?".
//
// Attributes:
//   - flagValue (int): The integer value representing the access control
//     entry type. This value is typically defined by the Windows security
//     model and indicates the type of access control entry.
func (aco *AccessControlObjectType) Parse(rawBytes []byte) {
	aco.RawBytesSize = 0

	aco.Flags.Parse(rawBytes[0:4])
	rawBytes = rawBytes[4:]
	aco.RawBytesSize += 4

	if aco.Flags.Value != ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		// Parse OBJECT_TYPE
		if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
			aco.ObjectType.Parse(rawBytes)
			aco.RawBytesSize += aco.ObjectType.RawBytesSize
			rawBytes = rawBytes[aco.ObjectType.RawBytesSize:]
		}

		// Parse INHERITED_OBJECT_TYPE
		if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
			aco.InheritedObjectType.Parse(rawBytes)
			aco.RawBytesSize += aco.InheritedObjectType.RawBytesSize
			// rawBytes = rawBytes[aco.InheritedObjectType.RawBytesSize:]
		}
	}
}

// ToBytes serializes the AccessControlObjectType struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the AccessControlObjectType.
func (aco *AccessControlObjectType) ToBytes() []byte {
	var serializedData []byte

	serializedData = append(serializedData, aco.Flags.ToBytes()...)

	if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		serializedData = append(serializedData, aco.ObjectType.GUID.ToBytes()...)
	}

	if (aco.Flags.Value & ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT) == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		serializedData = append(serializedData, aco.InheritedObjectType.GUID.ToBytes()...)
	}

	return serializedData
}

// Describe prints a human-readable representation of the AccessControlObjectType.
//
// Attributes:
//   - indent (int): The indentation level for the output.
func (aco *AccessControlObjectType) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlObjectType>\n", indentPrompt)

	if aco.Flags.Value == (ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT | ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT) {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mObjectType\x1b[0m          : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.ObjectType.GUID.ToFormatD(), aco.ObjectType.GUID.LookupName())
		fmt.Printf("%s │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.InheritedObjectType.GUID.ToFormatD(), aco.InheritedObjectType.GUID.LookupName())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_INHERITED_OBJECT_TYPE_PRESENT {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m               : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mInheritedObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.InheritedObjectType.GUID.ToFormatD(), aco.InheritedObjectType.GUID.LookupName())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_OBJECT_TYPE_PRESENT {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m      : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
		fmt.Printf("%s │ \x1b[93mObjectType\x1b[0m : \x1b[96m%s\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.ObjectType.GUID.ToFormatD(), aco.ObjectType.GUID.LookupName())
	} else if aco.Flags.Value == ACCESS_CONTROL_OBJECT_TYPE_FLAG_NONE {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
	} else {
		fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aco.Flags.Value, aco.Flags.Name)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
