package ace

import (
	"fmt"
	"slices"
	"strings"

	"github.com/p0dalirius/winacl/identity"
	"github.com/p0dalirius/winacl/object"
)

type AccessControlEntry struct {
	Index                   uint16
	Header                  AccessControlEntryHeader
	Mask                    AccessControlMask
	SID                     identity.Identity
	AccessControlObjectType object.AccessControlObjectType
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (ace *AccessControlEntry) Parse(RawBytes []byte) {
	ace.RawBytesSize = 0

	// Parse Header
	ace.Header.Parse(RawBytes)
	ace.RawBytes = RawBytes
	RawBytes = RawBytes[ace.Header.RawBytesSize:]
	ace.RawBytesSize += ace.Header.RawBytesSize

	switch ace.Header.Type.Value {
	case ACE_TYPE_ACCESS_ALLOWED:
		// Parsing ACE of type ACCESS_ALLOWED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_ACCESS_DENIED:
		// Parsing ACE of type ACCESS_DENIED_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_AUDIT:
		// Parsing ACE of type SYSTEM_AUDIT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/9431fd0f-5b9a-47f0-b3f0-3015e2d0d4f9

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_ALARM:
		// Parsing ACE of type SYSTEM_ALARM_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
		// Parsing ACE of type ACCESS_ALLOWED_COMPOUND_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_ACCESS_DENIED_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary
	case ACE_TYPE_SYSTEM_ALARM_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586

	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_DENIED_CALLBACK:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/35adad6b-fda5-4cc1-b1b5-9beda5b07d2e

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		// Source:

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		// Parsing ACE of type ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		// Source:

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_ALARM_CALLBACK:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		ace.AccessControlObjectType.Parse(RawBytes)
		RawBytes = RawBytes[ace.AccessControlObjectType.RawBytesSize:]
		ace.RawBytesSize += ace.AccessControlObjectType.RawBytesSize
		// Flags  (4 bytes): A 32-bit unsigned integer that specifies a set of bit flags that
		// indicate whether the ObjectType and InheritedObjectType fields contain valid data.
		// This parameter can be one or more of the following values.

		// ObjectType (16 bytes): A GUID that identifies a property set, property, extended right,
		// or type of child object. The purpose of this GUID depends on the user rights specified
		// in the Mask field. This field is valid only if the ACE_OBJECT_TYPE_PRESENT bit is set
		// in the Flags field. Otherwise, the ObjectType field is ignored.

		// InheritedObjectType (16 bytes): A GUID that identifies the type of child object that
		// can inherit the ACE. Inheritance is also controlled by the inheritance flags in the
		// ACE_HEADER, as well as by any protection against inheritance placed on the child
		// objects. This field is valid only if the ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set
		// in the Flags member. Otherwise, the InheritedObjectType field is ignored.

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
		// Parsing ACE of type SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
		// Source: ?

		// Reserved for future use.
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
		// No parsing required as it is reserved for future use.

	case ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		// Parsing ACE of type SYSTEM_MANDATORY_LABEL_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		// Parsing ACE of type SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	case ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		// Parsing ACE of type SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/aa0c0f62-4b4c-44f0-9718-c266a6accd9f

		// Mask (4 bytes): An ACCESS_MASK that specifies the user rights allowed by this ACE.
		ace.Mask.Parse(RawBytes)
		RawBytes = RawBytes[ace.Mask.RawBytesSize:]
		ace.RawBytesSize += ace.Mask.RawBytesSize

		// Sid (variable): The SID of a trustee. The length of the SID MUST be a multiple of 4.
		ace.SID.Parse(RawBytes)
		ace.RawBytesSize += ace.SID.SID.RawBytesSize

		// ApplicationData (variable): Optional application data. The size of the application
		// data is determined by the AceSize field of the ACE_HEADER.
		// TODO: Parse ApplicationData if necessary

	default:
		//
	}

	// Crop to content
	ace.RawBytes = ace.RawBytes[:ace.RawBytesSize]
}

// IsInherited checks whether the Access Control Entry (ACE) is inherited
// from a parent object. This is determined by checking if the ACE_FLAG_INHERITED
// is present in the Flags.Values slice of the ACE header.
//
// Returns:
// - bool: true if the ACE is inherited, false otherwise.
func (ace *AccessControlEntry) IsInherited() bool {
	return slices.Contains(ace.Header.Flags.Values, ACE_FLAG_INHERITED)
}

// HasFlag checks if a specific flag is set within the ACE's flags.
//
// Parameters:
// - flag: The integer value of the flag to check.
//
// Returns:
// - bool: true if the specified flag is set, false otherwise.
func (ace *AccessControlEntry) HasFlag(flag uint8) bool {
	return slices.Contains(ace.Header.Flags.Values, flag)
}

func (ace *AccessControlEntry) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlEntry #%d>\n", indentPrompt, ace.Index)
	ace.Header.Describe(indent + 1)

	switch ace.Header.Type.Value {
	case ACE_TYPE_ACCESS_ALLOWED:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM:
	case ACE_TYPE_ACCESS_ALLOWED_COMPOUND:
	case ACE_TYPE_ACCESS_ALLOWED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_OBJECT:
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK:
	case ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT:
		ace.Mask.Describe(indent + 1)
		ace.AccessControlObjectType.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT:
	case ACE_TYPE_SYSTEM_MANDATORY_LABEL:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	case ACE_TYPE_SYSTEM_SCOPED_POLICY_ID:
		ace.Mask.Describe(indent + 1)
		ace.SID.Describe(indent + 1)
	}

	fmt.Printf("%s └─\n", indentPrompt)
}
