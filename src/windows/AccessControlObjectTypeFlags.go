package windows

// A set of bit flags that indicate whether the ObjectType and InheritedObjectType members are present. This parameter can be one or more of the following values.
//
// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
const (
	ACCESSCONTROLOBJECTTYPEFLAG_NONE                              = 0x00000000 // Neither ObjectType nor InheritedObjectType are valid.
	ACCESSCONTROLOBJECTTYPEFLAG_ACE_OBJECT_TYPE_PRESENT           = 0x00000001 // ObjectType is valid.
	ACCESSCONTROLOBJECTTYPEFLAG_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 // InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.
)
