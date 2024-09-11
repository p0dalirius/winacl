package windows

// AccessMaskFlags: Enum class that defines constants for access mask flags.
//
// This class defines constants for various access mask flags as specified in the Microsoft documentation. These flags represent permissions or rights that can be granted or denied for security principals in access control entries (ACEs) of an access control list (ACL).
//
// The flags include permissions for creating or deleting child objects, listing contents, reading or writing properties, deleting a tree of objects, and controlling access. Additionally, it includes generic rights like GENERIC_ALL, GENERIC_EXECUTE, GENERIC_WRITE, and GENERIC_READ.
//
// The values for these flags are derived from the following Microsoft documentation sources:
// - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
// - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
// - https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum

const (
	ACCESSMASKFLAG_DS_CREATE_CHILD            = 0x00000001
	ACCESSMASKFLAG_DS_DELETE_CHILD            = 0x00000002
	ACCESSMASKFLAG_DS_LIST_CONTENTS           = 0x00000004
	ACCESSMASKFLAG_DS_WRITE_PROPERTY_EXTENDED = 0x00000008
	ACCESSMASKFLAG_DS_READ_PROPERTY           = 0x00000010
	ACCESSMASKFLAG_DS_WRITE_PROPERTY          = 0x00000020
	ACCESSMASKFLAG_DS_DELETE_TREE             = 0x00000040
	ACCESSMASKFLAG_DS_LIST_OBJECT             = 0x00000080
	ACCESSMASKFLAG_DS_CONTROL_ACCESS          = 0x00000100
	ACCESSMASKFLAG_DELETE                     = 0x00010000
	ACCESSMASKFLAG_READ_CONTROL               = 0x00020000
	ACCESSMASKFLAG_WRITE_DAC                  = 0x00040000
	ACCESSMASKFLAG_WRITE_OWNER                = 0x00080000
	ACCESSMASKFLAG_GENERIC_ALL                = 0x10000000
	ACCESSMASKFLAG_GENERIC_EXECUTE            = 0x20000000
	ACCESSMASKFLAG_GENERIC_WRITE              = 0x40000000
	ACCESSMASKFLAG_GENERIC_READ               = 0x80000000
)
