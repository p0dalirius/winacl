package windows

// PropertySet is an enumeration of GUIDs representing various property sets in Active Directory.
// These property sets group related properties of AD objects, making it easier to manage and apply permissions to these properties.
// Each entry in this enumeration maps a human-readable name to the corresponding GUID of the property set.
// These GUIDs are used in Access Control Entries (ACEs) to grant or deny permissions to read or write a set of properties on AD objects.
//
// The GUIDs are defined by Microsoft and can be found in the Microsoft documentation and technical specifications.
// Property sets are a crucial part of the Active Directory schema and help in defining the security model by allowing fine-grained access control.
//
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca
const (
	PROPERTY_SET_DOMAIN_PASSWORD_AND_LOCKOUT_POLICIES   = "c7407360-20bf-11d0-a768-00aa006e0529"
	PROPERTY_SET_GENERAL_INFORMATION                    = "59ba2f42-79a2-11d0-9020-00c04fc2d3cf"
	PROPERTY_SET_ACCOUNT_RESTRICTIONS                   = "4c164200-20c0-11d0-a768-00aa006e0529"
	PROPERTY_SET_LOGON_INFORMATION                      = "5f202010-79a5-11d0-9020-00c04fc2d4cf"
	PROPERTY_SET_GROUP_MEMBERSHIP                       = "bc0ac240-79a9-11d0-9020-00c04fc2d4cf"
	PROPERTY_SET_PHONE_AND_MAIL_OPTIONS                 = "e45795b2-9455-11d1-aebd-0000f80367c1"
	PROPERTY_SET_PERSONAL_INFORMATION                   = "77b5b886-944a-11d1-aebd-0000f80367c1"
	PROPERTY_SET_WEB_INFORMATION                        = "e45795b3-9455-11d1-aebd-0000f80367c1"
	PROPERTY_SET_PUBLIC_INFORMATION                     = "e48d0154-bcf8-11d1-8702-00c04fb96050"
	PROPERTY_SET_REMOTE_ACCESS_INFORMATION              = "037088f8-0ae1-11d2-b422-00a0c968f939"
	PROPERTY_SET_OTHER_DOMAIN_PARAMETERS_FOR_USE_BY_SAM = "b8119fd0-04f6-4762-ab7a-4986c76b3f9a"
	PROPERTY_SET_DNS_HOST_NAME_ATTRIBUTES               = "72e39547-7b18-11d1-adef-00c04fd8d5cd"
	PROPERTY_SET_MS_TS_GATEWAYACCESS                    = "ffa6f046-ca4b-4feb-b40d-04dfee722543"
	PROPERTY_SET_PRIVATE_INFORMATION                    = "91e647de-d96f-4b70-9557-d63ff4f3ccd8"
	PROPERTY_SET_TERMINAL_SERVER_LICENSE_SERVER         = "5805bc62-bdc9-4428-a5e2-856a0f4c185e"
)
