package identity

// SID authority constants define the various authorities used in Security Identifiers (SIDs),
// represented as hexadecimal values.
//
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
const (
	SID_AUTHORITY_NULL                      = 0x00
	SID_AUTHORITY_WORLD                     = 0x01
	SID_AUTHORITY_LOCAL                     = 0x02
	SID_AUTHORITY_CREATOR                   = 0x03
	SID_AUTHORITY_NON_UNIQUE                = 0x04
	SID_AUTHORITY_SECURITY_NT               = 0x05
	SID_AUTHORITY_SECURITY_APP_PACKAGE      = 0x0f
	SID_AUTHORITY_SECURITY_MANDATORY_LABEL  = 0x10
	SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID = 0x11
	SID_AUTHORITY_SECURITY_AUTHENTICATION   = 0x12
)

// sidAuthorityNames maps integer constants representing various security identifier (SID) authorities
// to their corresponding human-readable names.
//
// Usage:
//
//	This map allows for quick lookup of a SID authority's name by its integer identifier, aiding in
//	the readability and interpretation of SID authorities.
var sidAuthorityNames = map[int]string{
	SID_AUTHORITY_NULL:                      "Null",
	SID_AUTHORITY_WORLD:                     "World",
	SID_AUTHORITY_LOCAL:                     "Local",
	SID_AUTHORITY_CREATOR:                   "Creator",
	SID_AUTHORITY_NON_UNIQUE:                "Non Unique",
	SID_AUTHORITY_SECURITY_NT:               "NT\\Authority",
	SID_AUTHORITY_SECURITY_APP_PACKAGE:      "App Package",
	SID_AUTHORITY_SECURITY_MANDATORY_LABEL:  "Security Mandatory Label",
	SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID: "Security Scoped Policy ID",
	SID_AUTHORITY_SECURITY_AUTHENTICATION:   "Security Authentication",
}

// SecurityIdentifierAuthority represents an authority within a Security Identifier (SID),
// containing a human-readable name and an integer value.
//
// Fields:
//   - Name: A string representing the name of the authority.
//   - Value: An integer that uniquely identifies the authority.
type SecurityIdentifierAuthority struct {
	Name  string
	Value int
}

// Parse assigns a value and a name to the SecurityIdentifierAuthority (SIA) instance
// based on the provided integer flag value.
//
// Parameters:
//   - flagValue: An integer representing the authority identifier. This value is
//     used to look up the corresponding name in the sidAuthorityNames map.
//
// Behavior:
//   - Sets the `Value` field of the SIA instance to `flagValue`.
//   - Attempts to retrieve a corresponding name from the `sidAuthorityNames` map.
//     If found, assigns the retrieved name to the `Name` field.
//     If not found, assigns a default value of "?" to `Name`.
func (sia *SecurityIdentifierAuthority) Parse(flagValue int) {
	sia.Value = flagValue
	if name, found := sidAuthorityNames[flagValue]; found {
		sia.Name = name
	} else {
		sia.Name = "?"
	}
}
