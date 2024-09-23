package identity

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

type SecurityIdentifierAuthority struct {
	Name  string
	Value int
}

func (sia *SecurityIdentifierAuthority) Parse(flagValue int) {
	sia.Value = flagValue

	if flagValue == SID_AUTHORITY_NULL {
		sia.Name = "Null"
	} else if flagValue == SID_AUTHORITY_WORLD {
		sia.Name = "World"
	} else if flagValue == SID_AUTHORITY_LOCAL {
		sia.Name = "Local"
	} else if flagValue == SID_AUTHORITY_CREATOR {
		sia.Name = "Creator"
	} else if flagValue == SID_AUTHORITY_NON_UNIQUE {
		sia.Name = "Non Unique"
	} else if flagValue == SID_AUTHORITY_SECURITY_NT {
		sia.Name = "NT\\Authority"
	} else if flagValue == SID_AUTHORITY_SECURITY_MANDATORY_LABEL {
		sia.Name = "Security Mandatory Label"
	} else if flagValue == SID_AUTHORITY_SECURITY_SCOPED_POLICY_ID {
		sia.Name = "Security Scoped Policy ID"
	} else if flagValue == SID_AUTHORITY_SECURITY_AUTHENTICATION {
		sia.Name = "Security Authentication"
	} else {
		sia.Name = "?"
	}
}
