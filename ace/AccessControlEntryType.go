package ace

const (
	ACE_TYPE_ACCESS_ALLOWED                 = 0x00 // Access-allowed ACE that uses the ACCESS_ALLOWED_ACE (section 2.4.4.2) structure.
	ACE_TYPE_ACCESS_DENIED                  = 0x01 // Access-denied ACE that uses the ACCESS_DENIED_ACE (section 2.4.4.4) structure.
	ACE_TYPE_SYSTEM_AUDIT                   = 0x02 // System-audit ACE that uses the SYSTEM_AUDIT_ACE (section 2.4.4.10) structure.
	ACE_TYPE_SYSTEM_ALARM                   = 0x03 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_COMPOUND        = 0x04 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_OBJECT          = 0x05 // Object-specific access-allowed ACE that uses the ACCESS_ALLOWED_OBJECT_ACE (section 2.4.4.3) structure.
	ACE_TYPE_ACCESS_DENIED_OBJECT           = 0x06 // Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE (section 2.4.4.5) structure.
	ACE_TYPE_SYSTEM_AUDIT_OBJECT            = 0x07 // Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE (section 2.4.4.11) structure.
	ACE_TYPE_SYSTEM_ALARM_OBJECT            = 0x08 // Reserved for future use.
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK        = 0x09 // Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE (section 2.4.4.6) structure.
	ACE_TYPE_ACCESS_DENIED_CALLBACK         = 0x0A // Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE (section 2.4.4.7) structure.
	ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT = 0x0B // Object-specific access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_OBJECT_ACE (section 2.4.4.8) structure.
	ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT  = 0x0C // Object-specific access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_OBJECT_ACE (section 2.4.4.9) structure.
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK          = 0x0D // System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE (section 2.4.4.12) structure.
	ACE_TYPE_SYSTEM_ALARM_CALLBACK          = 0x0E // Reserved for future use.
	ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT   = 0x0F // Object-specific system-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_OBJECT_ACE (section 2.4.4.14) structure.
	ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT   = 0x10 // Reserved for future use.
	ACE_TYPE_SYSTEM_MANDATORY_LABEL         = 0x11 // Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE (section 2.4.4.13) structure.
	ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE      = 0x12 // Resource attribute ACE that uses the SYSTEM_RESOURCE_ATTRIBUTE_ACE (section 2.4.4.15).
	ACE_TYPE_SYSTEM_SCOPED_POLICY_ID        = 0x13 // A central policy ID ACE that uses the SYSTEM_SCOPED_POLICY_ID_ACE (section 2.4.4.16).

)

type AccessControlEntryType struct {
	Name  string
	Value int
}

func (acetype *AccessControlEntryType) Parse(flagValue int) {
	acetype.Value = flagValue

	if flagValue == ACE_TYPE_ACCESS_ALLOWED {
		acetype.Name = "ACCESS_ALLOWED"
	} else if flagValue == ACE_TYPE_ACCESS_DENIED {
		acetype.Name = "ACCESS_DENIED"
	} else if flagValue == ACE_TYPE_SYSTEM_AUDIT {
		acetype.Name = "SYSTEM_AUDIT"
	} else if flagValue == ACE_TYPE_SYSTEM_ALARM {
		acetype.Name = "SYSTEM_ALARM"
	} else if flagValue == ACE_TYPE_ACCESS_ALLOWED_COMPOUND {
		acetype.Name = "ACCESS_ALLOWED_COMPOUND"
	} else if flagValue == ACE_TYPE_ACCESS_ALLOWED_OBJECT {
		acetype.Name = "ACCESS_ALLOWED_OBJECT"
	} else if flagValue == ACE_TYPE_ACCESS_DENIED_OBJECT {
		acetype.Name = "ACCESS_DENIED_OBJECT"
	} else if flagValue == ACE_TYPE_SYSTEM_AUDIT_OBJECT {
		acetype.Name = "SYSTEM_AUDIT_OBJECT"
	} else if flagValue == ACE_TYPE_SYSTEM_ALARM_OBJECT {
		acetype.Name = "SYSTEM_ALARM_OBJECT"
	} else if flagValue == ACE_TYPE_ACCESS_ALLOWED_CALLBACK {
		acetype.Name = "ACCESS_ALLOWED_CALLBACK"
	} else if flagValue == ACE_TYPE_ACCESS_DENIED_CALLBACK {
		acetype.Name = "ACCESS_DENIED_CALLBACK"
	} else if flagValue == ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT {
		acetype.Name = "ACCESS_ALLOWED_CALLBACK_OBJECT"
	} else if flagValue == ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT {
		acetype.Name = "ACCESS_DENIED_CALLBACK_OBJECT"
	} else if flagValue == ACE_TYPE_SYSTEM_AUDIT_CALLBACK {
		acetype.Name = "SYSTEM_AUDIT_CALLBACK"
	} else if flagValue == ACE_TYPE_SYSTEM_ALARM_CALLBACK {
		acetype.Name = "SYSTEM_ALARM_CALLBACK"
	} else if flagValue == ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT {
		acetype.Name = "SYSTEM_AUDIT_CALLBACK_OBJECT"
	} else if flagValue == ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT {
		acetype.Name = "SYSTEM_ALARM_CALLBACK_OBJECT"
	} else if flagValue == ACE_TYPE_SYSTEM_MANDATORY_LABEL {
		acetype.Name = "SYSTEM_MANDATORY_LABEL"
	} else if flagValue == ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE {
		acetype.Name = "SYSTEM_RESOURCE_ATTRIBUTE"
	} else if flagValue == ACE_TYPE_SYSTEM_SCOPED_POLICY_ID {
		acetype.Name = "SYSTEM_SCOPED_POLICY_ID"
	} else {
		acetype.Name = "?"
	}
}
