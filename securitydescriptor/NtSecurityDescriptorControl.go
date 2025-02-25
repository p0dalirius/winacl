package securitydescriptor

import "encoding/binary"

// NtSecurityDescriptorControl represents the control flags for a NT Security Descriptor.
// The fields are defined as constants to represent their bit positions.
type NtSecurityDescriptorControl struct {
	RawValue uint16
	Values   []uint16
	Flags    []string
}

// Control indexes in bit field
const (
	NT_SECURITY_DESCRIPTOR_CONTROL_SR uint16 = 1 << iota // Self-Relative
	NT_SECURITY_DESCRIPTOR_CONTROL_RM                    // RM Control Valid
	NT_SECURITY_DESCRIPTOR_CONTROL_PS                    // SACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_PD                    // DACL Protected
	NT_SECURITY_DESCRIPTOR_CONTROL_SI                    // SACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_DI                    // DACL Auto-Inherited
	NT_SECURITY_DESCRIPTOR_CONTROL_SC                    // SACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_DC                    // DACL Computed Inheritance Required
	NT_SECURITY_DESCRIPTOR_CONTROL_SS                    // Server Security
	NT_SECURITY_DESCRIPTOR_CONTROL_DT                    // DACL Trusted
	NT_SECURITY_DESCRIPTOR_CONTROL_SD                    // SACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_SP                    // SACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_DD                    // DACL Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_DP                    // DACL Present
	NT_SECURITY_DESCRIPTOR_CONTROL_GD                    // Group Defaulted
	NT_SECURITY_DESCRIPTOR_CONTROL_OD                    // Owner Defaulted
)

// Control flag map from value to string representation
var NtSecurityDescriptorControlValueToName = map[uint16]string{
	NT_SECURITY_DESCRIPTOR_CONTROL_SR: "Self-Relative",
	NT_SECURITY_DESCRIPTOR_CONTROL_RM: "RM Control Valid",
	NT_SECURITY_DESCRIPTOR_CONTROL_PS: "SACL Protected",
	NT_SECURITY_DESCRIPTOR_CONTROL_PD: "DACL Protected",
	NT_SECURITY_DESCRIPTOR_CONTROL_SI: "SACL Auto-Inherited",
	NT_SECURITY_DESCRIPTOR_CONTROL_DI: "DACL Auto-Inherited",
	NT_SECURITY_DESCRIPTOR_CONTROL_SC: "SACL Computed Inheritance Required",
	NT_SECURITY_DESCRIPTOR_CONTROL_DC: "DACL Computed Inheritance Required",
	NT_SECURITY_DESCRIPTOR_CONTROL_SS: "Server Security",
	NT_SECURITY_DESCRIPTOR_CONTROL_DT: "DACL Trusted",
	NT_SECURITY_DESCRIPTOR_CONTROL_SD: "SACL Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_SP: "SACL Present",
	NT_SECURITY_DESCRIPTOR_CONTROL_DD: "DACL Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_DP: "DACL Present",
	NT_SECURITY_DESCRIPTOR_CONTROL_GD: "Group Defaulted",
	NT_SECURITY_DESCRIPTOR_CONTROL_OD: "Owner Defaulted",
}

// Control flag map from value to string representation
var NtSecurityDescriptorControlValueToShortName = map[uint16]string{
	NT_SECURITY_DESCRIPTOR_CONTROL_SR: "SR",
	NT_SECURITY_DESCRIPTOR_CONTROL_RM: "RM",
	NT_SECURITY_DESCRIPTOR_CONTROL_PS: "PS",
	NT_SECURITY_DESCRIPTOR_CONTROL_PD: "PD",
	NT_SECURITY_DESCRIPTOR_CONTROL_SI: "SI",
	NT_SECURITY_DESCRIPTOR_CONTROL_DI: "DI",
	NT_SECURITY_DESCRIPTOR_CONTROL_SC: "SC",
	NT_SECURITY_DESCRIPTOR_CONTROL_DC: "DC",
	NT_SECURITY_DESCRIPTOR_CONTROL_SS: "SS",
	NT_SECURITY_DESCRIPTOR_CONTROL_DT: "DT",
	NT_SECURITY_DESCRIPTOR_CONTROL_SD: "SD",
	NT_SECURITY_DESCRIPTOR_CONTROL_SP: "SP",
	NT_SECURITY_DESCRIPTOR_CONTROL_DD: "DD",
	NT_SECURITY_DESCRIPTOR_CONTROL_DP: "DP",
	NT_SECURITY_DESCRIPTOR_CONTROL_GD: "GD",
	NT_SECURITY_DESCRIPTOR_CONTROL_OD: "OD",
}

// FromBytes initializes the NtSecurityDescriptorControl struct by setting its RawValue
// and extracting the individual control flags from it. It populates the Values and Flags slices
// based on the control flags that are present in the RawValue.
//
// Parameters:
//   - rawValue (uint16): The raw value to be parsed, representing the control flags as a bitmask.
func (nsdc *NtSecurityDescriptorControl) FromBytes(rawValue []byte) {
	nsdc.RawValue = binary.LittleEndian.Uint16(rawValue)
	nsdc.Values = []uint16{}
	nsdc.Flags = []string{}

	for flagValue, flagName := range NtSecurityDescriptorControlValueToShortName {
		if (nsdc.RawValue & flagValue) == flagValue {
			nsdc.Values = append(nsdc.Values, flagValue)
			nsdc.Flags = append(nsdc.Flags, flagName)
		}
	}
}

// ToBytes serializes the NtSecurityDescriptorControl struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the security descriptor control.
func (nsdc *NtSecurityDescriptorControl) ToBytes() []byte {
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, nsdc.RawValue)
	return serializedData
}

// HasControl checks if a specific control bit is set in the RawValue.
// Parameters:
//   - control (uint16): The control flag to check (NT_SECURITY_DESCRIPTOR_CONTROL_*).
//
// Returns:
//   - bool: True if the specified control bit is set, false otherwise.
func (nsdc *NtSecurityDescriptorControl) HasControl(control uint16) bool {
	return (nsdc.RawValue & control) == control
}
