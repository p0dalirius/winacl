package securitydescriptor

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNtSecurityDescriptorControl_Involution(t *testing.T) {
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uint16(NT_SECURITY_DESCRIPTOR_CONTROL_SR|NT_SECURITY_DESCRIPTOR_CONTROL_SP))

	control := &NtSecurityDescriptorControl{}
	control.FromBytes(serializedData)
	data := control.ToBytes()

	if !bytes.Equal(data, serializedData) {
		t.Errorf("NtSecurityDescriptorControl.ToBytes() failed: Output of header.ToBytes() is not equal to input rawBytes")
	}
}

func TestNtSecurityDescriptorControl_FromBytes(t *testing.T) {
	uintValue := uint16(NT_SECURITY_DESCRIPTOR_CONTROL_SR | NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uintValue)
	expectedFlags := []uint16{NT_SECURITY_DESCRIPTOR_CONTROL_SP, NT_SECURITY_DESCRIPTOR_CONTROL_SR}

	control := &NtSecurityDescriptorControl{}
	control.FromBytes(serializedData)

	if control.RawValue != uintValue {
		t.Errorf("Expected RawValue to be 0x%04x, but got 0x%04x", uintValue, control.RawValue)
	}

	if len(control.Flags) != len(expectedFlags) {
		t.Errorf("Expected %d flags, but got %d", len(expectedFlags), len(control.Flags))
	}

	for _, flag := range expectedFlags {
		if !control.HasControl(flag) {
			t.Errorf("Expected flag %s (%d), but it was not found", NtSecurityDescriptorControlValueToShortName[flag], flag)
		}
	}
}

func TestNtSecurityDescriptorControl_ToBytes(t *testing.T) {
	uintValue := uint16(NT_SECURITY_DESCRIPTOR_CONTROL_SR | NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	serializedData := make([]byte, 2)
	binary.LittleEndian.PutUint16(serializedData, uintValue)

	control := &NtSecurityDescriptorControl{}
	control.FromBytes(serializedData)
	serializedData = control.ToBytes()

	if !bytes.Equal(serializedData, serializedData) {
		t.Errorf("Expected serialized data length to be 2, but got %d", len(serializedData))
	}

	deserializedValue := binary.LittleEndian.Uint16(serializedData)
	if deserializedValue != uintValue {
		t.Errorf("Expected deserialized value to be 0x%04x, but got 0x%04x", uintValue, deserializedValue)
	}
}

func TestNtSecurityDescriptorControl_HasControl(t *testing.T) {
	uintValue := uint16(NT_SECURITY_DESCRIPTOR_CONTROL_SR | NT_SECURITY_DESCRIPTOR_CONTROL_SP)
	rawValue := make([]byte, 2)
	binary.LittleEndian.PutUint16(rawValue, uintValue)
	controlFlag := uint16(NT_SECURITY_DESCRIPTOR_CONTROL_SR)

	control := &NtSecurityDescriptorControl{}
	control.FromBytes(rawValue)

	if !control.HasControl(controlFlag) {
		t.Errorf("Expected control flag 0x%04x to be set, but it was not", controlFlag)
	}

	nonExistentFlag := uint16(NT_SECURITY_DESCRIPTOR_CONTROL_RM)
	if control.HasControl(nonExistentFlag) {
		t.Errorf("Expected control flag 0x%04x to not be set, but it was", nonExistentFlag)
	}
}
