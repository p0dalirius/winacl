package ace

import (
	"testing"
)

// TestAccessControlEntryType_Involution tests the involution property of the AccessControlEntryType's ToBytes and Parse methods.
func TestAccessControlEntryType_Involution(t *testing.T) {
	originalType := AccessControlEntryType{
		Value: 0x05,
	}

	// Serialize the original type to bytes
	serializedBytes := originalType.ToBytes()

	// Parse the serialized bytes back into a new type
	var parsedType AccessControlEntryType
	parsedType.Parse(serializedBytes)

	// Check if the parsed type matches the original type
	if originalType.Value != parsedType.Value {
		t.Errorf("Involution test failed: expected 0x%02x, got 0x%02x", originalType.Value, parsedType.Value)
	}
}
