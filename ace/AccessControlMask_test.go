package ace

import (
	"testing"
)

// TestAccessControlMask_Involution tests the involution property of the AccessControlMask's ToBytes and Parse methods.
func TestAccessControlMask_Involution(t *testing.T) {
	originalMask := AccessControlMask{
		RawValue: 0x12345678,
	}

	// Serialize the original mask to bytes
	serializedBytes := originalMask.ToBytes()

	// Parse the serialized bytes back into a new mask
	var parsedMask AccessControlMask
	parsedMask.Parse(serializedBytes)

	// Check if the parsed mask matches the original mask
	if originalMask.RawValue != parsedMask.RawValue {
		t.Errorf("Involution test failed: expected 0x%08x, got 0x%08x", originalMask.RawValue, parsedMask.RawValue)
	}
}
