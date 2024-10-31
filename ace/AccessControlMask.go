package ace

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/p0dalirius/winacl/rights"
)

// AccessControlMask represents a mask for access control entries.
// It contains the raw value, a list of individual flags represented as uint32 values,
// and their corresponding names for better readability.
type AccessControlMask struct {
	RawValue uint32   // The raw value of the access control mask
	Values   []uint32 // Individual flag values extracted from the mask
	Flags    []string // Names of the flags corresponding to their values
	// Internal fields
	RawBytes     []byte // Raw byte representation of the mask
	RawBytesSize uint32 // Size of the raw bytes
}

// Parse populates the AccessControlMask from raw byte data.
// It extracts the RawValue and determines the corresponding flags and their names.
func (acm *AccessControlMask) Parse(RawBytes []byte) {
	// Store the raw bytes and set the size
	acm.RawBytes = RawBytes
	acm.RawBytesSize = 4

	// Convert raw bytes to a uint32 value using little-endian format
	acm.RawValue = binary.LittleEndian.Uint32(RawBytes[:acm.RawBytesSize])

	// Prepare a list of right names and sort them for consistent ordering
	listOfRightNames := make([]string, 0, len(rights.RightValueToRightName))
	for _, RightName := range rights.RightValueToRightName {
		listOfRightNames = append(listOfRightNames, RightName)
	}
	sort.Strings(listOfRightNames)

	// Initialize slices for flags and values
	acm.Flags = make([]string, 0)
	acm.Values = make([]uint32, 0)

	// Parse flags based on the sorted right names
	for _, RightName := range listOfRightNames {
		RightValue := rights.RightNameToRightValue[RightName]
		// Check if the corresponding right is set in the RawValue
		if (acm.RawValue & RightValue) == RightValue {
			acm.Flags = append(acm.Flags, RightName)    // Add the name of the right
			acm.Values = append(acm.Values, RightValue) // Add the value of the right
		}
	}
}

// HasRight checks if a specific right is set within the ACE's Mask.
//
// Parameters:
// - right: The integer value of the right to check.
//
// Returns:
// - bool: true if the specified right is set, false otherwise.
func (acm *AccessControlMask) HasRight(right uint32) bool {
	return slices.Contains(acm.Values, right)
}

// Describe outputs the AccessControlMask details in a formatted manner.
// It displays the raw mask value and the associated flags.
func (acm *AccessControlMask) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<AccessControlMask>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mMask\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, acm.RawValue, strings.Join(acm.Flags, "|"))
	fmt.Printf("%s └─\n", indentPrompt)
}
