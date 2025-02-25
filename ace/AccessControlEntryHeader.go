package ace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// AccessControlEntryHeader represents the header of an Access Control Entry (ACE)
// in a security descriptor. This struct encapsulates the basic information about
// an ACE, including its type, associated flags, and size.
//
// The struct contains the following fields:
//
//   - Type: An AccessControlEntryType that specifies the type of the ACE (e.g.,
//     access allowed, access denied).
//
//   - Flags: An AccessControlEntryFlag that holds flags associated with the ACE,
//     indicating additional properties like inheritance and propagation.
//
//   - Size: A uint16 value representing the size of the ACE header, which is typically
//     used when processing lists of ACEs in a security descriptor.
//
// Internal fields:
//
//   - RawBytes: A byte slice that holds the raw bytes of the ACE header for low-level
//     processing or serialization purposes.
//
//   - RawBytesSize: A uint32 value indicating the actual size of the raw bytes stored
//     in RawBytes.
type AccessControlEntryHeader struct {
	Type  AccessControlEntryType
	Flags AccessControlEntryFlag
	Size  uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse populates the AccessControlEntryHeader struct fields from the provided raw byte slice.
// It extracts the ACE type, flags, and size from the raw byte data.
// The raw bytes are expected to follow the ACE structure format, where the first byte
// represents the ACE type, the second byte represents the flags, and the next two bytes
// represent the size of the ACE.
//
// Parameters:
//   - rawBytes: A byte slice containing the raw data from which to parse the ACE header.
//     It must be at least 4 bytes long to avoid index out of range errors.
func (aceheader *AccessControlEntryHeader) Parse(rawBytes []byte) {
	// Ensure that RawBytes has sufficient length
	if len(rawBytes) < 4 {
		return // or handle the error appropriately (e.g., log, panic, etc.)
	}

	// Initialize RawBytesSize
	aceheader.RawBytesSize = 0
	aceheader.RawBytes = rawBytes

	// Parse the ACE type from the first byte
	aceheader.Type.Parse(rawBytes[:1])

	// Parse the ACE flags from the second byte
	aceheader.Flags.Parse(rawBytes[1:2])

	// Read the size of the ACE from bytes 2 and 3
	aceheader.Size = binary.LittleEndian.Uint16(rawBytes[2:4])

	// Set the raw bytes size to 4 since we've read 4 bytes for the header
	aceheader.RawBytesSize = 4
	aceheader.RawBytes = rawBytes[:aceheader.RawBytesSize]
}

// ToBytes serializes the AccessControlEntryHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the ACE header.
func (aceheader *AccessControlEntryHeader) ToBytes() []byte {
	serializedData := make([]byte, 0)

	serializedData = append(serializedData, aceheader.Type.ToBytes()...)
	serializedData = append(serializedData, aceheader.Flags.ToBytes()...)
	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, aceheader.Size)
	serializedData = append(serializedData, buffer...)

	return serializedData
}

// Describe prints a human-readable representation of the AccessControlEntryHeader struct.
// It displays the type, flags, and size of the access control entry, formatted with indentation
// to reflect the structure's hierarchy in a tree-like manner.
//
// Parameters:
//   - indent: An integer that specifies the level of indentation for the output,
//     allowing for better visualization of nested structures.
func (aceheader *AccessControlEntryHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<AccessControlEntryHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mType\x1b[0m  : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.Type.Value, aceheader.Type.String())
	fmt.Printf("%s │ \x1b[93mFlags\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, aceheader.Flags.RawValue, strings.Join(aceheader.Flags.Flags, "|"))
	fmt.Printf("%s │ \x1b[93mSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, aceheader.Size)
	fmt.Printf("%s └─\n", indentPrompt)
}
