package acl

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DiscretionaryAccessControlListHeader represents the header of a Discretionary Access Control List (DACL).
type DiscretionaryAccessControlListHeader struct {
	Revision AccessControlListRevision
	Sbz1     uint8
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse initializes the DiscretionaryAccessControlListHeader struct by parsing the raw byte slice.
// It sets the RawBytes and RawBytesSize fields, parses the header, and then parses each ACE.
//
// Parameters:
//   - rawBytes ([]byte): The raw byte slice to be parsed.
//
// Returns:
//   - error: An error if parsing fails, otherwise nil.
func (daclheader *DiscretionaryAccessControlListHeader) Parse(rawBytes []byte) error {
	// Parsing header
	if len(rawBytes) < 8 {
		return fmt.Errorf("invalid raw bytes length")
	}

	daclheader.RawBytes = rawBytes[:8]
	daclheader.RawBytesSize = 8

	daclheader.Revision.Parse(rawBytes[:1])
	daclheader.Sbz1 = rawBytes[1]
	daclheader.AclSize = binary.LittleEndian.Uint16(rawBytes[2:4])
	daclheader.AceCount = binary.LittleEndian.Uint16(rawBytes[4:6])
	daclheader.Sbz2 = binary.LittleEndian.Uint16(rawBytes[6:8])

	return nil
}

// ToBytes serializes the DiscretionaryAccessControlListHeader struct into a byte slice.
//
// Returns:
//   - []byte: The serialized byte slice representing the DACL header.
func (daclheader *DiscretionaryAccessControlListHeader) ToBytes() []byte {
	var serializedData []byte

	serializedData = append(serializedData, daclheader.Revision.ToBytes()...)
	serializedData = append(serializedData, daclheader.Sbz1)
	buffer := make([]byte, 2)
	binary.LittleEndian.PutUint16(buffer, daclheader.AclSize)
	serializedData = append(serializedData, buffer...)
	binary.LittleEndian.PutUint16(buffer, daclheader.AceCount)
	serializedData = append(serializedData, buffer...)
	binary.LittleEndian.PutUint16(buffer, daclheader.Sbz2)
	serializedData = append(serializedData, buffer...)

	return serializedData
}

// Describe prints a detailed description of the DiscretionaryAccessControlListHeader struct,
// including its attributes formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the DACL's components.
func (daclheader *DiscretionaryAccessControlListHeader) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<DiscretionaryAccessControlListHeader>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mRevision\x1b[0m : \x1b[96m0x%02x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, daclheader.Revision.Value, daclheader.Revision.String())
	fmt.Printf("%s │ \x1b[93mSbz1\x1b[0m     : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, daclheader.Sbz1)
	fmt.Printf("%s │ \x1b[93mAclSize\x1b[0m  : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, daclheader.AclSize)
	fmt.Printf("%s │ \x1b[93mAceCount\x1b[0m : \x1b[96m0x%04x (%d)\x1b[0m\n", indentPrompt, daclheader.AceCount, daclheader.AceCount)
	fmt.Printf("%s │ \x1b[93mSbz2\x1b[0m     : \x1b[96m0x%04x\x1b[0m\n", indentPrompt, daclheader.Sbz2)
	fmt.Printf("%s └─\n", indentPrompt)
}
