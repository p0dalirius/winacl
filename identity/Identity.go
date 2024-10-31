package identity

import (
	"fmt"
	"strings"
)

// Identity represents a user identity, including its name and associated Security Identifier (SID).
//
// Attributes:
//   - Name (string): The name of the identity, typically representing a user or group.
//   - SID (SID): The Security Identifier associated with the identity, used for access control.
//
// Internal attributes:
//   - RawBytes ([]byte): The raw byte data representing the identity, including the SID information.
//   - RawBytesSize (uint32): The size of the raw byte data.
type Identity struct {
	Name string
	SID  SID
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Parse populates the Identity struct by parsing the provided raw byte slice.
// It extracts the SID from the raw bytes and attempts to assign a name if the SID is well-known.
//
// Parameters:
//   - RawBytes ([]byte): The raw byte data containing the SID information.
func (identity *Identity) Parse(RawBytes []byte) {
	identity.RawBytes = RawBytes

	identity.SID.FromBytes(RawBytes)

	sidString := identity.SID.ToString()
	if name, exists := WellKnownSIDs[sidString]; exists {
		identity.Name = name
	}

	identity.RawBytesSize = identity.SID.RawBytesSize
}

// Describe prints a detailed description of the Identity struct, including its SID and name,
// formatted with indentation for clarity.
//
// Parameters:
//   - indent (int): The indentation level for formatting the output. Each level increases
//     the indentation depth, allowing for a hierarchical display of the Identity's components.
func (identity *Identity) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<Identity>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mSID\x1b[0m  : \x1b[96m%s\x1b[0m\n", indentPrompt, identity.SID.ToString())
	//identity.SID.Describe(indent + 1)

	fmt.Printf("%s │ \x1b[93mName\x1b[0m : '\x1b[94m%s\x1b[0m'\n", indentPrompt, identity.Name)

	fmt.Printf("%s └─\n", indentPrompt)
}
