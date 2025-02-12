package guid

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/p0dalirius/winacl/rights"
	"github.com/p0dalirius/winacl/schema"
)

// GUID represents a globally unique identifier (GUID).
// It consists of five fields: A, B, C, D, and E, which are used to store the components of the GUID.
//
// Fields:
// - A: A 32-bit unsigned integer representing the first part of the GUID.
// - B: A 16-bit unsigned integer representing the second part of the GUID.
// - C: A 16-bit unsigned integer representing the third part of the GUID.
// - D: A 16-bit unsigned integer representing the fourth part of the GUID.
// - E: A 64-bit unsigned integer representing the fifth part of the GUID.
type GUID struct {
	A uint32
	B uint16
	C uint16
	D uint16
	E uint64
}

// NewGUID generates a new random GUID.
//
// The function creates a new GUID by generating random values for each of its five fields:
// - A: A 32-bit unsigned integer.
// - B: A 16-bit unsigned integer.
// - C: A 16-bit unsigned integer.
// - D: A 16-bit unsigned integer.
// - E: A 64-bit unsigned integer.
//
// Returns:
// - A pointer to a newly generated GUID.
func NewGUID() *GUID {
	a := uint32(rand.Uint32())
	b := uint16(rand.Uint32() & 0xFFFF)
	c := uint16(rand.Uint32() & 0xFFFF)
	d := uint16(rand.Uint32() & 0xFFFF)
	e := uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
	return &GUID{A: a, B: b, C: c, D: d, E: e}
}

// Parse functions ===================================================================

// FromRawBytes parses a GUID from a raw byte array.
//
// The function takes a byte array and assigns the values to the GUID fields.
//
// Parameters:
// - data: A byte array containing the raw bytes of the GUID.
//
// Returns:
// - A pointer to the parsed GUID.
func (guid *GUID) FromRawBytes(data []byte) {
	guid.A = uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	guid.B = uint16(data[4]) | uint16(data[5])<<8
	guid.C = uint16(data[6]) | uint16(data[7])<<8
	guid.D = uint16(data[8])<<8 | uint16(data[9])
	guid.E = uint64(data[10])<<40 | uint64(data[11])<<32 | uint64(data[12])<<24 | uint64(data[13])<<16 | uint64(data[14])<<8 | uint64(data[15])
}

// FromFormatN parses a GUID from a string in the format N.
//
// The function takes a string and parses it into a GUID.
//
// Parameters:
// - data: A string containing the GUID in the format N.
//
// Returns:
// - A pointer to the parsed GUID.
// - An error if the string is not a valid GUID in the format N.
func FromFormatN(data string) (*GUID, error) {
	if len(data) != 32 {
		return nil, fmt.Errorf("GUID Format N should be 32 hexadecimal characters")
	}
	a, err := strconv.ParseUint(data[0:8], 16, 32)
	if err != nil {
		return nil, err
	}
	b, err := strconv.ParseUint(data[8:12], 16, 16)
	if err != nil {
		return nil, err
	}
	c, err := strconv.ParseUint(data[12:16], 16, 16)
	if err != nil {
		return nil, err
	}
	d, err := strconv.ParseUint(data[16:20], 16, 16)
	if err != nil {
		return nil, err
	}
	e, err := strconv.ParseUint(data[20:32], 16, 64)
	if err != nil {
		return nil, err
	}
	return &GUID{uint32(a), uint16(b), uint16(c), uint16(d), e}, nil
}

// FromFormatD parses a GUID from a string in the format D.
//
// The function takes a string and parses it into a GUID.
//
// Parameters:
// - data: A string containing the GUID in the format D.
//
// Returns:
// - A pointer to the parsed GUID.
// - An error if the string is not a valid GUID in the format D.
func FromFormatD(data string) (*GUID, error) {
	parts := strings.Split(data, "-")
	if len(parts) != 5 {
		return nil, fmt.Errorf("GUID Format D should be 32 hexadecimal characters separated in five parts")
	}
	a, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return nil, err
	}
	b, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, err
	}
	c, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return nil, err
	}
	d, err := strconv.ParseUint(parts[3], 16, 16)
	if err != nil {
		return nil, err
	}
	e, err := strconv.ParseUint(parts[4], 16, 64)
	if err != nil {
		return nil, err
	}
	return &GUID{uint32(a), uint16(b), uint16(c), uint16(d), e}, nil
}

// FromFormatB parses a GUID from a string in the format B.
//
// The function takes a string and parses it into a GUID.
//
// Parameters:
// - data: A string containing the GUID in the format B.
//
// Returns:
// - A pointer to the parsed GUID.
// - An error if the string is not a valid GUID in the format B.
func FromFormatB(data string) (*GUID, error) {
	if data[0] != '{' || data[len(data)-1] != '}' {
		return nil, fmt.Errorf("GUID Format B should be 32 hexadecimal characters separated in five parts enclosed in braces")
	}
	return FromFormatD(data[1 : len(data)-1])
}

// FromFormatP parses a GUID from a string in the format P.
//
// The function takes a string and parses it into a GUID.
//
// Parameters:
// - data: A string containing the GUID in the format P.
//
// Returns:
// - A pointer to the parsed GUID.
// - An error if the string is not a valid GUID in the format P.
func FromFormatP(data string) (*GUID, error) {
	if data[0] != '(' || data[len(data)-1] != ')' {
		return nil, fmt.Errorf("GUID Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses")
	}
	return FromFormatD(data[1 : len(data)-1])
}

// FromFormatX parses a GUID from a string in the format X.
//
// The function takes a string and parses it into a GUID.
//
// Parameters:
// - data: A string containing the GUID in the format X.
//
// Returns:
// - A pointer to the parsed GUID.
// - An error if the string is not a valid GUID in the format X.
func FromFormatX(data string) (*GUID, error) {
	if data[0] != '{' || data[len(data)-1] != '}' {
		return nil, fmt.Errorf("GUID Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}")
	}
	parts := strings.Split(data[1:len(data)-1], ",")
	if len(parts) != 4 {
		return nil, fmt.Errorf("GUID Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}")
	}
	a, err := strconv.ParseUint(parts[0][2:], 16, 32)
	if err != nil {
		return nil, err
	}
	b, err := strconv.ParseUint(parts[1][2:], 16, 16)
	if err != nil {
		return nil, err
	}
	c, err := strconv.ParseUint(parts[2][2:], 16, 16)
	if err != nil {
		return nil, err
	}
	subParts := strings.Split(parts[3][1:len(parts[3])-1], ",")
	if len(subParts) != 8 {
		return nil, fmt.Errorf("GUID Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}")
	}
	d1, err := strconv.ParseUint(subParts[0][2:], 16, 8)
	if err != nil {
		return nil, err
	}
	d2, err := strconv.ParseUint(subParts[1][2:], 16, 8)
	if err != nil {
		return nil, err
	}
	d := uint16(d1)<<8 | uint16(d2)
	e := uint64(0)
	for i := 2; i < 8; i++ {
		val, err := strconv.ParseUint(subParts[i][2:], 16, 8)
		if err != nil {
			return nil, err
		}
		e = e<<8 | val
	}
	return &GUID{uint32(a), uint16(b), uint16(c), d, e}, nil
}

// Export functions ===================================================================

// ToRawBytes returns the raw byte array representation of the GUID.
//
// The function converts the GUID into a byte array.
//
// Returns:
// - A byte array containing the raw bytes of the GUID.
func (guid *GUID) ToRawBytes() []byte {
	data := make([]byte, 0)
	data = append(data, byte(guid.A), byte(guid.A>>8), byte(guid.A>>16), byte(guid.A>>24))
	data = append(data, byte(guid.B), byte(guid.B>>8))
	data = append(data, byte(guid.C), byte(guid.C>>8))
	data = append(data, byte(guid.D>>8), byte(guid.D))
	eBytes := make([]byte, 6)

	for i := 0; i < 6; i++ {
		eBytes[5-i] = byte(guid.E >> (i * 8))
	}

	data = append(data, eBytes...)

	return data
}

// ToFormatN returns the GUID in the format N.
//
// The function converts the GUID into a string in the format N.
//
// Returns:
// - A string containing the GUID in the format N.
func (guid *GUID) ToFormatN() string {
	return fmt.Sprintf("%08x%04x%04x%04x%012x", guid.A, guid.B, guid.C, guid.D, guid.E)
}

// ToFormatD returns the GUID in the format D.
//
// The function converts the GUID into a string in the format D.
//
// Returns:
// - A string containing the GUID in the format D.
func (guid *GUID) ToFormatD() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", guid.A, guid.B, guid.C, guid.D, guid.E)
}

// ToFormatB returns the GUID in the format B.
//
// The function converts the GUID into a string in the format B.
//
// Returns:
// - A string containing the GUID in the format B.
func (guid *GUID) ToFormatB() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}", guid.A, guid.B, guid.C, guid.D, guid.E)
}

// ToFormatP returns the GUID in the format P.
//
// The function converts the GUID into a string in the format P.
//
// Returns:
// - A string containing the GUID in the format P.
func (guid *GUID) ToFormatP() string {
	return fmt.Sprintf("(%08x-%04x-%04x-%04x-%012x)", guid.A, guid.B, guid.C, guid.D, guid.E)
}

// ToFormatX returns the GUID in the format X.
//
// The function converts the GUID into a string in the format X.
//
// Returns:
// - A string containing the GUID in the format X.
func (guid *GUID) ToFormatX() string {
	hexD := fmt.Sprintf("%04x", guid.D)
	hexD1, hexD2 := hexD[:2], hexD[2:4]

	hexE := fmt.Sprintf("%012x", guid.E)
	hexE1, hexE2, hexE3, hexE4, hexE5, hexE6 := hexE[:2], hexE[2:4], hexE[4:6], hexE[6:8], hexE[8:10], hexE[10:12]

	return fmt.Sprintf("{0x%08x,0x%04x,0x%04x,{0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s}}",
		guid.A,
		guid.B,
		guid.C,
		hexD1, hexD2,
		hexE1, hexE2, hexE3, hexE4, hexE5, hexE6,
	)
}

// LookupName returns the name of the GUID if it is a well known GUID or a property set or a schema attribute
//
// The function takes a GUID and looks up the name of the GUID in the well known GUIDs, property sets, or schema attributes.
//
// Returns:
// - A string containing the name of the GUID.
// - "?" if the GUID is not found in the well known GUIDs, property sets, or schema attributes.
func (guid *GUID) LookupName() string {
	formatD := guid.ToFormatD()

	if name, exists := rights.GUIDToExtendedRight[formatD]; exists {
		return name
	} else if name, exists := schema.GUIDToPropertySet[formatD]; exists {
		return name
	} else if name, exists := schema.GUIDToSchemaAttributeDisplayName[formatD]; exists {
		return fmt.Sprintf("LDAP Attribute: %s", name)
	} else {
		return "?"
	}
}
