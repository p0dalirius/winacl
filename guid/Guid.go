package guid

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/p0dalirius/winacl/rights"
	"github.com/p0dalirius/winacl/schema"
)

type GUID struct {
	A uint32
	B uint16
	C uint16
	D uint16
	E uint64
}

// Parse functions

func (guid *GUID) FromRawBytes(data []byte) {
	guid.A = uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	guid.B = uint16(data[4]) | uint16(data[5])<<8
	guid.C = uint16(data[6]) | uint16(data[7])<<8
	guid.D = uint16(data[8])<<8 | uint16(data[9])
	guid.E = uint64(data[10])<<40 | uint64(data[11])<<32 | uint64(data[12])<<24 | uint64(data[13])<<16 | uint64(data[14])<<8 | uint64(data[15])
}

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

func FromFormatB(data string) (*GUID, error) {
	if data[0] != '{' || data[len(data)-1] != '}' {
		return nil, fmt.Errorf("GUID Format B should be 32 hexadecimal characters separated in five parts enclosed in braces")
	}
	return FromFormatD(data[1 : len(data)-1])
}

func FromFormatP(data string) (*GUID, error) {
	if data[0] != '(' || data[len(data)-1] != ')' {
		return nil, fmt.Errorf("GUID Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses")
	}
	return FromFormatD(data[1 : len(data)-1])
}

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

// Export functions

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

func (guid *GUID) ToFormatN() string {
	return fmt.Sprintf("%08x%04x%04x%04x%012x", guid.A, guid.B, guid.C, guid.D, guid.E)
}

func (guid *GUID) ToFormatD() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", guid.A, guid.B, guid.C, guid.D, guid.E)
}

func (guid *GUID) ToFormatB() string {
	return fmt.Sprintf("{%08x-%04x-%04x-%04x-%012x}", guid.A, guid.B, guid.C, guid.D, guid.E)
}

func (guid *GUID) ToFormatP() string {
	return fmt.Sprintf("(%08x-%04x-%04x-%04x-%012x)", guid.A, guid.B, guid.C, guid.D, guid.E)
}

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
