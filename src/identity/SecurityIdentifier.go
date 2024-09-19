package identity

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Represents a Security Identifier (SID) in various formats and provides methods for manipulation and conversion between them.
//
// Attributes:
// 	revisionLevel (int): The revision level of the SID.
// 	subAuthorityCount (int): The number of sub-authorities in the SID.
// 	identifierAuthority (SID_IDENTIFIER_AUTHORITY): The identifier authority value.
// 	reserved (bytes): Reserved bytes, should always be empty.
// 	subAuthorities (list): A list of sub-authorities.
// 	relativeIdentifier (int): The relative identifier.
//
// Methods:
// 	Parse(RawBytes []byte): Parses the raw bytes to populate the SID fields.
// 	ToString() string: Converts the SID to its string representation.
//  Describe(): prints a detailed description of the SID with the specified indentation level.
//
// See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861

type SID struct {
	RevisionLevel       uint8
	SubAuthorityCount   uint8
	IdentifierAuthority uint64
	SubAuthorities      []uint32
	RelativeIdentifier  uint32
	Reserved            []byte
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (sid *SID) Parse(RawBytes []byte) {
	sid.RawBytesSize = 0

	sid.RevisionLevel = uint8(RawBytes[0])
	sid.RawBytesSize += 1

	sid.SubAuthorityCount = uint8(RawBytes[1])
	sid.RawBytesSize += 1

	sid.IdentifierAuthority = 0
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[2:4])) >> 16
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[4:6])) >> 8
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[6:8]))
	sid.RawBytesSize += 6

	sid.SubAuthorities = make([]uint32, sid.SubAuthorityCount-1)
	for i := 0; i < int(sid.SubAuthorityCount-1); i++ {
		sid.SubAuthorities[i] = binary.LittleEndian.Uint32(RawBytes[sid.RawBytesSize : sid.RawBytesSize+4])
		sid.RawBytesSize += 4
	}

	sid.RelativeIdentifier = binary.LittleEndian.Uint32(RawBytes[sid.RawBytesSize : sid.RawBytesSize+4])
	sid.RawBytesSize += 4

	sid.RawBytes = RawBytes[:sid.RawBytesSize]
}

func (sid *SID) ToString() string {

	sidstring := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.IdentifierAuthority)

	for _, subauthority := range sid.SubAuthorities {
		sidstring += fmt.Sprintf("-%d", subauthority)
	}

	sidstring += fmt.Sprintf("-%d", sid.RelativeIdentifier)

	return sidstring
}

func (sid *SID) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SID '%s'>\n", indentPrompt, sid.ToString())
	fmt.Printf("%s │ \x1b[93mRevisionLevel\x1b[0m        : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.RevisionLevel)
	fmt.Printf("%s │ \x1b[93mIdentifierAuthority\x1b[0m  : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.IdentifierAuthority)

	if sid.SubAuthorityCount != 0 {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (%03d)\x1b[0m :\n", indentPrompt, sid.SubAuthorityCount)
		for index, subauthority := range sid.SubAuthorities {
			fmt.Printf("%s │ \x1b[93mSubAuthority %02d\x1b[0m : 0x%08x\n", strings.Repeat(" │ ", indent+1), index, subauthority)
		}
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	} else {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (0)\x1b[0m   : Empty\n", indentPrompt)
	}

	fmt.Printf("%s │ \x1b[93mRelativeIdentifier\x1b[0m   : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.RelativeIdentifier)
	fmt.Printf("%s └─\n", indentPrompt)
}
