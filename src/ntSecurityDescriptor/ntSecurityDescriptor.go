package ntsecuritydescriptor

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type NtSecurityDescriptor struct {
	Owner string
	Group string

	Header []byte
	DACL   []byte
	SACL   []byte

	RawBytes []byte
}

func (sd *NtSecurityDescriptor) Parse() error {
	// Parse the header
	headerSize := binary.LittleEndian.Uint16(sd.RawBytes[0:2])
	sd.Header = sd.RawBytes[2 : 2+headerSize]

	// Parse the DACL
	daclSize := binary.LittleEndian.Uint16(sd.RawBytes[2+headerSize : 2+headerSize+2])
	sd.DACL = sd.RawBytes[2+headerSize+2 : 2+headerSize+2+daclSize]

	// Parse the SACL
	saclSize := binary.LittleEndian.Uint16(sd.RawBytes[2+headerSize+2+daclSize : 2+headerSize+2+daclSize+2])
	sd.SACL = sd.RawBytes[2+headerSize+2+daclSize+2 : 2+headerSize+2+daclSize+2+saclSize]

	// Parse the Owner
	ownerSize := binary.LittleEndian.Uint16(sd.RawBytes[2+headerSize+2+daclSize+2+saclSize : 2+headerSize+2+daclSize+2+saclSize+2])
	sd.Owner = string(sd.RawBytes[2+headerSize+2+daclSize+2+saclSize+2 : 2+headerSize+2+daclSize+2+saclSize+2+ownerSize])

	// Parse the Group
	groupSize := binary.LittleEndian.Uint16(sd.RawBytes[2+headerSize+2+daclSize+2+saclSize+2+ownerSize : 2+headerSize+2+daclSize+2+saclSize+2+ownerSize+2])
	sd.Group = string(sd.RawBytes[2+headerSize+2+daclSize+2+saclSize+2+ownerSize+2 : 2+headerSize+2+daclSize+2+saclSize+2+ownerSize+2+groupSize])

	return nil
}

func (ntsd *NtSecurityDescriptor) Describe(indent int) {
	fmt.Println("<NTSecurityDescriptor>")

	// Print DACL
	if ntsd.DACL != nil {
		ntsd.DACL.Describe(ntsd.Header.OffsetDacl, indent+1)
	} else {
		fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}
	// Print SACL
	if ntsd.SACL != nil {
		ntsd.SACL.Describe(ntsd.Header.OffsetSacl, indent+1)
	} else {
		fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	fmt.Println(" └─")
}
