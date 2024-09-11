package securitydescriptor

import (
	"fmt"
	"strings"
	"winacl/acl"
)

type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader

	Owner string
	Group string

	DACL acl.DiscretionaryAccessControlList
	SACL acl.SystemAccessControlList

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (ntsd *NtSecurityDescriptor) Parse(RawBytes []byte) error {
	ntsd.RawBytes = RawBytes
	ntsd.RawBytesSize = 0

	// Parse the header
	ntsd.Header.Parse(ntsd.RawBytes)
	ntsd.RawBytesSize += ntsd.Header.RawBytesSize

	// Parse DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		daclBytes := ntsd.RawBytes[ntsd.Header.OffsetDacl:]
		ntsd.DACL.Parse(daclBytes)
		ntsd.RawBytesSize += ntsd.DACL.RawBytesSize
	}

	// Parse SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		saclBytes := ntsd.RawBytes[ntsd.Header.OffsetSacl:]
		ntsd.SACL.Parse(saclBytes)
		ntsd.RawBytesSize += ntsd.SACL.RawBytesSize
	}

	return nil
}

func (ntsd *NtSecurityDescriptor) Describe(indent int) {
	fmt.Println("<NTSecurityDescriptor>")

	ntsd.Header.Describe(indent + 1)

	// Print DACL
	if ntsd.Header.OffsetDacl != 0 {
		ntsd.DACL.Describe(indent + 1)
	} else {
		fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	// Print SACL
	if ntsd.Header.OffsetSacl != 0 {
		ntsd.SACL.Describe(indent + 1)
	} else {
		fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	fmt.Println(" └─")
}
