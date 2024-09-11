package ntsecuritydescriptor

import (
	"fmt"
	"strings"
)

type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader

	Owner string
	Group string

	DACL DiscretionaryAccessControlList
	SACL SystemAccessControlList

	RawBytes []byte
}

func (ntsd *NtSecurityDescriptor) Parse() error {

	// Parse the header
	ntsd.Header.Parse(ntsd.RawBytes)

	// Parse DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		daclBytes := ntsd.RawBytes[ntsd.Header.OffsetDacl:]
		err := ntsd.DACL.Header.Parse(daclBytes)
		if err != nil {
			return fmt.Errorf("failed to parse DACL: %v", err)
		}
	}

	// Parse SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		saclBytes := ntsd.RawBytes[ntsd.Header.OffsetSacl:]
		err := ntsd.SACL.Header.Parse(saclBytes)
		if err != nil {
			return fmt.Errorf("failed to parse SACL: %v", err)
		}
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
