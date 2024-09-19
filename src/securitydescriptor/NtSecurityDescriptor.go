package securitydescriptor

import (
	"fmt"
	"strings"
	"winacl/acl"
	"winacl/identity"
)

type NtSecurityDescriptor struct {
	Header NtSecurityDescriptorHeader

	Owner identity.Identity
	Group identity.Identity

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

	// Parse Owner if present
	if ntsd.Header.OffsetOwner != 0 {
		ntsd.Owner.Parse(RawBytes[ntsd.Header.OffsetOwner:])
		ntsd.RawBytesSize += ntsd.Owner.SID.RawBytesSize
		ntsd.Owner.Describe(0)
	}

	// Parse Group if present
	if ntsd.Header.OffsetGroup != 0 {
		ntsd.Group.Parse(RawBytes[ntsd.Header.OffsetGroup:])
		ntsd.RawBytesSize += ntsd.Group.SID.RawBytesSize
		ntsd.Group.Describe(0)
	}

	// Parse DACL if present
	if ntsd.Header.OffsetDacl != 0 {
		daclBytes := ntsd.RawBytes[ntsd.Header.OffsetDacl:]
		ntsd.DACL.Parse(daclBytes)
		ntsd.RawBytesSize += ntsd.DACL.RawBytesSize
		ntsd.DACL.Describe(0)
	}

	// Parse SACL if present
	if ntsd.Header.OffsetSacl != 0 {
		saclBytes := ntsd.RawBytes[ntsd.Header.OffsetSacl:]
		ntsd.SACL.Parse(saclBytes)
		ntsd.RawBytesSize += ntsd.SACL.RawBytesSize
		ntsd.SACL.Describe(0)
	}

	return nil
}

func (ntsd *NtSecurityDescriptor) Describe(indent int) {
	fmt.Println("<NTSecurityDescriptor>")

	ntsd.Header.Describe(indent + 1)

	if ntsd.Header.OffsetOwner != 0 {
		fmt.Printf("%s<Owner>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Owner.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetGroup != 0 {
		fmt.Printf("%s<Group>\n", strings.Repeat(" │ ", indent+1))
		ntsd.Group.Describe(indent + 2)
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	}

	if ntsd.Header.OffsetSacl > ntsd.Header.OffsetDacl {
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
	} else {
		// Print SACL
		if ntsd.Header.OffsetSacl != 0 {
			ntsd.SACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<SystemAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}

		// Print DACL
		if ntsd.Header.OffsetDacl != 0 {
			ntsd.DACL.Describe(indent + 1)
		} else {
			fmt.Printf("%s<DiscretionaryAccessControlList is \x1b[91mnot present\x1b[0m>\n", strings.Repeat(" │ ", indent+1))
			fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
		}
	}

	fmt.Println(" └─")
}
