package securitydescriptor

import (
	"fmt"
	"strings"

	"github.com/p0dalirius/winacl/acl"
	"github.com/p0dalirius/winacl/guid"
	"github.com/p0dalirius/winacl/identity"
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
	}

	// Parse Group if present
	if ntsd.Header.OffsetGroup != 0 {
		ntsd.Group.Parse(RawBytes[ntsd.Header.OffsetGroup:])
		ntsd.RawBytesSize += ntsd.Group.SID.RawBytesSize
	}

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

// Methods

func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAnyExtendedRights(extendedRights []string) map[*identity.SID][]string {
	identitiesMap := make(map[*identity.SID][]string)

	if len(extendedRights) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		matchingRights := make([]string, 0)
		for _, extendedRightGUID := range extendedRights {
			if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
				if extendedRightName, exists := guid.GUIDToExtendedRight[extendedRightGUID]; exists {
					matchingRights = append(matchingRights, extendedRightName)
				} else {
					matchingRights = append(matchingRights, extendedRightGUID)
				}
			}
		}
		if len(matchingRights) != 0 {
			identitiesMap[&ace.SID.SID] = matchingRights
		}
	}

	return identitiesMap
}

func (ntsd *NtSecurityDescriptor) FindIdentitiesWithAllExtendedRights(extendedRights []string) map[*identity.SID][]string {
	identitiesMap := make(map[*identity.SID][]string)

	if len(extendedRights) == 0 {
		return identitiesMap
	}

	for _, ace := range ntsd.DACL.Entries {
		allRightsMatched := true
		// fmt.Printf("ACE ID %d\n", ace.Index)
		for _, extendedRightGUID := range extendedRights {
			if strings.EqualFold(ace.AccessControlObjectType.ObjectType.GUID.ToFormatD(), extendedRightGUID) {
				// Right is present
				allRightsMatched = allRightsMatched && true
			} else {
				// Right is not present, skipping this identity
				allRightsMatched = allRightsMatched && false
				// fmt.Printf("break\n")
				break
			}
		}
		if allRightsMatched {
			identitiesMap[&ace.SID.SID] = extendedRights
		}
	}

	return identitiesMap
}
