package ace

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"

	"github.com/p0dalirius/winacl/rights"
)

type AccessControlMask struct {
	RawValue uint32
	Values   []uint32
	Flags    []string
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (acm *AccessControlMask) Parse(RawBytes []byte) {
	acm.RawBytes = RawBytes
	acm.RawBytesSize = 4
	acm.RawValue = binary.LittleEndian.Uint32(RawBytes[:acm.RawBytesSize])

	// Sort right names to avoid random placement of flags
	listOfRightNames := []string{}
	for _, RightName := range rights.RightValueToRightName {
		listOfRightNames = append(listOfRightNames, RightName)
	}
	sort.Strings(listOfRightNames)

	// Parse flags
	acm.Flags = make([]string, 0)
	acm.Values = make([]uint32, 0)
	for _, RightName := range listOfRightNames {
		RightValue := rights.RightNameToRightValue[RightName]
		if (acm.RawValue & RightValue) == RightValue {
			acm.Flags = append(acm.Flags, RightName)
			acm.Values = append(acm.Values, RightValue)
		}
	}
}

func (acm *AccessControlMask) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlMask>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mMask\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, acm.RawValue, strings.Join(acm.Flags, "|"))

	fmt.Printf("%s └─\n", indentPrompt)
}
