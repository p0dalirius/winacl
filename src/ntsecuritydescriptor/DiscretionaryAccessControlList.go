package ntsecuritydescriptor

import (
	"fmt"
	"strings"
)

type DiscretionaryAccessControlList struct {
	Header DiscretionaryAccessControlListHeader
}

func (dacl *DiscretionaryAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<DiscretionaryAccessControlList>\n", indentPrompt)

	dacl.Header.Describe(indent + 1)

	fmt.Printf("%s └─\n", indentPrompt)
}
