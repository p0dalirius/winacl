package ntsecuritydescriptor

import (
	"fmt"
	"strings"
)

type SystemAccessControlList struct {
	Header SystemAccessControlListHeader
}

func (dacl *SystemAccessControlList) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SystemAccessControlList>\n", indentPrompt)

	dacl.Header.Describe(indent + 1)

	fmt.Printf("%s └─\n", indentPrompt)
}
