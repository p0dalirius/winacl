package ace

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	RIGHT_DS_CREATE_CHILD            = uint32(0x00000001)
	RIGHT_DS_DELETE_CHILD            = uint32(0x00000002)
	RIGHT_DS_LIST_CONTENTS           = uint32(0x00000004)
	RIGHT_DS_WRITE_PROPERTY_EXTENDED = uint32(0x00000008)
	RIGHT_DS_READ_PROPERTY           = uint32(0x00000010)
	RIGHT_DS_WRITE_PROPERTY          = uint32(0x00000020)
	RIGHT_DS_DELETE_TREE             = uint32(0x00000040)
	RIGHT_DS_LIST_OBJECT             = uint32(0x00000080)
	RIGHT_DS_CONTROL_ACCESS          = uint32(0x00000100)
	RIGHT_DELETE                     = uint32(0x00010000)
	RIGHT_READ_CONTROL               = uint32(0x00020000)
	RIGHT_WRITE_DAC                  = uint32(0x00040000)
	RIGHT_WRITE_OWNER                = uint32(0x00080000)
	// Generic rights
	RIGHT_GENERIC_ALL     = uint32(0x10000000)
	RIGHT_GENERIC_EXECUTE = uint32(0x20000000)
	RIGHT_GENERIC_WRITE   = uint32(0x40000000)
	RIGHT_GENERIC_READ    = uint32(0x80000000)
)

var AccessControlMaskRightNameToRightValue = map[string]uint32{
	"DS_CREATE_CHILD":            RIGHT_DS_CREATE_CHILD,
	"DS_DELETE_CHILD":            RIGHT_DS_DELETE_CHILD,
	"DS_LIST_CONTENTS":           RIGHT_DS_LIST_CONTENTS,
	"DS_WRITE_PROPERTY_EXTENDED": RIGHT_DS_WRITE_PROPERTY_EXTENDED,
	"DS_READ_PROPERTY":           RIGHT_DS_READ_PROPERTY,
	"DS_WRITE_PROPERTY":          RIGHT_DS_WRITE_PROPERTY,
	"DS_DELETE_TREE":             RIGHT_DS_DELETE_TREE,
	"DS_LIST_OBJECT":             RIGHT_DS_LIST_OBJECT,
	"DS_CONTROL_ACCESS":          RIGHT_DS_CONTROL_ACCESS,
	"DELETE":                     RIGHT_DELETE,
	"READ_CONTROL":               RIGHT_READ_CONTROL,
	"WRITE_DAC":                  RIGHT_WRITE_DAC,
	"WRITE_OWNER":                RIGHT_WRITE_OWNER,
	"GENERIC_ALL":                RIGHT_GENERIC_ALL,
	"GENERIC_EXECUTE":            RIGHT_GENERIC_EXECUTE,
	"GENERIC_WRITE":              RIGHT_GENERIC_WRITE,
	"GENERIC_READ":               RIGHT_GENERIC_READ,
}

var AccessControlMaskRightValueToRightName = map[uint32]string{
	RIGHT_DS_CREATE_CHILD:            "DS_CREATE_CHILD",
	RIGHT_DS_DELETE_CHILD:            "DS_DELETE_CHILD",
	RIGHT_DS_LIST_CONTENTS:           "DS_LIST_CONTENTS",
	RIGHT_DS_WRITE_PROPERTY_EXTENDED: "DS_WRITE_PROPERTY_EXTENDED",
	RIGHT_DS_READ_PROPERTY:           "DS_READ_PROPERTY",
	RIGHT_DS_WRITE_PROPERTY:          "DS_WRITE_PROPERTY",
	RIGHT_DS_DELETE_TREE:             "DS_DELETE_TREE",
	RIGHT_DS_LIST_OBJECT:             "DS_LIST_OBJECT",
	RIGHT_DS_CONTROL_ACCESS:          "DS_CONTROL_ACCESS",
	RIGHT_DELETE:                     "DELETE",
	RIGHT_READ_CONTROL:               "READ_CONTROL",
	RIGHT_WRITE_DAC:                  "WRITE_DAC",
	RIGHT_WRITE_OWNER:                "WRITE_OWNER",
	RIGHT_GENERIC_ALL:                "GENERIC_ALL",
	RIGHT_GENERIC_EXECUTE:            "GENERIC_EXECUTE",
	RIGHT_GENERIC_WRITE:              "GENERIC_WRITE",
	RIGHT_GENERIC_READ:               "GENERIC_READ",
}

type AccessControlMask struct {
	Value uint32
	Flags []string
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (acm *AccessControlMask) Parse(RawBytes []byte) {
	acm.RawBytes = RawBytes
	acm.RawBytesSize = 4
	acm.Value = binary.LittleEndian.Uint32(RawBytes[:acm.RawBytesSize])

	if (acm.Value & RIGHT_DS_CREATE_CHILD) == RIGHT_DS_CREATE_CHILD {
		acm.Flags = append(acm.Flags, "DS_CREATE_CHILD")
	}
	if (acm.Value & RIGHT_DS_DELETE_CHILD) == RIGHT_DS_DELETE_CHILD {
		acm.Flags = append(acm.Flags, "DS_DELETE_CHILD")
	}
	if (acm.Value & RIGHT_DS_LIST_CONTENTS) == RIGHT_DS_LIST_CONTENTS {
		acm.Flags = append(acm.Flags, "DS_LIST_CONTENTS")
	}
	if (acm.Value & RIGHT_DS_WRITE_PROPERTY_EXTENDED) == RIGHT_DS_WRITE_PROPERTY_EXTENDED {
		acm.Flags = append(acm.Flags, "DS_WRITE_PROPERTY_EXTENDED")
	}
	if (acm.Value & RIGHT_DS_READ_PROPERTY) == RIGHT_DS_READ_PROPERTY {
		acm.Flags = append(acm.Flags, "DS_READ_PROPERTY")
	}
	if (acm.Value & RIGHT_DS_WRITE_PROPERTY) == RIGHT_DS_WRITE_PROPERTY {
		acm.Flags = append(acm.Flags, "DS_WRITE_PROPERTY")
	}
	if (acm.Value & RIGHT_DS_DELETE_TREE) == RIGHT_DS_DELETE_TREE {
		acm.Flags = append(acm.Flags, "DS_DELETE_TREE")
	}
	if (acm.Value & RIGHT_DS_LIST_OBJECT) == RIGHT_DS_LIST_OBJECT {
		acm.Flags = append(acm.Flags, "DS_LIST_OBJECT")
	}
	if (acm.Value & RIGHT_DS_CONTROL_ACCESS) == RIGHT_DS_CONTROL_ACCESS {
		acm.Flags = append(acm.Flags, "DS_CONTROL_ACCESS")
	}
	if (acm.Value & RIGHT_DELETE) == RIGHT_DELETE {
		acm.Flags = append(acm.Flags, "DELETE")
	}
	if (acm.Value & RIGHT_READ_CONTROL) == RIGHT_READ_CONTROL {
		acm.Flags = append(acm.Flags, "READ_CONTROL")
	}
	if (acm.Value & RIGHT_WRITE_DAC) == RIGHT_WRITE_DAC {
		acm.Flags = append(acm.Flags, "WRITE_DAC")
	}
	if (acm.Value & RIGHT_WRITE_OWNER) == RIGHT_WRITE_OWNER {
		acm.Flags = append(acm.Flags, "WRITE_OWNER")
	}
	if (acm.Value & RIGHT_GENERIC_ALL) == RIGHT_GENERIC_ALL {
		acm.Flags = append(acm.Flags, "GENERIC_ALL")
	}
	if (acm.Value & RIGHT_GENERIC_EXECUTE) == RIGHT_GENERIC_EXECUTE {
		acm.Flags = append(acm.Flags, "GENERIC_EXECUTE")
	}
	if (acm.Value & RIGHT_GENERIC_WRITE) == RIGHT_GENERIC_WRITE {
		acm.Flags = append(acm.Flags, "GENERIC_WRITE")
	}
	if (acm.Value & RIGHT_GENERIC_READ) == RIGHT_GENERIC_READ {
		acm.Flags = append(acm.Flags, "GENERIC_READ")
	}

}

func (acm *AccessControlMask) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<AccessControlMask>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mMask\x1b[0m : \x1b[96m0x%08x\x1b[0m (\x1b[94m%s\x1b[0m)\n", indentPrompt, acm.Value, strings.Join(acm.Flags, "|"))

	fmt.Printf("%s └─\n", indentPrompt)
}
