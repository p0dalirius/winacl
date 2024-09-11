package acl

const (
	ACL_REVISION    = 0x02
	ACL_REVISION_DS = 0x04
)

type AccessControlListRevision struct {
	Name  string
	Value uint8
}

func (aclrev *AccessControlListRevision) Parse(flagValue uint8) {
	aclrev.Value = flagValue

	if flagValue == ACL_REVISION_DS {
		aclrev.Name = "ACL_REVISION_DS"
	} else if flagValue == ACL_REVISION {
		aclrev.Name = "ACL_REVISION"
	} else {
		aclrev.Name = "?"
	}
}
