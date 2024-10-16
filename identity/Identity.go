package identity

import (
	"fmt"
	"strings"
)

type Identity struct {
	Name string
	SID  SID
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

func (identity *Identity) Parse(RawBytes []byte) {
	identity.RawBytes = RawBytes

	identity.SID.Parse(RawBytes)

	wellKnownSIDs := map[string]string{
		"S-1-0-0":      "Nobody",
		"S-1-1-0":      "World",
		"S-1-2-0":      "Local",
		"S-1-2-1":      "Console Logon",
		"S-1-3-0":      "Creator Owner",
		"S-1-3-1":      "Creator Group",
		"S-1-3-2":      "Creator Owner Server",
		"S-1-3-3":      "Creator Owner Group",
		"S-1-3-4":      "Owner rights",
		"S-1-5-1":      "Dialup DIALUP",
		"S-1-5-2":      "NT AUTHORITY\\NETWORK",
		"S-1-5-3":      "NT AUTHORITY\\BATCH",
		"S-1-5-4":      "NT AUTHORITY\\INTERACTIVE",
		"S-1-5-6":      "SERVICE",
		"S-1-5-7":      "ANONYMOUS LOGON",
		"S-1-5-8":      "PROXY",
		"S-1-5-9":      "ENTERPRISE DOMAIN CONTROLLERS",
		"S-1-5-10":     "SELF",
		"S-1-5-11":     "NT AUTHORITY\\Authenticated Users",
		"S-1-5-12":     "NT AUTHORITY\\RESTRICTED",
		"S-1-5-13":     "TERMINAL SERVER USER",
		"S-1-5-14":     "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
		"S-1-5-15":     "NT AUTHORITY\\This Organization",
		"S-1-5-17":     "NT AUTHORITY\\IUSR",
		"S-1-5-18":     "NT AUTHORITY\\SYSTEM",
		"S-1-5-19":     "NT AUTHORITY\\LOCAL SERVICE",
		"S-1-5-20":     "NT AUTHORITY\\NETWORK SERVICE",
		"S-1-5-32":     "The built-in domain, it contains groups that define roles on a local machine. BUILTIN",
		"S-1-5-32-544": "BUILTIN\\Administrators",
		"S-1-5-32-545": "BUILTIN\\Users",
		"S-1-5-32-546": "BUILTIN\\Guests",
		"S-1-5-32-547": "BUILTIN\\Power Users",
		"S-1-5-32-551": "BUILTIN\\Backup Operators",
		"S-1-5-32-552": "BUILTIN\\Replicator",
		"S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
		"S-1-5-32-555": "BUILTIN\\Remote Desktop Users",
		"S-1-5-32-558": "BUILTIN\\Performance Monitor Users",
		"S-1-5-32-559": "BUILTIN\\Performance Log Users",
		"S-1-5-32-568": "BUILTIN\\IIS_IUSRS",
		"S-1-5-32-569": "BUILTIN\\Cryptographic Operators",
		"S-1-5-32-573": "BUILTIN\\Event Log Readers",
		"S-1-5-32-578": "BUILTIN\\Hyper-V Administrators",
		"S-1-5-32-579": "BUILTIN\\Access Control Assistance Operators",
		"S-1-5-32-581": "BUILTIN\\System Managed Accounts Group",
		"S-1-5-32-583": "BUILTIN\\Device Owners",
		"S-1-5-64-10":  "NTLM Authentication",
		"S-1-5-80":     "All services",
		"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464": "Trusted installer NT SERVICE\\TrustedInstaller",
		"S-1-5-113":  "Local account",
		"S-1-5-114":  "Local account and member of Administrators group German: NT-AUTORITÄT\\Lokales Konto und Mitglied der Gruppse \"Administratoren\"",
		"S-1-15-2-1": "All applications running in an app package context. APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
		"S-1-18-1":   "Authentication authority asserted identity",
	}

	sidString := identity.SID.ToString()
	if name, exists := wellKnownSIDs[sidString]; exists {
		identity.Name = name
	}

	identity.RawBytesSize = identity.SID.RawBytesSize
}

func (identity *Identity) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<Identity>\n", indentPrompt)

	fmt.Printf("%s │ \x1b[93mSID\x1b[0m  : \x1b[96m%s\x1b[0m\n", indentPrompt, identity.SID.ToString())
	//identity.SID.Describe(indent + 1)

	fmt.Printf("%s │ \x1b[93mName\x1b[0m : '\x1b[94m%s\x1b[0m'\n", indentPrompt, identity.Name)

	fmt.Printf("%s └─\n", indentPrompt)
}
