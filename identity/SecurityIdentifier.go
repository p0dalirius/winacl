package identity

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Represents a Security Identifier (SID) in various formats and provides methods for manipulation and conversion between them.
//
// Attributes:
// 	revisionLevel (int): The revision level of the SID.
// 	subAuthorityCount (int): The number of sub-authorities in the SID.
// 	identifierAuthority (SID_IDENTIFIER_AUTHORITY): The identifier authority value.
// 	reserved (bytes): Reserved bytes, should always be empty.
// 	subAuthorities (list): A list of sub-authorities.
// 	relativeIdentifier (int): The relative identifier.
//
// Methods:
// 	Parse(RawBytes []byte): Parses the raw bytes to populate the SID fields.
// 	ToString() string: Converts the SID to its string representation.
//  Describe(): prints a detailed description of the SID with the specified indentation level.
//
// See: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861

type SID struct {
	RevisionLevel       uint8
	SubAuthorityCount   uint8
	IdentifierAuthority uint64
	SubAuthorities      []uint32
	RelativeIdentifier  uint32
	Reserved            []byte
	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

const (
	WELLKNOWNSID_NOBODY                              = "S-1-0-0"
	WELLKNOWNSID_EVERYONE                            = "S-1-1-0"
	WELLKNOWNSID_LOCAL                               = "S-1-2-0"
	WELLKNOWNSID_CONSOLE_LOGON                       = "S-1-2-1"
	WELLKNOWNSID_CREATOR_OWNER                       = "S-1-3-0"
	WELLKNOWNSID_CREATOR_GROUP                       = "S-1-3-1"
	WELLKNOWNSID_CREATOR_OWNER_SERVER                = "S-1-3-2"
	WELLKNOWNSID_CREATOR_GROUP_SERVER                = "S-1-3-3"
	WELLKNOWNSID_NT_AUTHORITY                        = "S-1-5"
	WELLKNOWNSID_DIALUP                              = "S-1-5-1"
	WELLKNOWNSID_NETWORK                             = "S-1-5-2"
	WELLKNOWNSID_BATCH                               = "S-1-5-3"
	WELLKNOWNSID_INTERACTIVE                         = "S-1-5-4"
	WELLKNOWNSID_SERVICE                             = "S-1-5-6"
	WELLKNOWNSID_ANONYMOUS                           = "S-1-5-7"
	WELLKNOWNSID_PROXY                               = "S-1-5-8"
	WELLKNOWNSID_ENTERPRISE_DOMAIN_CONTROLLERS       = "S-1-5-9"
	WELLKNOWNSID_PRINCIPAL_SELF                      = "S-1-5-10"
	WELLKNOWNSID_AUTHENTICATED_USERS                 = "S-1-5-11"
	WELLKNOWNSID_RESTRICTED_CODE                     = "S-1-5-12"
	WELLKNOWNSID_TERMINAL_SERVER_USERS               = "S-1-5-13"
	WELLKNOWNSID_REMOTE_INTERACTIVE_LOGON            = "S-1-5-14"
	WELLKNOWNSID_THIS_ORGANIZATION                   = "S-1-5-15"
	WELLKNOWNSID_IUSR                                = "S-1-5-17"
	WELLKNOWNSID_LOCAL_SYSTEM                        = "S-1-5-18"
	WELLKNOWNSID_LOCAL_SERVICE                       = "S-1-5-19"
	WELLKNOWNSID_NETWORK_SERVICE                     = "S-1-5-20"
	WELLKNOWNSID_ADMINISTRATORS                      = "S-1-5-32-544"
	WELLKNOWNSID_USERS                               = "S-1-5-32-545"
	WELLKNOWNSID_GUESTS                              = "S-1-5-32-546"
	WELLKNOWNSID_POWER_USERS                         = "S-1-5-32-547"
	WELLKNOWNSID_ACCOUNT_OPERATORS                   = "S-1-5-32-548"
	WELLKNOWNSID_SERVER_OPERATORS                    = "S-1-5-32-549"
	WELLKNOWNSID_PRINT_OPERATORS                     = "S-1-5-32-550"
	WELLKNOWNSID_BACKUP_OPERATORS                    = "S-1-5-32-551"
	WELLKNOWNSID_REPLICATORS                         = "S-1-5-32-552"
	WELLKNOWNSID_NTLM_AUTHENTICATION                 = "S-1-5-64-10"
	WELLKNOWNSID_SCHANNEL_AUTHENTICATION             = "S-1-5-64-14"
	WELLKNOWNSID_DIGEST_AUTHENTICATION               = "S-1-5-64-21"
	WELLKNOWNSID_UNTRUSTED_LEVEL                     = "S-1-16-0"
	WELLKNOWNSID_LOW_INTEGRITY_LEVEL                 = "S-1-16-4096"
	WELLKNOWNSID_MEDIUM_INTEGRITY_LEVEL              = "S-1-16-8192"
	WELLKNOWNSID_MEDIUM_PLUS_INTEGRITY_LEVEL         = "S-1-16-8448"
	WELLKNOWNSID_HIGH_INTEGRITY_LEVEL                = "S-1-16-12288"
	WELLKNOWNSID_SYSTEM_INTEGRITY_LEVEL              = "S-1-16-16384"
	WELLKNOWNSID_PROTECTED_PROCESS                   = "S-1-16-20480"
	WELLKNOWNSID_SECURE_PROCESS                      = "S-1-16-28672"
	WELLKNOWNSID_ADMINISTRATOR_ACCOUNT               = "S-1-5-21-0-0-0-500"
	WELLKNOWNSID_GUEST_ACCOUNT                       = "S-1-5-21-0-0-0-501"
	WELLKNOWNSID_KRBTGT_ACCOUNT                      = "S-1-5-21-0-0-0-502"
	WELLKNOWNSID_DOMAIN_ADMINS                       = "S-1-5-21-0-0-0-512"
	WELLKNOWNSID_DOMAIN_USERS                        = "S-1-5-21-0-0-0-513"
	WELLKNOWNSID_DOMAIN_GUESTS                       = "S-1-5-21-0-0-0-514"
	WELLKNOWNSID_DOMAIN_COMPUTERS                    = "S-1-5-21-0-0-0-515"
	WELLKNOWNSID_DOMAIN_CONTROLLERS                  = "S-1-5-21-0-0-0-516"
	WELLKNOWNSID_CERT_PUBLISHERS                     = "S-1-5-21-0-0-0-517"
	WELLKNOWNSID_SCHEMA_ADMINS                       = "S-1-5-21-0-0-0-518"
	WELLKNOWNSID_ENTERPRISE_ADMINS                   = "S-1-5-21-0-0-0-519"
	WELLKNOWNSID_GROUP_POLICY_CREATOR_OWNERS         = "S-1-5-21-0-0-0-520"
	WELLKNOWNSID_READ_ONLY_DOMAIN_CONTROLLERS        = "S-1-5-21-0-0-0-521"
	WELLKNOWNSID_CLONEABLE_DOMAIN_CONTROLLERS        = "S-1-5-21-0-0-0-522"
	WELLKNOWNSID_RAS_SERVERS_GROUP                   = "S-1-5-21-0-0-0-553"
	WELLKNOWNSID_PRE_WINDOWS_2000_COMPATIBLE_ACCESS  = "S-1-5-32-554"
	WELLKNOWNSID_REMOTE_DESKTOP_USERS                = "S-1-5-32-555"
	WELLKNOWNSID_NETWORK_CONFIGURATION_OPERATORS     = "S-1-5-32-556"
	WELLKNOWNSID_INCOMING_FOREST_TRUST_BUILDERS      = "S-1-5-32-557"
	WELLKNOWNSID_PERFORMANCE_MONITOR_USERS           = "S-1-5-32-558"
	WELLKNOWNSID_PERFORMANCE_LOG_USERS               = "S-1-5-32-559"
	WELLKNOWNSID_WINDOWS_AUTHORIZATION_ACCESS_GROUP  = "S-1-5-32-560"
	WELLKNOWNSID_TERMINAL_SERVER_LICENSE_SERVERS     = "S-1-5-32-561"
	WELLKNOWNSID_DISTRIBUTED_COM_USERS               = "S-1-5-32-562"
	WELLKNOWNSID_CRYPTOGRAPHIC_OPERATORS             = "S-1-5-32-569"
	WELLKNOWNSID_EVENT_LOG_READERS                   = "S-1-5-32-573"
	WELLKNOWNSID_CERTIFICATE_SERVICE_DCOM_ACCESS     = "S-1-5-32-574"
	WELLKNOWNSID_RDS_REMOTE_ACCESS_SERVERS           = "S-1-5-32-575"
	WELLKNOWNSID_RDS_ENDPOINT_SERVERS                = "S-1-5-32-576"
	WELLKNOWNSID_RDS_MANAGEMENT_SERVERS              = "S-1-5-32-577"
	WELLKNOWNSID_HYPER_V_ADMINISTRATORS              = "S-1-5-32-578"
	WELLKNOWNSID_ACCESS_CONTROL_ASSISTANCE_OPERATORS = "S-1-5-32-579"
	WELLKNOWNSID_REMOTE_MANAGEMENT_USERS             = "S-1-5-32-580"
)

// WellKnownSIDs maps some well-known SIDs to their names.
var WellKnownSIDs = map[string]string{
	// Operating system-defined SIDs
	"S-1-0-0":  "Nobody",
	"S-1-1-0":  "Everyone",
	"S-1-2-0":  "Local",
	"S-1-2-1":  "Console Logon",
	"S-1-3-0":  "Creator Owner",
	"S-1-3-1":  "Creator Group",
	"S-1-3-2":  "Creator Owner Server",
	"S-1-3-3":  "Creator Group Server",
	"S-1-5":    "NT Authority",
	"S-1-5-1":  "Dialup",
	"S-1-5-2":  "Network",
	"S-1-5-3":  "Batch",
	"S-1-5-4":  "Interactive",
	"S-1-5-6":  "Service",
	"S-1-5-7":  "Anonymous",
	"S-1-5-8":  "Proxy",
	"S-1-5-9":  "Enterprise Domain Controllers",
	"S-1-5-10": "Principal Self",
	"S-1-5-11": "Authenticated Users",
	"S-1-5-12": "Restricted Code",
	"S-1-5-13": "Terminal Server Users",
	"S-1-5-14": "Remote Interactive Logon",
	"S-1-5-15": "This Organization",
	"S-1-5-17": "IUSR",
	"S-1-5-18": "Local System",
	"S-1-5-19": "Local Service",
	"S-1-5-20": "Network Service",

	// Built-in system groups
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-548": "Account Operators",
	"S-1-5-32-549": "Server Operators",
	"S-1-5-32-550": "Print Operators",
	"S-1-5-32-551": "Backup Operators",
	"S-1-5-32-552": "Replicators",

	// Logon types
	"S-1-5-64-10": "NTLM Authentication",
	"S-1-5-64-14": "SChannel Authentication",
	"S-1-5-64-21": "Digest Authentication",

	// Mandatory integrity levels
	"S-1-16-0":     "Untrusted Level",
	"S-1-16-4096":  "Low Integrity Level",
	"S-1-16-8192":  "Medium Integrity Level",
	"S-1-16-8448":  "Medium Plus Integrity Level",
	"S-1-16-12288": "High Integrity Level",
	"S-1-16-16384": "System Integrity Level",
	"S-1-16-20480": "Protected Process",
	"S-1-16-28672": "Secure Process",

	// Special identity groups
	"S-1-5-21-0-0-0-500": "Administrator Account",
	"S-1-5-21-0-0-0-501": "Guest Account",
	"S-1-5-21-0-0-0-502": "KRBTGT Account",
	"S-1-5-21-0-0-0-512": "Domain Admins",
	"S-1-5-21-0-0-0-513": "Domain Users",
	"S-1-5-21-0-0-0-514": "Domain Guests",
	"S-1-5-21-0-0-0-515": "Domain Computers",
	"S-1-5-21-0-0-0-516": "Domain Controllers",
	"S-1-5-21-0-0-0-517": "Cert Publishers",
	"S-1-5-21-0-0-0-518": "Schema Admins",
	"S-1-5-21-0-0-0-519": "Enterprise Admins",
	"S-1-5-21-0-0-0-520": "Group Policy Creator Owners",
	"S-1-5-21-0-0-0-521": "Read-Only Domain Controllers",
	"S-1-5-21-0-0-0-522": "Cloneable Domain Controllers",
	"S-1-5-21-0-0-0-553": "RAS Servers Group",

	// Others
	"S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
	"S-1-5-32-555": "Remote Desktop Users",
	"S-1-5-32-556": "Network Configuration Operators",
	"S-1-5-32-557": "Incoming Forest Trust Builders",
	"S-1-5-32-558": "Performance Monitor Users",
	"S-1-5-32-559": "Performance Log Users",
	"S-1-5-32-560": "Windows Authorization Access Group",
	"S-1-5-32-561": "Terminal Server License Servers",
	"S-1-5-32-562": "Distributed COM Users",
	"S-1-5-32-569": "Cryptographic Operators",
	"S-1-5-32-573": "Event Log Readers",
	"S-1-5-32-574": "Certificate Service DCOM Access",
	"S-1-5-32-575": "RDS Remote Access Servers",
	"S-1-5-32-576": "RDS Endpoint Servers",
	"S-1-5-32-577": "RDS Management Servers",
	"S-1-5-32-578": "Hyper-V Administrators",
	"S-1-5-32-579": "Access Control Assistance Operators",
	"S-1-5-32-580": "Remote Management Users",
}

// IsWellKnownSID checks if the SID is a well-known SID.
func (sid *SID) IsWellKnownSID() bool {
	// Check if the SID is in the map of well-known SIDs
	_, found := WellKnownSIDs[sid.ToString()]
	return found
}

// LookupName returns the name of the well-known SID if it is well-known, otherwise it returns an empty string.
func (sid *SID) LookupName() string {
	// Check if it's a well-known SID and return its name
	if name, found := WellKnownSIDs[sid.ToString()]; found {
		return name
	}
	// If it's not a well-known SID, return an empty string
	return ""
}

func (sid *SID) Parse(RawBytes []byte) {
	sid.RawBytesSize = 0

	sid.RevisionLevel = uint8(RawBytes[0])
	sid.RawBytesSize += 1

	sid.SubAuthorityCount = uint8(RawBytes[1])
	sid.RawBytesSize += 1

	sid.IdentifierAuthority = 0
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[2:4])) >> 16
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[4:6])) >> 8
	sid.IdentifierAuthority += uint64(binary.BigEndian.Uint16(RawBytes[6:8]))
	sid.RawBytesSize += 6

	sid.SubAuthorities = make([]uint32, sid.SubAuthorityCount-1)
	for i := 0; i < int(sid.SubAuthorityCount-1); i++ {
		sid.SubAuthorities[i] = binary.LittleEndian.Uint32(RawBytes[sid.RawBytesSize : sid.RawBytesSize+4])
		sid.RawBytesSize += 4
	}

	sid.RelativeIdentifier = binary.LittleEndian.Uint32(RawBytes[sid.RawBytesSize : sid.RawBytesSize+4])
	sid.RawBytesSize += 4

	sid.RawBytes = RawBytes[:sid.RawBytesSize]
}

func (sid *SID) ToString() string {

	sidstring := fmt.Sprintf("S-%d-%d", sid.RevisionLevel, sid.IdentifierAuthority)

	for _, subauthority := range sid.SubAuthorities {
		sidstring += fmt.Sprintf("-%d", subauthority)
	}

	sidstring += fmt.Sprintf("-%d", sid.RelativeIdentifier)

	return sidstring
}

func (sid *SID) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)

	fmt.Printf("%s<SID '%s'>\n", indentPrompt, sid.ToString())
	fmt.Printf("%s │ \x1b[93mRevisionLevel\x1b[0m        : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.RevisionLevel)
	fmt.Printf("%s │ \x1b[93mIdentifierAuthority\x1b[0m  : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.IdentifierAuthority)

	if sid.SubAuthorityCount != 0 {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (%03d)\x1b[0m :\n", indentPrompt, sid.SubAuthorityCount)
		for index, subauthority := range sid.SubAuthorities {
			fmt.Printf("%s │ \x1b[93mSubAuthority %02d\x1b[0m : 0x%08x\n", strings.Repeat(" │ ", indent+1), index, subauthority)
		}
		fmt.Printf("%s └─\n", strings.Repeat(" │ ", indent+1))
	} else {
		fmt.Printf("%s │ \x1b[93mSubAuthorities (0)\x1b[0m   : Empty\n", indentPrompt)
	}

	fmt.Printf("%s │ \x1b[93mRelativeIdentifier\x1b[0m   : \x1b[96m0x%02x\x1b[0m\n", indentPrompt, sid.RelativeIdentifier)
	fmt.Printf("%s └─\n", indentPrompt)
}
