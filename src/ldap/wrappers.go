package ldap

import (
	"winacl/logger"
	"winacl/windows"

	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func FindObjectSIDByRID(ldapSession *Session, domain string, RID int) string {
	// The FindObjectSIDByRID function searches for an object SID based on a given RID within a specified domain.
	// It takes an LDAP session, domain name, and RID as input parameters.
	// It first retrieves the domain object using the GetDomain function.
	// Then it constructs a query for the local RID and searches for the object SID.
	// If the domain object is found and the local RID matches the input RID, it returns the object SID.
	// If no matching object is found, it returns an empty string.

	objectSID := ""

	localRIDs := []int{
		windows.RID_LOCAL_ADMINS,
		windows.RID_LOCAL_USERS,
		windows.RID_LOCAL_GUESTS,
		windows.RID_LOCAL_POWER_USERS,
		windows.RID_LOCAL_ACCOUNT_OPS,
		windows.RID_LOCAL_SYSTEM_OPS,
		windows.RID_LOCAL_PRINT_OPS,
		windows.RID_LOCAL_BACKUP_OPS,
		windows.RID_LOCAL_REPLICATOR,
		windows.RID_LOCAL_RAS_SERVERS,
		windows.RID_LOCAL_PREW2KCOMPACCESS,
		windows.RID_LOCAL_REMOTE_DESKTOP_USERS,
		windows.RID_LOCAL_NETWORK_CONFIGURATION_OPS,
		windows.RID_LOCAL_INCOMING_FOREST_TRUST_BUILDERS,
		windows.RID_LOCAL_MONITORING_USERS,
		windows.RID_LOCAL_LOGGING_USERS,
		windows.RID_LOCAL_AUTHORIZATIONACCESS,
		windows.RID_LOCAL_TS_LICENSE_SERVERS,
		windows.RID_LOCAL_DCOM_USERS,
		windows.RID_LOCAL_IUSERS,
		windows.RID_LOCAL_CRYPTO_OPERATORS,
		windows.RID_LOCAL_CACHEABLE_PRINCIPALS_GROUP,
		windows.RID_LOCAL_NON_CACHEABLE_PRINCIPALS_GROUP,
		windows.RID_LOCAL_EVENT_LOG_READERS_GROUP,
		windows.RID_LOCAL_CERTSVC_DCOM_ACCESS_GROUP,
		windows.RID_LOCAL_RDS_REMOTE_ACCESS_SERVERS,
		windows.RID_LOCAL_RDS_ENDPOINT_SERVERS,
		windows.RID_LOCAL_RDS_MANAGEMENT_SERVERS,
		windows.RID_LOCAL_HYPER_V_ADMINS,
		windows.RID_LOCAL_ACCESS_CONTROL_ASSISTANCE_OPS,
		windows.RID_LOCAL_REMOTE_MANAGEMENT_USERS,
		windows.RID_LOCAL_DEFAULT_ACCOUNT,
		windows.RID_LOCAL_STORAGE_REPLICA_ADMINS,
		windows.RID_LOCAL_DEVICE_OWNERS,
	}

	domainObject := GetDomain(ldapSession, domain)
	if domainObject != nil {

		// Create query for local RID
		query := ""
		for _, localRID := range localRIDs {
			if localRID == RID {
				query = fmt.Sprintf("(objectSid=S-1-5-32-%d)", localRID)
				break
			}
		}
		// Create query for other (domain) RID
		if len(query) == 0 {
			query = fmt.Sprintf("(objectSid=%s-%d)", domainObject.SID, RID)
		}

		// Perform LDAP query to find the object
		attributes := []string{"distinguishedName", "objectSid"}
		results := QueryWholeSubtree(ldapSession, "", query, attributes)

		if len(results) > 1 {
			logger.Warn(fmt.Sprintf("Error: More than one result for SID '%s-%d' in the domain '%s'", domainObject.SID, RID, domain))
		} else {
			if len(results) == 1 {
				// One result found
				objectSID = ParseSIDFromBytes(results[0].GetRawAttributeValue("objectSid"))
			}
		}
	}

	return objectSID
}

func IsDomainAtLeast(ldapSession *Session, domain string, functionalityLevel int) bool {
	// IsDomainAtLeast checks if the domain's functionality level is at least the specified level.
	// It takes an LDAP session, domain name, and functionality level as input parameters.
	// It returns true if the domain's functionality level is at least the specified level, false otherwise.

	domainObject := GetDomain(ldapSession, domain)

	if domainObject != nil {
		query := fmt.Sprintf("(distinguishedName=%s)", domainObject.DistinguishedName)
		attributes := []string{"msDS-Behavior-Version"}
		results := QueryBaseObject(ldapSession, domainObject.DistinguishedName, query, attributes)

		if len(results) != 0 {
			domainFunctionalityLevel, err := strconv.Atoi(results[0].GetAttributeValue("msDS-Behavior-Version"))
			if err != nil {
				logger.Warn("Failed to parse msDS-Behavior-Version to int")
				return false
			} else {
				if domainFunctionalityLevel >= functionalityLevel {
					return true
				} else {
					return false
				}
			}
		} else {
			return false
		}
	}

	return false
}

func BaseDNExists(ldapSession *Session, baseDN string) bool {
	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN
		baseDN,
		// Scope
		ldap.ScopeBaseObject,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		1,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=*)",
		// Attributes to retrieve
		[]string{"distinguishedName"},
		// Controls
		nil,
	)

	// Perform LDAP search
	_, err := ldapSession.connection.Search(searchRequest)
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false
	} else {
		return true
	}
}

func GetDomainDNSServers(ldapSession *Session) []string {
	dnsServers := []string{}

	// Check in read only domain controllers
	readOnlyDomainControllersMap := GetAllReadOnlyDomainControllers(ldapSession)
	for distinguishedName := range readOnlyDomainControllersMap {
		for _, hostname := range readOnlyDomainControllersMap[distinguishedName] {
			fmt.Printf("hostname = %s\n", hostname)
			// Try to connect to
			conn, err := net.Dial("tcp", hostname+":53")
			if err == nil {
				// Get remote address which contains the IP of the connected DNS server
				remoteAddr := conn.RemoteAddr().String()
				remoteIP := strings.Split(remoteAddr, ":")[0]

				dnsServers = append(dnsServers, remoteIP)
				defer conn.Close()
			} else {
				fmt.Printf("Error: %s\n", err)
			}
		}
	}

	// Check in domain controllers
	domainControllersMap := GetAllDomainControllers(ldapSession)
	for distinguishedName := range domainControllersMap {
		for _, hostname := range domainControllersMap[distinguishedName] {
			fmt.Printf("hostname = %s\n", hostname)
			// Try to connect to
			conn, err := net.Dial("tcp", hostname+":53")
			if err == nil {
				// Get remote address which contains the IP of the connected DNS server
				remoteAddr := conn.RemoteAddr().String()
				remoteIP := strings.Split(remoteAddr, ":")[0]

				dnsServers = append(dnsServers, remoteIP)
				defer conn.Close()
			} else {
				fmt.Printf("Error: %s\n", err)
			}
		}
	}

	return dnsServers
}

func GetPrincipalDomainController(ldapSession *Session, domainName string) string {
	// Constructing LDAP query to find the principal domain controller (PDC)
	query := fmt.Sprintf("(&(objectClass=computer)(primaryGroupID=%d)(dnsHostName=*%s*))", windows.RID_DOMAIN_GROUP_CONTROLLERS, domainName)
	attributes := []string{"dnsHostName"}

	// Performing LDAP query
	ldapResults := QueryWholeSubtree(ldapSession, "", query, attributes)

	if len(ldapResults) == 0 {
		return ""
	} else {
		// Extracting the DNS hostname of the PDC
		pdcHostname := ldapResults[0].GetAttributeValue("dnsHostName")
		return pdcHostname
	}
}

func GetAllDomains(ldapSession *Session) map[string]*Domain {
	// The GetAllDomains function retrieves all domains from the LDAP server using a specific search filter
	// It returns a map of domain Fully Qualified Domain Names (FQDN) to Domain objects
	// Each Domain object contains the DistinguishedName, FQDN, and SID of the domain

	attributes := []string{"distinguishedName", "objectSid"}
	query := "(objectClass=domain)"

	ldapResults := QueryWholeSubtree(ldapSession, "", query, attributes)

	domainsMap := make(map[string]*Domain)

	if len(ldapResults) != 0 {
		for _, entry := range ldapResults {
			DNSName := GetDomainFromDistinguishedName(entry.GetAttributeValue("distinguishedName"))
			DNSName = strings.ToUpper(DNSName)

			NetBIOSName := strings.ToUpper(entry.GetAttributeValue("dc"))

			domain := &Domain{
				DistinguishedName: entry.GetAttributeValue("distinguishedName"),
				NetBIOSName:       NetBIOSName,
				DNSName:           DNSName,
				SID:               ParseSIDFromBytes(entry.GetRawAttributeValue("objectSid")),
			}

			domainsMap[DNSName] = domain
		}
	}

	return domainsMap
}

func GetAllComputers(ldapSession *Session) map[string][]string {

	attributes := []string{"distinguishedName", "dnsHostname"}

	query := "(&"
	// Searching for computer accounts
	query += "(objectClass=computer)"
	// With a DNS hostname
	query += "(dnsHostname=*)"
	// Closing the AND
	query += ")"

	ldapResults := QueryWholeSubtree(ldapSession, "", query, attributes)

	computersMap := make(map[string][]string)

	if len(ldapResults) != 0 {
		for _, entry := range ldapResults {
			computersMap[entry.GetAttributeValue("distinguishedName")] = entry.GetEqualFoldAttributeValues("dnsHostname")
		}
	}

	return computersMap
}

func GetAllDomainControllers(ldapSession *Session) map[string][]string {

	attributes := []string{"distinguishedName", "dnsHostname"}

	query := "(&"
	// Searching for computer accounts
	query += "(objectClass=computer)"
	//
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", windows.UAF_SERVER_TRUST_ACCOUNT)
	// With a DNS hostname
	query += "(dnsHostname=*)"
	// Closing the AND
	query += ")"

	ldapResults := QueryWholeSubtree(ldapSession, "", query, attributes)

	domainControllersMap := make(map[string][]string)

	if len(ldapResults) != 0 {
		for _, entry := range ldapResults {
			domainControllersMap[entry.GetAttributeValue("distinguishedName")] = entry.GetEqualFoldAttributeValues("dnsHostname")
		}
	}

	return domainControllersMap
}

func GetAllReadOnlyDomainControllers(ldapSession *Session) map[string][]string {

	attributes := []string{"distinguishedName", "dnsHostname"}

	query := "(&"
	// Searching for computer accounts
	query += "(objectClass=computer)"
	//
	query += fmt.Sprintf("(userAccountControl:1.2.840.113556.1.4.803:=%d)", windows.UAF_PARTIAL_SECRETS_ACCOUNT)
	// With a DNS hostname
	query += "(dnsHostname=*)"
	// Closing the AND
	query += ")"

	ldapResults := QueryWholeSubtree(ldapSession, "", query, attributes)
	readOnlyDomainControllersMap := make(map[string][]string)

	if len(ldapResults) != 0 {
		for _, entry := range ldapResults {
			readOnlyDomainControllersMap[entry.GetAttributeValue("distinguishedName")] = entry.GetEqualFoldAttributeValues("dnsHostname")
		}
	}

	return readOnlyDomainControllersMap
}

func GetDomain(ldapSession *Session, domain string) *Domain {
	// Generate documentation for the GetDomain function
	// GetDomain retrieves information about a specific domain from LDAP based on the provided domain name.
	// It performs an LDAP search to fetch the distinguished name, fully qualified domain name (FQDN), and Security Identifier (SID) of the domain.
	// If the domain name contains a period (.), it searches for the FQDN; otherwise, it searches for the NetBIOS name.
	// Parameters:
	// - ldapSession: The LDAP session to use for the search.
	// - domain: The name of the domain to retrieve information for.
	// Returns:
	// - A pointer to the Domain struct containing the retrieved information, or nil if the domain is not found or an error occurs.

	query := "(objectClass=domain)"
	attributes := []string{"distinguishedName", "objectSid", "dc"}
	ldapResults := QueryWholeSubtree(ldapSession, "defaultNamingContext", query, attributes)

	if strings.Contains(domain, ".") {
		// FQDN
		for _, entry := range ldapResults {
			DNSName := GetDomainFromDistinguishedName(entry.GetAttributeValue("distinguishedName"))
			DNSName = strings.ToUpper(DNSName)

			NetBIOSName := strings.ToUpper(entry.GetAttributeValue("dc"))

			if DNSName == strings.ToUpper(domain) {
				return &Domain{
					DistinguishedName: entry.GetAttributeValue("distinguishedName"),
					NetBIOSName:       NetBIOSName,
					DNSName:           DNSName,
					SID:               ParseSIDFromBytes(entry.GetRawAttributeValue("objectSid")),
				}
			}
		}
	} else {
		// Netbios Name
		for _, entry := range ldapResults {
			DNSName := GetDomainFromDistinguishedName(entry.GetAttributeValue("distinguishedName"))
			DNSName = strings.ToUpper(DNSName)

			NetBIOSName := strings.ToUpper(entry.GetAttributeValue("dc"))

			if NetBIOSName == strings.ToUpper(domain) {
				return &Domain{
					DistinguishedName: entry.GetAttributeValue("distinguishedName"),
					NetBIOSName:       NetBIOSName,
					DNSName:           DNSName,
					SID:               ParseSIDFromBytes(entry.GetRawAttributeValue("objectSid")),
				}
			}
		}
	}

	return nil
}

func GetAllNamingContexts(ldapSession *Session) []string {
	// Fetch the RootDSE entry
	rootDSE := GetRootDSE(ldapSession)
	if rootDSE == nil {
		return nil
	}

	// Retrieve the namingContexts attribute
	namingContexts := rootDSE.GetAttributeValues("namingContexts")
	if len(namingContexts) == 0 {
		return nil
	}

	return namingContexts
}
