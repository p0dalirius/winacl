package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"
	"winacl/logger"

	"github.com/go-ldap/ldap/v3"
)

type Entry ldap.Entry

type Session struct {
	// Network
	host       string
	port       int
	connection *ldap.Conn
	// Credentials
	domain   string
	username string
	password string
	// Config
	debug    bool
	useldaps bool
}

type Domain struct {
	NetBIOSName       string `json:"netbiosName"`
	DNSName           string `json:"dnsName"`
	DistinguishedName string `json:"distinguishedName"`
	SID               string `json:"sid"`
}

func (s *Session) InitSession(host string, port int, useldaps bool, domain string, username string, password string, debug bool) {
	// Network
	s.host = host
	s.port = port
	// Credentials
	s.domain = domain
	s.username = username
	s.password = password
	// Config
	s.useldaps = useldaps
	s.debug = debug
}

func (s *Session) Connect() bool {
	// Check if TCP port is valid
	if s.port < 1 || s.port > 65535 {
		logger.Warn("Invalid port number. Port must be in the range 1-65535.")
		return false
	}

	// Set up LDAP connection
	var ldapConnection *ldap.Conn
	var err error

	// Check if LDAPS is available
	if s.useldaps {
		// LDAPS connection
		ldapConnection, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", s.host, s.port), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			logger.Warn(fmt.Sprintf("Error connecting to LDAPS server: %s", err))
			return false
		}
		//
	} else {
		// Regular LDAP connection
		ldapConnection, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", s.host, s.port))
		if err != nil {
			logger.Warn(fmt.Sprintf("Error connecting to LDAP server: %s", err))
			return false
		}
	}

	// Bind with credentials if provided
	if len(s.password) > 0 {
		// Binding with credentials
		if s.debug {
			logger.Debug("Performing authenticated NTLM bind ...")
		}
		err = ldapConnection.NTLMBind(s.domain, s.username, s.password)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error binding: %s", err))
			return false
		}

	} else {
		// Unauthenticated Bind
		bindDN := ""
		if s.username != "" {
			bindDN = fmt.Sprintf("%s@%s", s.username, s.domain)
			if s.debug {
				logger.Debug(fmt.Sprintf("Using bindDN: '%s'", bindDN))
			}
		}

		if s.debug {
			logger.Debug("Performing unauthenticated bind ...")
		}
		err = ldapConnection.UnauthenticatedBind(bindDN)
		if err != nil {
			logger.Warn(fmt.Sprintf("Error binding: %s", err))
		}
	}

	s.connection = ldapConnection
	return true
}

func (s *Session) ReConnect() bool {
	s.connection.Close()
	return s.Connect()
}

func GetRootDSE(ldapSession *Session) *ldap.Entry {
	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN blank
		"",
		// Scope Base
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
		[]string{"*"},
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.connection.Search(searchRequest)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error searching LDAP: %s", err))
		return nil
	}

	return searchResult.Entries[0]
}

func RawQuery(ldapSession *Session, baseDN string, query string, attributes []string, scope int) []*ldap.Entry {
	debug := false

	// Parsing parameters
	if len(baseDN) == 0 {
		baseDN = "defaultNamingContext"
	}
	if strings.ToLower(baseDN) == "defaultnamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using defaultNamingContext %s ...\n", rootDSE.GetAttributeValue("defaultNamingContext")))
		}
		baseDN = rootDSE.GetAttributeValue("defaultNamingContext")
	} else if strings.ToLower(baseDN) == "configurationnamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using configurationNamingContext %s ...\n", rootDSE.GetAttributeValue("configurationNamingContext")))
		}
		baseDN = rootDSE.GetAttributeValue("configurationNamingContext")
	} else if strings.ToLower(baseDN) == "schemanamingcontext" {
		rootDSE := GetRootDSE(ldapSession)
		if debug {
			logger.Debug(fmt.Sprintf("Using schemaNamingContext CN=Schema,%s ...\n", rootDSE.GetAttributeValue("configurationNamingContext")))
		}
		baseDN = fmt.Sprintf("CN=Schema,%s", rootDSE.GetAttributeValue("configurationNamingContext"))

	}

	if (scope != ldap.ScopeBaseObject) && (scope != ldap.ScopeSingleLevel) && (scope != ldap.ScopeWholeSubtree) {
		scope = ldap.ScopeWholeSubtree
	}

	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN
		baseDN,
		// Scope
		scope,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		0,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		query,
		// Attributes to retrieve
		attributes,
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.connection.SearchWithPaging(searchRequest, 1000)
	if err != nil {
		logger.Warn(fmt.Sprintf("Error searching LDAP: %s", err))
		return nil
	}

	return searchResult.Entries
}

func QueryBaseObject(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeBaseObject)
	return entries
}

func QuerySingleLevel(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeSingleLevel)
	return entries
}

func QueryWholeSubtree(ldapSession *Session, baseDN string, query string, attributes []string) []*ldap.Entry {
	entries := RawQuery(ldapSession, baseDN, query, attributes, ldap.ScopeWholeSubtree)
	return entries
}

func QueryAllNamingContexts(ldapSession *Session, query string, attributes []string, scope int) []*ldap.Entry {
	// Fetch the RootDSE entry to get the naming contexts
	rootDSE := GetRootDSE(ldapSession)
	if rootDSE == nil {
		// logger.Warn("Could not retrieve RootDSE.")
		return nil
	}

	// Retrieve the namingContexts attribute
	namingContexts := rootDSE.GetAttributeValues("namingContexts")
	if len(namingContexts) == 0 {
		//logger.Warn("No naming contexts found.")
		return nil
	}

	// Store all entries from all naming contexts
	var allEntries []*ldap.Entry

	// Iterate over each naming context and perform the query
	for _, context := range namingContexts {
		entries := RawQuery(ldapSession, context, query, attributes, scope)
		if entries != nil {
			allEntries = append(allEntries, entries...)
		}
	}

	return allEntries
}
