package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"time"

	"winacl/ldap"
	"winacl/logger"
	"winacl/securitydescriptor"
)

var (
	// Configuration
	useLdaps bool
	quiet    bool
	debug    bool
	// Network
	dnsNameServer    string
	domainController string
	ldapPort         int

	// Authentifications
	authDomain   string
	authUsername string
	// noPass         bool
	authPassword string
	authHashes   string
	// authKey        string
	// useKerberos    bool
	distinguishedName string
)

func parseArgs() {
	flag.BoolVar(&useLdaps, "use-ldaps", false, "Use LDAPS instead of LDAP.")
	flag.BoolVar(&quiet, "quiet", false, "Show no information at all.")
	flag.BoolVar(&debug, "debug", false, "Debug mode.")

	flag.StringVar(&domainController, "dc-ip", "", "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter.")

	flag.IntVar(&ldapPort, "port", 0, "Port number to connect to LDAP server.")

	flag.StringVar(&dnsNameServer, "ns", "", "IP Address of the dns server to use in the queries. If omitted it will use the ip of the domain controller specified in the -host parameter.")
	flag.StringVar(&dnsNameServer, "nameserver", "", "IP Address of the dns server to use in the queries. If omitted it will use the ip of the domain controller specified in the -host parameter.")

	flag.StringVar(&authDomain, "d", "", "Active Directory domain to authenticate to.")
	flag.StringVar(&authDomain, "domain", "", "Active Directory domain to authenticate to.")

	flag.StringVar(&authUsername, "u", "", "User to authenticate as.")
	flag.StringVar(&authUsername, "username", "", "User to authenticate as.")

	//flag.BoolVar(&noPass, "no-pass", false, "don't ask for password (useful for -k)")
	flag.StringVar(&authPassword, "p", "", "password to authenticate with.")
	flag.StringVar(&authPassword, "password", "", "password to authenticate with.")

	flag.StringVar(&authHashes, "H", "", "NT/LM hashes, format is LMhash:NThash.")
	flag.StringVar(&authHashes, "hashes", "", "NT/LM hashes, format is LMhash:NThash.")
	//flag.StringVar(&authKey, "aes-key", "", "AES key to use for Kerberos Authentication (128 or 256 bits)")
	//flag.BoolVar(&useKerberos, "k", false, "Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

	flag.StringVar(&distinguishedName, "D", "", "distinguishedName.")
	flag.StringVar(&distinguishedName, "distinguishedName", "", "distinguishedName.")

	flag.Parse()

	if ldapPort == 0 {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}
}

func main() {
	parseArgs()

	startTime := time.Now()

	if debug {
		if !useLdaps {
			logger.Debug(fmt.Sprintf("Connecting to remote ldap://%s:%d ...", domainController, ldapPort))
		} else {
			logger.Debug(fmt.Sprintf("Connecting to remote ldaps://%s:%d ...", domainController, ldapPort))
		}
	}
	ldapSession := ldap.Session{}
	ldapSession.InitSession(
		domainController,
		ldapPort,
		useLdaps,
		authDomain,
		authUsername,
		authPassword,
		debug,
	)
	connected := ldapSession.Connect()

	if connected {
		logger.Info(fmt.Sprintf("Connected as '%s\\%s'", authDomain, authUsername))

		query := fmt.Sprintf("(distinguishedName=%s)", distinguishedName)

		if debug {
			logger.Debug(fmt.Sprintf("LDAP query used: %s", query))
		}

		attributes := []string{"distinguishedName", "ntSecurityDescriptor"}
		ldapResults := ldap.QueryWholeSubtree(&ldapSession, "", query, attributes)

		for _, entry := range ldapResults {
			ntSecurityDescriptor := securitydescriptor.NtSecurityDescriptor{}

			if debug {
				logger.Debug(fmt.Sprintf("| distinguishedName: %s", entry.GetAttributeValue("distinguishedName")))
				logger.Debug(fmt.Sprintf("| ntSecurityDescriptor: %s", hex.EncodeToString(entry.GetEqualFoldRawAttributeValue("ntSecurityDescriptor"))))
			}

			ntSecurityDescriptor.Parse(entry.GetEqualFoldRawAttributeValue("ntSecurityDescriptor"))

			ntSecurityDescriptor.Describe(0)
		}

	} else {
		if debug {
			logger.Warn("Error: Could not create ldapSession.")
		}
	}

	// Elapsed time
	elapsedTime := time.Since(startTime).Round(time.Millisecond)
	hours := int(elapsedTime.Hours())
	minutes := int(elapsedTime.Minutes()) % 60
	seconds := int(elapsedTime.Seconds()) % 60
	milliseconds := int(elapsedTime.Milliseconds()) % 1000
	logger.Info(fmt.Sprintf("Total time elapsed: %02dh%02dm%02d.%04ds", hours, minutes, seconds, milliseconds))
}
