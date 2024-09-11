package ldap

import "fmt"

func GetAllCertificates(ldapSession *Session) []string {
	distinguishedNames := []string{}

	query := "(objectClass=pKICertificateTemplate)"
	attributes := []string{"distinguishedName"}
	ldapResults := QueryWholeSubtree(ldapSession, "configurationNamingContext", query, attributes)

	if len(ldapResults) != 0 {
		for _, entry := range ldapResults {
			distinguishedNames = append(distinguishedNames, entry.GetAttributeValue("distinguishedName"))
		}
	}

	return distinguishedNames
}

func GetNamesOfAllEnabledCertificates(ldapSession *Session) []string {
	names := []string{}

	queryPKIEnrollmentService := "(objectCategory=pKIEnrollmentService)"

	attributes := []string{"certificateTemplates"}

	ldapResultPKIEnrollmentService := QueryWholeSubtree(ldapSession, "configurationNamingContext", queryPKIEnrollmentService, attributes)

	// We have found pKIEnrollmentServices
	if len(ldapResultPKIEnrollmentService) != 0 {
		for _, entry := range ldapResultPKIEnrollmentService {
			// Iterating on the enabled certificate templates of the pKIEnrollmentService
			names = append(names, entry.GetEqualFoldAttributeValues("certificateTemplates")...)
		}
	}

	return names
}

func GetDistinguishedNamesOfAllEnabledCertificates(ldapSession *Session) []string {
	distinguishedNames := []string{}
	certificateTemplateNames := GetNamesOfAllEnabledCertificates(ldapSession)

	for _, name := range certificateTemplateNames {
		queryPKICertificateTemplate := "(&"
		queryPKICertificateTemplate += "(objectClass=pKICertificateTemplate)"
		queryPKICertificateTemplate += fmt.Sprintf("(name=%s)", name)
		queryPKICertificateTemplate += ")"

		attributes := []string{"distinguishedName"}

		ldapResultsPKICertificateTemplate := QueryWholeSubtree(ldapSession, "configurationNamingContext", queryPKICertificateTemplate, attributes)

		if len(ldapResultsPKICertificateTemplate) != 0 {
			for _, entry := range ldapResultsPKICertificateTemplate {
				distinguishedNames = append(distinguishedNames, entry.GetAttributeValue("distinguishedName"))
			}
		}

	}

	return distinguishedNames
}
