#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DescribeNTSecurityDescriptor.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Nov 2023

import argparse
import binascii
from enum import Enum, IntFlag
import io
import ldap3
from ldap3.protocol.formatters.formatters import format_sid
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import nt_hash, parse_lm_nt_hashes
import os
import random
import re
import struct
import sys


VERSION = "1.2"


# LDAP controls
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
LDAP_PAGED_RESULT_OID_STRING = "1.2.840.113556.1.4.319"
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f14f3610-ee22-4d07-8a24-1bf1466cba5f
LDAP_SERVER_NOTIFICATION_OID = "1.2.840.113556.1.4.528"


class LDAPSearcher(object):
    """
    LDAPSearcher is a utility class designed to facilitate the execution of LDAP queries against an LDAP server.
    It encapsulates the details of establishing a session with an LDAP server, constructing and executing queries,
    and processing the results. This class aims to simplify LDAP interactions, making it easier to retrieve and
    manipulate directory information.

    Attributes:
        ldap_server (str): The address of the LDAP server to connect to.
        ldap_session (ldap3.Connection): An established session with the LDAP server.
        debug (bool): A flag indicating whether to output debug information.

    Methods:
        query(base_dn, query, attributes, page_size): Executes an LDAP query and returns the results.
    """

    schemaIDGUID = {}

    def __init__(self, ldap_server, ldap_session, debug=False):
        super(LDAPSearcher, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.debug = debug

    def query(self, base_dn, query, attributes=['*'], page_size=1000):
        """
        Executes an LDAP query with optional notification control.

        This method performs an LDAP search operation based on the provided query and attributes. It supports
        pagination to handle large datasets and can optionally enable notification control to receive updates
        about changes in the LDAP directory.

        Parameters:
        - query (str): The LDAP query string.
        - attributes (list of str): A list of attribute names to include in the search results. Defaults to ['*'], which returns all attributes.
        - notify (bool): If True, enables the LDAP server notification control to receive updates about changes. Defaults to False.

        Returns:
        - dict: A dictionary where each key is a distinguished name (DN) and each value is a dictionary of attributes for that DN.

        Raises:
        - ldap3.core.exceptions.LDAPInvalidFilterError: If the provided query string is not a valid LDAP filter.
        - Exception: For any other issues encountered during the search operation.
        """

        results = {}
        try:
            # https://ldap3.readthedocs.io/en/latest/searches.html#the-search-operation
            paged_response = True
            paged_cookie = None
            while paged_response == True:
                self.ldap_session.search(
                    base_dn,
                    query,
                    attributes=attributes,
                    size_limit=0,
                    paged_size=page_size,
                    paged_cookie=paged_cookie
                )
                if "controls" in self.ldap_session.result.keys():
                    if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                        next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                        if len(next_cookie) == 0:
                            paged_response = False
                        else:
                            paged_response = True
                            paged_cookie = next_cookie
                    else:
                        paged_response = False
                else:
                    paged_response = False
                for entry in self.ldap_session.response:
                    if entry['type'] != 'searchResEntry':
                        continue
                    results[entry['dn'].lower()] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results

    def query_all_naming_contexts(self, query, attributes=['*'], page_size=1000):
        """
        Queries all naming contexts on the LDAP server with the given query and attributes.

        This method iterates over all naming contexts retrieved from the LDAP server's information,
        performing a paged search for each context using the provided query and attributes. The results
        are aggregated and returned as a dictionary where each key is a distinguished name (DN) and
        each value is a dictionary of attributes for that DN.

        Parameters:
        - query (str): The LDAP query to execute.
        - attributes (list of str): A list of attribute names to retrieve for each entry. Defaults to ['*'] which fetches all attributes.

        Returns:
        - dict: A dictionary where each key is a DN and each value is a dictionary of attributes for that DN.
        """

        results = {}
        try:
            for naming_context in self.ldap_server.info.naming_contexts:
                paged_response = True
                paged_cookie = None
                while paged_response == True:
                    self.ldap_session.search(
                        naming_context,
                        query,
                        attributes=attributes,
                        size_limit=0,
                        paged_size=page_size,
                        paged_cookie=paged_cookie
                    )
                    if "controls" in self.ldap_session.result.keys():
                        if LDAP_PAGED_RESULT_OID_STRING in self.ldap_session.result["controls"].keys():
                            next_cookie = self.ldap_session.result["controls"][LDAP_PAGED_RESULT_OID_STRING]["value"]["cookie"]
                            if len(next_cookie) == 0:
                                paged_response = False
                            else:
                                paged_response = True
                                paged_cookie = next_cookie
                        else:
                            paged_response = False
                    else:
                        paged_response = False
                    for entry in self.ldap_session.response:
                        if entry['type'] != 'searchResEntry':
                            continue
                        results[entry['dn']] = entry["attributes"]
        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
            print("Invalid Filter. (ldap3.core.exceptions.LDAPInvalidFilterError)")
        except Exception as e:
            raise e
        return results

    def generate_guid_map_from_ldap(self):
        if self.debug:
            print("[>] Extracting the list of schemaIDGUID ...")

        results = self.query(
            base_dn=self.ldap_server.info.other["schemaNamingContext"],
            query="(schemaIDGUID=*)",
            attributes=["*"]
        )

        self.schemaIDGUID = {}
        for distinguishedName in results.keys():
            __guid = GUID.load(data=results[distinguishedName]["schemaIDGUID"])
            self.schemaIDGUID[__guid.toFormatD()] = results[distinguishedName]
            self.schemaIDGUID[__guid.toFormatD()]["distinguishedName"] = distinguishedName

        if self.debug:
            print("[>] done.")


## GUID

class GUIDFormat(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = 0
    D = 1
    B = 2
    P = 3
    X = 4


class GUIDImportFormatPattern(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = "^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$"
    D = "^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$"
    B = "^{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})}$"
    P = "^\\(([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\\)$"
    X = "^{0x([0-9a-f]{8}),0x([0-9a-f]{4}),0x([0-9a-f]{4}),{0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2})}}$"


class InvalidGUIDFormat(Exception):
    pass


class GUID(object):
    """
    GUID

    See: https://docs.microsoft.com/en-us/dotnet/api/system.GUID?view=net-5.0
    """

    Format: GUIDFormat = None

    def __init__(self, a=None, b=None, c=None, d=None, e=None):
        super(GUID, self).__init__()
        if a is None:
            a = sum([random.randint(0, 0xff) << (8*k) for k in range(4)])
        if b is None:
            b = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if c is None:
            c = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if d is None:
            d = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if e is None:
            e = sum([random.randint(0, 0xff) << (8*k) for k in range(6)])
        self.a, self.b, self.c, self.d, self.e = a, b, c, d, e

    @classmethod
    def load(cls, data):
        self = None

        if type(data) == bytes and len(data) == 16:
            return GUID.fromRawBytes(data)

        elif type(data) == str:
            matched = re.match(GUIDImportFormatPattern.X.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatX(matched.group(0))
                self.Format = GUIDFormat.X
                return self

            matched = re.match(GUIDImportFormatPattern.P.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatP(matched.group(0))
                self.Format = GUIDFormat.P
                return self

            matched = re.match(GUIDImportFormatPattern.D.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatD(matched.group(0))
                self.Format = GUIDFormat.D
                return self

            matched = re.match(GUIDImportFormatPattern.B.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatB(matched.group(0))
                self.Format = GUIDFormat.B
                return self

            matched = re.match(GUIDImportFormatPattern.N.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatN(matched.group(0))
                self.Format = GUIDFormat.N
                return self

        return self

    # Import formats

    @classmethod
    def fromRawBytes(cls, data: bytes):
        if len(data) != 16:
            raise InvalidGUIDFormat("fromRawBytes takes exactly 16 bytes of data in input")
        # 0xffffff
        a = struct.unpack("<L", data[0:4])[0]
        # 0xffff
        b = struct.unpack("<H", data[4:6])[0]
        # 0xffff
        c = struct.unpack("<H", data[6:8])[0]
        # 0xffff
        d = struct.unpack(">H", data[8:10])[0]
        # 0xffffffffffff
        e = binascii.hexlify(data[10:16]).decode("UTF-8").rjust(6, '0')
        e = int(e, 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatN(cls, data):
        # N => 32 digits : 00000000000000000000000000000000
        if not re.match(GUIDImportFormatPattern.N.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format N should be 32 hexadecimal characters separated in five parts.")
        a = int(data[0:8], 16)
        b = int(data[8:12], 16)
        c = int(data[12:16], 16)
        d = int(data[16:20], 16)
        e = int(data[20:32], 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatD(cls, data):
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        if not re.match(GUIDImportFormatPattern.D.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format D should be 32 hexadecimal characters separated in five parts.")
        a, b, c, d, e = map(lambda x: int(x, 16), data.split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatB(cls, data):
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        if not re.match(GUIDImportFormatPattern.B.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format B should be 32 hexadecimal characters separated in five parts enclosed in braces.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatP(cls, data):
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        if not re.match(GUIDImportFormatPattern.P.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatX(cls, data):
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        if not re.match(GUIDImportFormatPattern.X.value, data, re.IGNORECASE):
            raise InvalidGUIDFormat("GUID Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}.")
        hex_a, hex_b, hex_c, rest = data[1:-1].split(',', 3)
        rest = rest[1:-1].split(',')
        a = int(hex_a, 16)
        b = int(hex_b, 16)
        c = int(hex_c, 16)
        d = int(rest[0], 16) * 0x100 + int(rest[1], 16)
        e = int(rest[2], 16) * (0x1 << (8 * 5))
        e += int(rest[3], 16) * (0x1 << (8 * 4))
        e += int(rest[4], 16) * (0x1 << (8 * 3))
        e += int(rest[5], 16) * (0x1 << (8 * 2))
        e += int(rest[6], 16) * (0x1 << 8)
        e += int(rest[7], 16)
        self = cls(a, b, c, d, e)
        return self

    # Export formats

    def toRawBytes(self):
        data = b''
        data += struct.pack("<L", self.a)
        data += struct.pack("<H", self.b)
        data += struct.pack("<H", self.c)
        data += struct.pack(">H", self.d)
        data += binascii.unhexlify(hex(self.e)[2:].rjust(12, '0'))
        return data

    def toFormatN(self) -> str:
        # N => 32 digits :
        # 00000000000000000000000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s%s%s%s%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatD(self) -> str:
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s-%s-%s-%s-%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatB(self) -> str:
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "{%s-%s-%s-%s-%s}" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatP(self) -> str:
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "(%s-%s-%s-%s-%s)" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatX(self) -> str:
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_d1, hex_d2 = hex_d[:2], hex_d[2:4]
        hex_e = hex(self.e)[2:].rjust(12, '0')
        hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6 = hex_e[:2], hex_e[2:4], hex_e[4:6], hex_e[6:8], hex_e[8:10], hex_e[10:12]
        return "{0x%s,0x%s,0x%s,{0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s}}" % (hex_a, hex_b, hex_c, hex_d1, hex_d2, hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6)

    def __repr__(self):
        return "<GUID %s>" % self.toFormatB()

## 


def parseArgs():
    print("DescribeNTSecurityDescriptor.py v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(add_help=True, description="Parse and describe the contents of a raw ntSecurityDescriptor structure")

    parser.add_argument("--use-ldaps", action="store_true", default=False, help="Use LDAPS instead of LDAP")

    authconn = parser.add_argument_group("authentication & connection")
    authconn.add_argument("--dc-ip", action="store", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
    authconn.add_argument("--kdcHost", dest="kdcHost", action="store", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", help="user to authenticate with")

    secret = parser.add_argument_group()
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", action="store_true", help="don\"t ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    options = parser.parse_args()
 

    if options.auth_username is not None:
        if options.auth_password is None and options.no_pass == False and options.auth_hashes is None:
            print("[+] No password of hashes provided and --no-pass is '%s'" % options.no_pass)
            from getpass import getpass
            if options.auth_domain is not None:
                options.auth_password = getpass("  | Provide a password for '%s\\%s':" % (options.auth_domain, options.auth_username))
            else:
                options.auth_password = getpass("  | Provide a password for '%s':" % options.auth_username)

    return options


if __name__ == "__main__":
    options = parseArgs()

    ls = None
    if options.auth_username is not None:
        # Parse hashes
        auth_lm_hash = ""
        auth_nt_hash = ""
        if options.auth_hashes is not None:
            if ":" in options.auth_hashes:
                auth_lm_hash = options.auth_hashes.split(":")[0]
                auth_nt_hash = options.auth_hashes.split(":")[1]
            else:
                auth_nt_hash = options.auth_hashes
        
        # Use AES Authentication key if available
        if options.auth_key is not None:
            options.use_kerberos = True
        if options.use_kerberos is True and options.kdcHost is None:
            print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
            exit()

        # Try to authenticate with specified credentials
        print("[>] Try to authenticate as '%s\\%s' on %s ... " % (options.auth_domain, options.auth_username, options.dc_ip))
        ldap_server, ldap_session = init_ldap_session(
            auth_domain=options.auth_domain,
            auth_dc_ip=options.dc_ip,
            auth_username=options.auth_username,
            auth_password=options.auth_password,
            auth_lm_hash=auth_lm_hash,
            auth_nt_hash=auth_nt_hash,
            auth_key=options.auth_key,
            use_kerberos=options.use_kerberos,
            kdcHost=options.kdcHost,
            use_ldaps=options.use_ldaps
        )
        print("[+] Authentication successful!\n")
        ls = LDAPSearcher(
            ldap_server=ldap_server,
            ldap_session=ldap_session
        )
        ls.generate_guid_map_from_ldap()

        data = [(key, value["name"]) for key, value in ls.schemaIDGUID.items()]
        data = sorted(data, key=lambda x:x[1])

        f = open("./ADSchemaAttributes.go", "w")
        f.write("package guid\n\n")

        f.write("const (\n")
        for guid, name in data:
            f.write('\tSCHEMA_ATTRIBUTE_%s = "%s"\n' % (name.upper().replace("-","_"), guid))
        f.write(")\n\n\n")

        f.write("var SchemaAttributeDisplayNameToGUID = map[string]string{\n")
        for guid, name in data:
            f.write('\t"%s": SCHEMA_ATTRIBUTE_%s,\n' % (name.lower(), name.upper().replace("-","_")))
        f.write("}\n\n\n")

        f.write("var GUIDToSchemaAttributeDisplayName = map[string]string{\n")
        for guid, name in data:
            f.write('\tSCHEMA_ATTRIBUTE_%s: "%s",\n' % (name.upper().replace("-","_"), name.lower()))
        f.write("}\n\n\n")

        f.close()