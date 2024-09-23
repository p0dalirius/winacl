package rights

const (
	EXTENDED_RIGHT_ABANDON_REPLICATION                           = "ee914b82-0a98-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_ADD_GUID                                      = "440820ad-65b4-11d1-a3da-0000f875ae0d"
	EXTENDED_RIGHT_ALLOCATE_RIDS                                 = "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_ALLOWED_TO_AUTHENTICATE                       = "68b1d179-0d15-4d4f-ab71-46152e79a7bc"
	EXTENDED_RIGHT_APPLY_GROUP_POLICY                            = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
	EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT                        = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	EXTENDED_RIGHT_CERTIFICATE_AUTOENROLLMENT                    = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
	EXTENDED_RIGHT_CHANGE_DOMAIN_MASTER                          = "014bf69c-7b3b-11d1-85f6-08002be74fab"
	EXTENDED_RIGHT_CHANGE_INFRASTRUCTURE_MASTER                  = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd"
	EXTENDED_RIGHT_CHANGE_PDC                                    = "bae50096-4752-11d1-9052-00c04fc2d4cf"
	EXTENDED_RIGHT_CHANGE_RID_MASTER                             = "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_CHANGE_SCHEMA_MASTER                          = "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_CREATE_INBOUND_FOREST_TRUST                   = "e2a36dc9-ae17-47c3-b58b-be34c55ba633"
	EXTENDED_RIGHT_DO_GARBAGE_COLLECTION                         = "fec364e0-0a98-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_DOMAIN_ADMINISTER_SERVER                      = "ab721a52-1e2f-11d0-9819-00aa0040529b"
	EXTENDED_RIGHT_DS_CHECK_STALE_PHANTOMS                       = "69ae6200-7f46-11d2-b9ad-00c04f79f805"
	EXTENDED_RIGHT_DS_EXECUTE_INTENTIONS_SCRIPT                  = "2f16c4a5-b98e-432c-952a-cb388ba33f2e"
	EXTENDED_RIGHT_DS_INSTALL_REPLICA                            = "9923a32a-3607-11d2-b9be-0000f87a36b2"
	EXTENDED_RIGHT_DS_QUERY_SELF_QUOTA                           = "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc"
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES                    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL                = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET    = "89e95b76-444d-4c62-991a-0facbeda640c"
	EXTENDED_RIGHT_DS_REPLICATION_MANAGE_TOPOLOGY                = "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2"
	EXTENDED_RIGHT_DS_REPLICATION_MONITOR_TOPOLOGY               = "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96"
	EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE                    = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
	EXTENDED_RIGHT_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD = "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5"
	EXTENDED_RIGHT_GENERATE_RSOP_LOGGING                         = "b7b1b3de-ab09-4242-9e30-9980e5d322f7"
	EXTENDED_RIGHT_GENERATE_RSOP_PLANNING                        = "b7b1b3dd-ab09-4242-9e30-9980e5d322f7"
	EXTENDED_RIGHT_MANAGE_OPTIONAL_FEATURES                      = "7c0e2a7c-a419-48e4-a995-10180aad54dd"
	EXTENDED_RIGHT_MIGRATE_SID_HISTORY                           = "ba33815a-4f93-4c76-87f3-57574bff8109"
	EXTENDED_RIGHT_MSMQ_OPEN_CONNECTOR                           = "b4e60130-df3f-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_PEEK                                     = "06bd3201-df3e-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_PEEK_COMPUTER_JOURNAL                    = "4b6e08c3-df3c-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_PEEK_DEAD_LETTER                         = "4b6e08c1-df3c-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_RECEIVE                                  = "06bd3200-df3e-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_RECEIVE_COMPUTER_JOURNAL                 = "4b6e08c2-df3c-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_RECEIVE_DEAD_LETTER                      = "4b6e08c0-df3c-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_RECEIVE_JOURNAL                          = "06bd3203-df3e-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_MSMQ_SEND                                     = "06bd3202-df3e-11d1-9c86-006008764d0e"
	EXTENDED_RIGHT_OPEN_ADDRESS_BOOK                             = "a1990816-4298-11d1-ade2-00c04fd8d5cd"
	EXTENDED_RIGHT_READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION  = "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2"
	EXTENDED_RIGHT_REANIMATE_TOMBSTONES                          = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f"
	EXTENDED_RIGHT_RECALCULATE_HIERARCHY                         = "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd"
	EXTENDED_RIGHT_RECALCULATE_SECURITY_INHERITANCE              = "62dd28a8-7f46-11d2-b9ad-00c04f79f805"
	EXTENDED_RIGHT_RECEIVE_AS                                    = "ab721a56-1e2f-11d0-9819-00aa0040529b"
	EXTENDED_RIGHT_REFRESH_GROUP_CACHE                           = "9432c620-033c-4db7-8b58-14ef6d0bf477"
	EXTENDED_RIGHT_RELOAD_SSL_CERTIFICATE                        = "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8"
	EXTENDED_RIGHT_RUN_PROTECT_ADMIN_GROUPS_TASK                 = "7726b9d5-a4b4-4288-a6b2-dce952e80a7f"
	EXTENDED_RIGHT_SAM_ENUMERATE_ENTIRE_DOMAIN                   = "91d67418-0135-4acc-8d79-c08e857cfbec"
	EXTENDED_RIGHT_SEND_AS                                       = "ab721a54-1e2f-11d0-9819-00aa0040529b"
	EXTENDED_RIGHT_SEND_TO                                       = "ab721a55-1e2f-11d0-9819-00aa0040529b"
	EXTENDED_RIGHT_UNEXPIRE_PASSWORD                             = "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501"
	EXTENDED_RIGHT_UPDATE_PASSWORD_NOT_REQUIRED_BIT              = "280f369c-67c7-438e-ae98-1d46f3c6f541"
	EXTENDED_RIGHT_UPDATE_SCHEMA_CACHE                           = "be2bb760-7f46-11d2-b9ad-00c04f79f805"
	EXTENDED_RIGHT_USER_CHANGE_PASSWORD                          = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD                    = "00299570-246d-11d0-a768-00aa006e0529"
	EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER                    = "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e"
	EXTENDED_RIGHT_DS_READ_PARTITION_SECRETS                     = "084c93a2-620d-4879-a836-f0ae47de0e89"
	EXTENDED_RIGHT_DS_WRITE_PARTITION_SECRETS                    = "94825a8d-b171-4116-8146-1e34d8f54401"
	EXTENDED_RIGHT_DS_SET_OWNER                                  = "4125c71f-7fac-4ff0-bcb7-f09a41325286"
	EXTENDED_RIGHT_DS_BYPASS_QUOTA                               = "88a9933e-e5c8-4f2a-9dd7-2527416b8092"
	EXTENDED_RIGHT_DS_VALIDATED_WRITE_COMPUTER                   = "9b026da6-0d3c-465c-8bee-5199d7165cba"
)

var ExtendedRightToGUID = map[string]string{
	"EXTENDED_RIGHT_ABANDON_REPLICATION":                           EXTENDED_RIGHT_ABANDON_REPLICATION,
	"EXTENDED_RIGHT_ADD_GUID":                                      EXTENDED_RIGHT_ADD_GUID,
	"EXTENDED_RIGHT_ALLOCATE_RIDS":                                 EXTENDED_RIGHT_ALLOCATE_RIDS,
	"EXTENDED_RIGHT_ALLOWED_TO_AUTHENTICATE":                       EXTENDED_RIGHT_ALLOWED_TO_AUTHENTICATE,
	"EXTENDED_RIGHT_APPLY_GROUP_POLICY":                            EXTENDED_RIGHT_APPLY_GROUP_POLICY,
	"EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT":                        EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT,
	"EXTENDED_RIGHT_CERTIFICATE_AUTOENROLLMENT":                    EXTENDED_RIGHT_CERTIFICATE_AUTOENROLLMENT,
	"EXTENDED_RIGHT_CHANGE_DOMAIN_MASTER":                          EXTENDED_RIGHT_CHANGE_DOMAIN_MASTER,
	"EXTENDED_RIGHT_CHANGE_INFRASTRUCTURE_MASTER":                  EXTENDED_RIGHT_CHANGE_INFRASTRUCTURE_MASTER,
	"EXTENDED_RIGHT_CHANGE_PDC":                                    EXTENDED_RIGHT_CHANGE_PDC,
	"EXTENDED_RIGHT_CHANGE_RID_MASTER":                             EXTENDED_RIGHT_CHANGE_RID_MASTER,
	"EXTENDED_RIGHT_CHANGE_SCHEMA_MASTER":                          EXTENDED_RIGHT_CHANGE_SCHEMA_MASTER,
	"EXTENDED_RIGHT_CREATE_INBOUND_FOREST_TRUST":                   EXTENDED_RIGHT_CREATE_INBOUND_FOREST_TRUST,
	"EXTENDED_RIGHT_DO_GARBAGE_COLLECTION":                         EXTENDED_RIGHT_DO_GARBAGE_COLLECTION,
	"EXTENDED_RIGHT_DOMAIN_ADMINISTER_SERVER":                      EXTENDED_RIGHT_DOMAIN_ADMINISTER_SERVER,
	"EXTENDED_RIGHT_DS_CHECK_STALE_PHANTOMS":                       EXTENDED_RIGHT_DS_CHECK_STALE_PHANTOMS,
	"EXTENDED_RIGHT_DS_EXECUTE_INTENTIONS_SCRIPT":                  EXTENDED_RIGHT_DS_EXECUTE_INTENTIONS_SCRIPT,
	"EXTENDED_RIGHT_DS_INSTALL_REPLICA":                            EXTENDED_RIGHT_DS_INSTALL_REPLICA,
	"EXTENDED_RIGHT_DS_QUERY_SELF_QUOTA":                           EXTENDED_RIGHT_DS_QUERY_SELF_QUOTA,
	"EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES":                    EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES,
	"EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL":                EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL,
	"EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET":    EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET,
	"EXTENDED_RIGHT_DS_REPLICATION_MANAGE_TOPOLOGY":                EXTENDED_RIGHT_DS_REPLICATION_MANAGE_TOPOLOGY,
	"EXTENDED_RIGHT_DS_REPLICATION_MONITOR_TOPOLOGY":               EXTENDED_RIGHT_DS_REPLICATION_MONITOR_TOPOLOGY,
	"EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE":                    EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE,
	"EXTENDED_RIGHT_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD": EXTENDED_RIGHT_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD,
	"EXTENDED_RIGHT_GENERATE_RSOP_LOGGING":                         EXTENDED_RIGHT_GENERATE_RSOP_LOGGING,
	"EXTENDED_RIGHT_GENERATE_RSOP_PLANNING":                        EXTENDED_RIGHT_GENERATE_RSOP_PLANNING,
	"EXTENDED_RIGHT_MANAGE_OPTIONAL_FEATURES":                      EXTENDED_RIGHT_MANAGE_OPTIONAL_FEATURES,
	"EXTENDED_RIGHT_MIGRATE_SID_HISTORY":                           EXTENDED_RIGHT_MIGRATE_SID_HISTORY,
	"EXTENDED_RIGHT_MSMQ_OPEN_CONNECTOR":                           EXTENDED_RIGHT_MSMQ_OPEN_CONNECTOR,
	"EXTENDED_RIGHT_MSMQ_PEEK":                                     EXTENDED_RIGHT_MSMQ_PEEK,
	"EXTENDED_RIGHT_MSMQ_PEEK_COMPUTER_JOURNAL":                    EXTENDED_RIGHT_MSMQ_PEEK_COMPUTER_JOURNAL,
	"EXTENDED_RIGHT_MSMQ_PEEK_DEAD_LETTER":                         EXTENDED_RIGHT_MSMQ_PEEK_DEAD_LETTER,
	"EXTENDED_RIGHT_MSMQ_RECEIVE":                                  EXTENDED_RIGHT_MSMQ_RECEIVE,
	"EXTENDED_RIGHT_MSMQ_RECEIVE_COMPUTER_JOURNAL":                 EXTENDED_RIGHT_MSMQ_RECEIVE_COMPUTER_JOURNAL,
	"EXTENDED_RIGHT_MSMQ_RECEIVE_DEAD_LETTER":                      EXTENDED_RIGHT_MSMQ_RECEIVE_DEAD_LETTER,
	"EXTENDED_RIGHT_MSMQ_RECEIVE_JOURNAL":                          EXTENDED_RIGHT_MSMQ_RECEIVE_JOURNAL,
	"EXTENDED_RIGHT_MSMQ_SEND":                                     EXTENDED_RIGHT_MSMQ_SEND,
	"EXTENDED_RIGHT_OPEN_ADDRESS_BOOK":                             EXTENDED_RIGHT_OPEN_ADDRESS_BOOK,
	"EXTENDED_RIGHT_READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION":  EXTENDED_RIGHT_READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION,
	"EXTENDED_RIGHT_REANIMATE_TOMBSTONES":                          EXTENDED_RIGHT_REANIMATE_TOMBSTONES,
	"EXTENDED_RIGHT_RECALCULATE_HIERARCHY":                         EXTENDED_RIGHT_RECALCULATE_HIERARCHY,
	"EXTENDED_RIGHT_RECALCULATE_SECURITY_INHERITANCE":              EXTENDED_RIGHT_RECALCULATE_SECURITY_INHERITANCE,
	"EXTENDED_RIGHT_RECEIVE_AS":                                    EXTENDED_RIGHT_RECEIVE_AS,
	"EXTENDED_RIGHT_REFRESH_GROUP_CACHE":                           EXTENDED_RIGHT_REFRESH_GROUP_CACHE,
	"EXTENDED_RIGHT_RELOAD_SSL_CERTIFICATE":                        EXTENDED_RIGHT_RELOAD_SSL_CERTIFICATE,
	"EXTENDED_RIGHT_RUN_PROTECT_ADMIN_GROUPS_TASK":                 EXTENDED_RIGHT_RUN_PROTECT_ADMIN_GROUPS_TASK,
	"EXTENDED_RIGHT_SAM_ENUMERATE_ENTIRE_DOMAIN":                   EXTENDED_RIGHT_SAM_ENUMERATE_ENTIRE_DOMAIN,
	"EXTENDED_RIGHT_SEND_AS":                                       EXTENDED_RIGHT_SEND_AS,
	"EXTENDED_RIGHT_SEND_TO":                                       EXTENDED_RIGHT_SEND_TO,
	"EXTENDED_RIGHT_UNEXPIRE_PASSWORD":                             EXTENDED_RIGHT_UNEXPIRE_PASSWORD,
	"EXTENDED_RIGHT_UPDATE_PASSWORD_NOT_REQUIRED_BIT":              EXTENDED_RIGHT_UPDATE_PASSWORD_NOT_REQUIRED_BIT,
	"EXTENDED_RIGHT_UPDATE_SCHEMA_CACHE":                           EXTENDED_RIGHT_UPDATE_SCHEMA_CACHE,
	"EXTENDED_RIGHT_USER_CHANGE_PASSWORD":                          EXTENDED_RIGHT_USER_CHANGE_PASSWORD,
	"EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD":                    EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD,
	"EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER":                    EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER,
	"EXTENDED_RIGHT_DS_READ_PARTITION_SECRETS":                     EXTENDED_RIGHT_DS_READ_PARTITION_SECRETS,
	"EXTENDED_RIGHT_DS_WRITE_PARTITION_SECRETS":                    EXTENDED_RIGHT_DS_WRITE_PARTITION_SECRETS,
	"EXTENDED_RIGHT_DS_SET_OWNER":                                  EXTENDED_RIGHT_DS_SET_OWNER,
	"EXTENDED_RIGHT_DS_BYPASS_QUOTA":                               EXTENDED_RIGHT_DS_BYPASS_QUOTA,
	"EXTENDED_RIGHT_DS_VALIDATED_WRITE_COMPUTER":                   EXTENDED_RIGHT_DS_VALIDATED_WRITE_COMPUTER,
}

var GUIDToExtendedRight = map[string]string{
	EXTENDED_RIGHT_ABANDON_REPLICATION:                           "EXTENDED_RIGHT_ABANDON_REPLICATION",
	EXTENDED_RIGHT_ADD_GUID:                                      "EXTENDED_RIGHT_ADD_GUID",
	EXTENDED_RIGHT_ALLOCATE_RIDS:                                 "EXTENDED_RIGHT_ALLOCATE_RIDS",
	EXTENDED_RIGHT_ALLOWED_TO_AUTHENTICATE:                       "EXTENDED_RIGHT_ALLOWED_TO_AUTHENTICATE",
	EXTENDED_RIGHT_APPLY_GROUP_POLICY:                            "EXTENDED_RIGHT_APPLY_GROUP_POLICY",
	EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT:                        "EXTENDED_RIGHT_CERTIFICATE_ENROLLMENT",
	EXTENDED_RIGHT_CERTIFICATE_AUTOENROLLMENT:                    "EXTENDED_RIGHT_CERTIFICATE_AUTOENROLLMENT",
	EXTENDED_RIGHT_CHANGE_DOMAIN_MASTER:                          "EXTENDED_RIGHT_CHANGE_DOMAIN_MASTER",
	EXTENDED_RIGHT_CHANGE_INFRASTRUCTURE_MASTER:                  "EXTENDED_RIGHT_CHANGE_INFRASTRUCTURE_MASTER",
	EXTENDED_RIGHT_CHANGE_PDC:                                    "EXTENDED_RIGHT_CHANGE_PDC",
	EXTENDED_RIGHT_CHANGE_RID_MASTER:                             "EXTENDED_RIGHT_CHANGE_RID_MASTER",
	EXTENDED_RIGHT_CHANGE_SCHEMA_MASTER:                          "EXTENDED_RIGHT_CHANGE_SCHEMA_MASTER",
	EXTENDED_RIGHT_CREATE_INBOUND_FOREST_TRUST:                   "EXTENDED_RIGHT_CREATE_INBOUND_FOREST_TRUST",
	EXTENDED_RIGHT_DO_GARBAGE_COLLECTION:                         "EXTENDED_RIGHT_DO_GARBAGE_COLLECTION",
	EXTENDED_RIGHT_DOMAIN_ADMINISTER_SERVER:                      "EXTENDED_RIGHT_DOMAIN_ADMINISTER_SERVER",
	EXTENDED_RIGHT_DS_CHECK_STALE_PHANTOMS:                       "EXTENDED_RIGHT_DS_CHECK_STALE_PHANTOMS",
	EXTENDED_RIGHT_DS_EXECUTE_INTENTIONS_SCRIPT:                  "EXTENDED_RIGHT_DS_EXECUTE_INTENTIONS_SCRIPT",
	EXTENDED_RIGHT_DS_INSTALL_REPLICA:                            "EXTENDED_RIGHT_DS_INSTALL_REPLICA",
	EXTENDED_RIGHT_DS_QUERY_SELF_QUOTA:                           "EXTENDED_RIGHT_DS_QUERY_SELF_QUOTA",
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES:                    "EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES",
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL:                "EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_ALL",
	EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET:    "EXTENDED_RIGHT_DS_REPLICATION_GET_CHANGES_IN_FILTERED_SET",
	EXTENDED_RIGHT_DS_REPLICATION_MANAGE_TOPOLOGY:                "EXTENDED_RIGHT_DS_REPLICATION_MANAGE_TOPOLOGY",
	EXTENDED_RIGHT_DS_REPLICATION_MONITOR_TOPOLOGY:               "EXTENDED_RIGHT_DS_REPLICATION_MONITOR_TOPOLOGY",
	EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE:                    "EXTENDED_RIGHT_DS_REPLICATION_SYNCHRONIZE",
	EXTENDED_RIGHT_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD: "EXTENDED_RIGHT_ENABLE_PER_USER_REVERSIBLY_ENCRYPTED_PASSWORD",
	EXTENDED_RIGHT_GENERATE_RSOP_LOGGING:                         "EXTENDED_RIGHT_GENERATE_RSOP_LOGGING",
	EXTENDED_RIGHT_GENERATE_RSOP_PLANNING:                        "EXTENDED_RIGHT_GENERATE_RSOP_PLANNING",
	EXTENDED_RIGHT_MANAGE_OPTIONAL_FEATURES:                      "EXTENDED_RIGHT_MANAGE_OPTIONAL_FEATURES",
	EXTENDED_RIGHT_MIGRATE_SID_HISTORY:                           "EXTENDED_RIGHT_MIGRATE_SID_HISTORY",
	EXTENDED_RIGHT_MSMQ_OPEN_CONNECTOR:                           "EXTENDED_RIGHT_MSMQ_OPEN_CONNECTOR",
	EXTENDED_RIGHT_MSMQ_PEEK:                                     "EXTENDED_RIGHT_MSMQ_PEEK",
	EXTENDED_RIGHT_MSMQ_PEEK_COMPUTER_JOURNAL:                    "EXTENDED_RIGHT_MSMQ_PEEK_COMPUTER_JOURNAL",
	EXTENDED_RIGHT_MSMQ_PEEK_DEAD_LETTER:                         "EXTENDED_RIGHT_MSMQ_PEEK_DEAD_LETTER",
	EXTENDED_RIGHT_MSMQ_RECEIVE:                                  "EXTENDED_RIGHT_MSMQ_RECEIVE",
	EXTENDED_RIGHT_MSMQ_RECEIVE_COMPUTER_JOURNAL:                 "EXTENDED_RIGHT_MSMQ_RECEIVE_COMPUTER_JOURNAL",
	EXTENDED_RIGHT_MSMQ_RECEIVE_DEAD_LETTER:                      "EXTENDED_RIGHT_MSMQ_RECEIVE_DEAD_LETTER",
	EXTENDED_RIGHT_MSMQ_RECEIVE_JOURNAL:                          "EXTENDED_RIGHT_MSMQ_RECEIVE_JOURNAL",
	EXTENDED_RIGHT_MSMQ_SEND:                                     "EXTENDED_RIGHT_MSMQ_SEND",
	EXTENDED_RIGHT_OPEN_ADDRESS_BOOK:                             "EXTENDED_RIGHT_OPEN_ADDRESS_BOOK",
	EXTENDED_RIGHT_READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION:  "EXTENDED_RIGHT_READ_ONLY_REPLICATION_SECRET_SYNCHRONIZATION",
	EXTENDED_RIGHT_REANIMATE_TOMBSTONES:                          "EXTENDED_RIGHT_REANIMATE_TOMBSTONES",
	EXTENDED_RIGHT_RECALCULATE_HIERARCHY:                         "EXTENDED_RIGHT_RECALCULATE_HIERARCHY",
	EXTENDED_RIGHT_RECALCULATE_SECURITY_INHERITANCE:              "EXTENDED_RIGHT_RECALCULATE_SECURITY_INHERITANCE",
	EXTENDED_RIGHT_RECEIVE_AS:                                    "EXTENDED_RIGHT_RECEIVE_AS",
	EXTENDED_RIGHT_REFRESH_GROUP_CACHE:                           "EXTENDED_RIGHT_REFRESH_GROUP_CACHE",
	EXTENDED_RIGHT_RELOAD_SSL_CERTIFICATE:                        "EXTENDED_RIGHT_RELOAD_SSL_CERTIFICATE",
	EXTENDED_RIGHT_RUN_PROTECT_ADMIN_GROUPS_TASK:                 "EXTENDED_RIGHT_RUN_PROTECT_ADMIN_GROUPS_TASK",
	EXTENDED_RIGHT_SAM_ENUMERATE_ENTIRE_DOMAIN:                   "EXTENDED_RIGHT_SAM_ENUMERATE_ENTIRE_DOMAIN",
	EXTENDED_RIGHT_SEND_AS:                                       "EXTENDED_RIGHT_SEND_AS",
	EXTENDED_RIGHT_SEND_TO:                                       "EXTENDED_RIGHT_SEND_TO",
	EXTENDED_RIGHT_UNEXPIRE_PASSWORD:                             "EXTENDED_RIGHT_UNEXPIRE_PASSWORD",
	EXTENDED_RIGHT_UPDATE_PASSWORD_NOT_REQUIRED_BIT:              "EXTENDED_RIGHT_UPDATE_PASSWORD_NOT_REQUIRED_BIT",
	EXTENDED_RIGHT_UPDATE_SCHEMA_CACHE:                           "EXTENDED_RIGHT_UPDATE_SCHEMA_CACHE",
	EXTENDED_RIGHT_USER_CHANGE_PASSWORD:                          "EXTENDED_RIGHT_USER_CHANGE_PASSWORD",
	EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD:                    "EXTENDED_RIGHT_USER_FORCE_CHANGE_PASSWORD",
	EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER:                    "EXTENDED_RIGHT_DS_CLONE_DOMAIN_CONTROLLER",
	EXTENDED_RIGHT_DS_READ_PARTITION_SECRETS:                     "EXTENDED_RIGHT_DS_READ_PARTITION_SECRETS",
	EXTENDED_RIGHT_DS_WRITE_PARTITION_SECRETS:                    "EXTENDED_RIGHT_DS_WRITE_PARTITION_SECRETS",
	EXTENDED_RIGHT_DS_SET_OWNER:                                  "EXTENDED_RIGHT_DS_SET_OWNER",
	EXTENDED_RIGHT_DS_BYPASS_QUOTA:                               "EXTENDED_RIGHT_DS_BYPASS_QUOTA",
	EXTENDED_RIGHT_DS_VALIDATED_WRITE_COMPUTER:                   "EXTENDED_RIGHT_DS_VALIDATED_WRITE_COMPUTER",
}