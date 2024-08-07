package lsa

import (
	"golang.org/x/sys/windows"
)

type LUID struct {
	lowPart  uint32
	highPart int32
}

type LSA_LAST_INTER_LOGON_INFO struct {
	LastSuccessfulLogon                        uint64
	LastFailedLogon                            uint64
	FailedAttemptCountSinceLastSuccessfulLogon uint32
}

type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               windows.LUID
	UserName              UnicodeString
	LogonDomain           UnicodeString
	AuthenticationPackage UnicodeString
	LogonType             uint32
	Session               uint32
	Sid                   *windows.SID
	LogonTime             uint64
	LogonServer           UnicodeString
	DnsDomainName         UnicodeString
	Upn                   UnicodeString
	UserFlags             uint32
	LastLogonInfo         LSA_LAST_INTER_LOGON_INFO
	LogonScript           UnicodeString
	ProfilePath           UnicodeString
	HomeDirectory         UnicodeString
	HomeDirectoryDrive    UnicodeString
	LogoffTime            uint64
	KickOffTime           uint64
	PasswordLastSet       uint64
	PasswordCanChange     uint64
	PasswordMustChange    uint64
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}


type LSA_UNICODE_STRING2 struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LSA_UNICODE_STRING3 struct {
	Length        uint16
	MaximumLength uint16
	Buffer        []uint16
}

type LSA_STRING struct {
	Length        int16
	MaximumLength int16
	Buffer        *byte
}

type KERB_QUERY_TKT_CACHE_RESPONSE struct {
	MessageType	   KERB_PROTOCOL_MESSAGE_TYPE	
	CountOfTickets uint32
	Tickets        []uintptr
}


type KERB_QUERY_TKT_CACHE_REQUEST struct {
	MessageType KERB_PROTOCOL_MESSAGE_TYPE
	LogonId     windows.LUID
}

type KERB_TICKET_CACHE_INFO struct {
	ClientName     UnicodeString
	RealmName      UnicodeString
	ServerName     UnicodeString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

type KERB_TICKET_CACHE_INFO_EX struct {
	ClientName     UnicodeString
	ClientRealm    UnicodeString
	ServerName     UnicodeString
	ServerRealm    UnicodeString
	StartTime      int64
	EndTime        int64
	RenewTime      int64
	EncryptionType int32
	TicketFlags    uint32
}

type KERB_TICKET_CACHE_INFO_EX2 struct {
	ClientName     int
	ClientRealm    int
	ServerName     int
	ServerRealm    int
	StartTime      int
	EndTime        int
	RenewTime      int
	EncryptionType int
	TicketFlags    int
	SessionKeyType int
	BranchId       int
}

type KERB_TICKET_CACHE_INFO_EX3 struct {
	ClientName     int
	ClientRealm    int
	ServerName     int
	ServerRealm    int
	StartTime      int
	EndTime        int
	RenewTime      int
	EncryptionType int
	TicketFlags    int
	SessionKeyType int
	BranchId       int
	CacheFlags     int
	KdcCalled      int
}

type KERB_QUERY_TKT_CACHE_EX_RESPONSE struct {
	MessageType    KERB_PROTOCOL_MESSAGE_TYPE
	CountOfTickets int
	Tickets        int
}

type KERB_QUERY_TKT_CACHE_EX2_RESPONSE struct {
	MessageType    KERB_PROTOCOL_MESSAGE_TYPE
	CountOfTickets int
	Tickets        int
}

type KERB_QUERY_TKT_CACHE_EX3_RESPONSE struct {
	MessageType    KERB_PROTOCOL_MESSAGE_TYPE
	CountOfTickets int
	Tickets        int
}

type SecHandle struct {
	DWLOWER uint
	DWUPPER uint
}

type KERB_RETRIEVE_TKT_REQUEST struct {
	MessageType       KERB_PROTOCOL_MESSAGE_TYPE // 4
	LogonId           windows.LUID // 8
	TargetName        UnicodeString // 16
	TicketFlags       uint32	// 4
	CacheOptions      uint32	// 4
	EncryptionType    int32	    // 4
	CredentialsHandle SecHandle  // 16
}
type KERB_RETRIEVE_TKT_REQUEST2 struct {
	MessageType       KERB_PROTOCOL_MESSAGE_TYPE // 4
	LogonId           windows.LUID // 8
	TargetName        uintptr // 16
	TicketFlags       uint32	// 4
	CacheOptions      uint32	// 4
	EncryptionType    int32	    // 4
	CredentialsHandle SecHandle  // 16
}


type KERB_RETRIEVE_TKT_RESPONSE struct {
	Ticket         KERB_EXTERNAL_TICKET
}

type KERB_EXTERNAL_TICKET struct {
	ServiceName         *KERB_EXTERNAL_NAME
	TargetName          *KERB_EXTERNAL_NAME
	ClientName          *KERB_EXTERNAL_NAME
	DomainName          UnicodeString
	TargetDomainName    UnicodeString
	AltTargetDomainName UnicodeString
	SessionKey          KERB_CRYPTO_KEY
	TicketFlags         uint32
	Flags               uint32
	KeyExpirationTime   int64
	StartTime           int64
	EndTime             int64
	RenewUntil          int64
	TimeSkew            int64
	EncodedTicketSize   uint32
	EncodedTicket       *byte
}

type KERB_EXTERNAL_NAME struct {
	NameType  int16
	NameCount uint16
	Names     [1]UnicodeString
}

type KERB_INTERNAL_NAME struct {
	NameType  uint16
	NameCount uint16
	Names     []UnicodeString // Use a slice instead of a fixed-size array
}

func (k *KERB_EXTERNAL_NAME) String() string {
	if k.NameCount == 0 {
		return ""
	}
	return k.Names[0].String()
}

type KERB_CRYPTO_KEY struct {
	KeyType uint32
	Length  uint32
	Key     [1]byte // Dynamically sized array of bytes
}


type KRB_CRED struct {
	Pvno    int
	MsgType int
	Tickets []Ticket
	EncPart EncryptedData
}

type PrincipalName struct {
	NameType   int      //NT_SRV_INST dans l'exemple C#
	NameString []string // liste de strings qui correspond aux parties du nom du service
}

//EncryptedData représente les données chiffrées dans un ticket Kerberos.
type EncryptedData struct {
	Etype  int    // le type d'encryption
	Cipher []byte // les données chiffrées
}

//Ticket représente un ticket Kerberos.
type Ticket struct {
	TktVno  int            // le numéro de version du ticket
	Realm   string         // le domaine du ticket
	SName   PrincipalName  // le nom du service
	EncPart EncryptedData  // les données chiffrées
}


type UCHAR byte
type PUCHAR *UCHAR

type test struct {
	test2 int
	test3 string
}





type KERB_PROTOCOL_MESSAGE_TYPE uint32

const (
	KerbDebugRequestMessage                 KERB_PROTOCOL_MESSAGE_TYPE = 0
	KerbQueryTicketCacheMessage             KERB_PROTOCOL_MESSAGE_TYPE = 1
	KerbChangeMachinePasswordMessage        KERB_PROTOCOL_MESSAGE_TYPE = 2
	KerbVerifyPacMessage                    KERB_PROTOCOL_MESSAGE_TYPE = 3
	KerbRetrieveTicketMessage               KERB_PROTOCOL_MESSAGE_TYPE = 4
	KerbUpdateAddressesMessage              KERB_PROTOCOL_MESSAGE_TYPE = 5
	KerbPurgeTicketCacheMessage             KERB_PROTOCOL_MESSAGE_TYPE = 6
	KerbChangePasswordMessage               KERB_PROTOCOL_MESSAGE_TYPE = 7
	KerbRetrieveEncodedTicketMessage        KERB_PROTOCOL_MESSAGE_TYPE = 8
	KerbDecryptDataMessage                  KERB_PROTOCOL_MESSAGE_TYPE = 9
	KerbAddBindingCacheEntryMessage         KERB_PROTOCOL_MESSAGE_TYPE = 10
	KerbSetPasswordMessage                  KERB_PROTOCOL_MESSAGE_TYPE = 11
	KerbSetPasswordExMessage                KERB_PROTOCOL_MESSAGE_TYPE = 12
	KerbVerifyCredentialsMessage            KERB_PROTOCOL_MESSAGE_TYPE = 13
	KerbQueryTicketCacheExMessage           KERB_PROTOCOL_MESSAGE_TYPE = 14
	KerbPurgeTicketCacheExMessage           KERB_PROTOCOL_MESSAGE_TYPE = 15
	KerbRefreshSmartcardCredentialsMessage  KERB_PROTOCOL_MESSAGE_TYPE = 16
	KerbAddExtraCredentialsMessage          KERB_PROTOCOL_MESSAGE_TYPE = 17
	KerbQuerySupplementalCredentialsMessage KERB_PROTOCOL_MESSAGE_TYPE = 18
	KerbTransferCredentialsMessage          KERB_PROTOCOL_MESSAGE_TYPE = 19
	KerbQueryTicketCacheEx2Message          KERB_PROTOCOL_MESSAGE_TYPE = 20
	KerbSubmitTicketMessage                 KERB_PROTOCOL_MESSAGE_TYPE = 21
	KerbAddExtraCredentialsExMessage        KERB_PROTOCOL_MESSAGE_TYPE = 22
	KerbQueryKdcProxyCacheMessage           KERB_PROTOCOL_MESSAGE_TYPE = 23
	KerbPurgeKdcProxyCacheMessage           KERB_PROTOCOL_MESSAGE_TYPE = 24
	KerbQueryTicketCacheEx3Message          KERB_PROTOCOL_MESSAGE_TYPE = 25
	KerbCleanupMachinePkinitCredsMessage    KERB_PROTOCOL_MESSAGE_TYPE = 26
	KerbAddBindingCacheEntryExMessage       KERB_PROTOCOL_MESSAGE_TYPE = 27
	KerbQueryBindingCacheMessage            KERB_PROTOCOL_MESSAGE_TYPE = 28
	KerbPurgeBindingCacheMessage            KERB_PROTOCOL_MESSAGE_TYPE = 29
	KerbPinKdcMessage                       KERB_PROTOCOL_MESSAGE_TYPE = 30
	KerbUnpinAllKdcsMessage                 KERB_PROTOCOL_MESSAGE_TYPE = 31
	KerbQueryDomainExtendedPoliciesMessage  KERB_PROTOCOL_MESSAGE_TYPE = 32
	KerbQueryS4U2ProxyCacheMessage          KERB_PROTOCOL_MESSAGE_TYPE = 33
	KerbRetrieveKeyTabMessage               KERB_PROTOCOL_MESSAGE_TYPE = 34
)


