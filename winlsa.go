package winlsa

import (
	"fmt"
	"reflect"
	//"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/carlpett/winlsa/internal/lsa"
)

// A LUID is a locally unique identifier guaranteed to be unique on the
// operating system that generated it until the system is restarted.
//
// In the context of winlsa, it is a session identifier.
type LUID = windows.LUID

type LogonType uint32

func (lt LogonType) String() string {
	switch lt {
	case LogonTypeSystem:
		return "System"
	case LogonTypeInteractive:
		return "Interactive"
	case LogonTypeNetwork:
		return "Network"
	case LogonTypeBatch:
		return "Batch"
	case LogonTypeService:
		return "Service"
	case LogonTypeProxy:
		return "Proxy"
	case LogonTypeUnlock:
		return "Unlock"
	case LogonTypeNetworkCleartext:
		return "NetworkCleartext"
	case LogonTypeNewCredentials:
		return "NewCredentials"
	case LogonTypeRemoteInteractive:
		return "RemoteInteractive"
	case LogonTypeCachedInteractive:
		return "CachedInteractive"
	case LogonTypeCachedRemoteInteractive:
		return "CachedRemoteInteractive"
	case LogonTypeCachedUnlock:
		return "CachedUnlock"
	default:
		return fmt.Sprintf("Undefined LogonType(%d)", lt)
	}
}

const (
	// Not explicitly defined in LSA, but according to
	// https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession,
	// LogonType=0 is "Used only by the System account."
	LogonTypeSystem LogonType = iota
	_ // LogonType=1 is not used
	LogonTypeInteractive
	LogonTypeNetwork
	LogonTypeBatch
	LogonTypeService
	LogonTypeProxy
	LogonTypeUnlock
	LogonTypeNetworkCleartext
	LogonTypeNewCredentials
	LogonTypeRemoteInteractive
	LogonTypeCachedInteractive
	LogonTypeCachedRemoteInteractive
	LogonTypeCachedUnlock
)

type LogonSessionData struct {
	UserName                                   string
	LogonDomain                                string
	AuthenticationPackage                      string
	LogonId 								   windows.LUID
	LogonType                                  LogonType
	Session                                    uint32
	Sid                                        *windows.SID
	LogonTime                                  time.Time
	LogonServer                                string
	DnsDomainName                              string
	Upn                                        string
	UserFlags                                  uint32
	LastSuccessfulLogon                        time.Time
	LastFailedLogon                            time.Time
	FailedAttemptCountSinceLastSuccessfulLogon uint32
	LogonScript                                string
	ProfilePath                                string
	HomeDirectory                              string
	HomeDirectoryDrive                         string
	LogoffTime                                 time.Time
	KickOffTime                                time.Time
	PasswordLastSet                            time.Time
	PasswordCanChange                          time.Time
	PasswordMustChange                         time.Time
}

func newLogonSessionData(data *lsa.SECURITY_LOGON_SESSION_DATA) *LogonSessionData {
	var sid *windows.SID
	if data.Sid != nil {
		sid, _ = data.Sid.Copy()
	}
	return &LogonSessionData{
		UserName:              data.UserName.String(),
		LogonDomain:           data.LogonDomain.String(),
		AuthenticationPackage: data.AuthenticationPackage.String(),
		LogonType:             LogonType(data.LogonType),
		Session:               data.Session,
		Sid:                   sid,
		LogonId: 			   data.LogonId,
		LogonTime:             timeFromUint64(data.LogonTime),
		LogonServer:           data.LogonServer.String(),
		DnsDomainName:         data.DnsDomainName.String(),
		Upn:                   data.Upn.String(),
		UserFlags:             data.UserFlags,
		LogonScript:           data.LogonScript.String(),
		ProfilePath:           data.ProfilePath.String(),
		HomeDirectory:         data.HomeDirectory.String(),
		HomeDirectoryDrive:    data.HomeDirectoryDrive.String(),
		LogoffTime:            timeFromUint64(data.LogoffTime),
		KickOffTime:           timeFromUint64(data.KickOffTime),
		PasswordLastSet:       timeFromUint64(data.PasswordLastSet),
		PasswordCanChange:     timeFromUint64(data.PasswordCanChange),
		PasswordMustChange:    timeFromUint64(data.PasswordMustChange),
		LastSuccessfulLogon:   timeFromUint64(data.LastLogonInfo.LastSuccessfulLogon),
		LastFailedLogon:       timeFromUint64(data.LastLogonInfo.LastFailedLogon),
		FailedAttemptCountSinceLastSuccessfulLogon: data.LastLogonInfo.FailedAttemptCountSinceLastSuccessfulLogon,
	}
}


func timeFromUint64(nsec uint64) time.Time {
	if nsec == 0 || nsec == ^uint64(0)>>1 {
		return time.Time{}
	}
	const windowsEpoch = 116444736000000000
	return time.Unix(0, int64(nsec-windowsEpoch)*100)
}

func GetLogonSessions() ([]LUID, error) {
	var cnt uint32
	var buffer uintptr
	err := lsa.LsaEnumerateLogonSessions(&cnt, &buffer)
	if err != nil {
		return nil, err
	}

	var data []LUID
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	sh.Data = buffer
	sh.Len = int(cnt)
	sh.Cap = int(cnt)
	luids := make([]LUID, cnt)
	for idx := uint32(0); idx < cnt; idx++ {
		luids[idx] = data[idx]
	}

	err = lsa.LsaFreeReturnBuffer(buffer)
	if err != nil {
		return nil, err
	}
	return luids, nil
}
func GetLogonSessionData(luid *windows.LUID) (*LogonSessionData, error) {
	var dataBuffer *lsa.SECURITY_LOGON_SESSION_DATA
	err := lsa.LsaGetLogonSessionData(luid, &dataBuffer)
	if err != nil {
		return nil, err
	}
	sessionData := newLogonSessionData(dataBuffer)

	err = lsa.LsaFreeReturnBuffer(uintptr(unsafe.Pointer(dataBuffer)))
	if err != nil {
		return nil, err
	}

	return sessionData, nil
}
