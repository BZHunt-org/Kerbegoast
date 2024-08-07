package lsa

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	secur32    = windows.NewLazySystemDLL("Secur32.dll")
	advapi32   = windows.NewLazySystemDLL("Advapi32.dll")
	kernel32   = windows.NewLazySystemDLL("Kernel32.dll")
	ntdll      = windows.NewLazySystemDLL("ntdll.dll")
	libcrypt32 = windows.NewLazySystemDLL("crypt32.dll")

	procLsaEnumerateLogonSessions      = secur32.NewProc("LsaEnumerateLogonSessions")
	procLsaGetLogonSessionData         = secur32.NewProc("LsaGetLogonSessionData")
	procLsaFreeReturnBuffer            = secur32.NewProc("LsaFreeReturnBuffer")
	procLsaNtStatusToWinError          = advapi32.NewProc("LsaNtStatusToWinError")
	procLsaLookupAuthenticationPackage = secur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaCallAuthenticationPackage   = secur32.NewProc("LsaCallAuthenticationPackage") 
	procCopyMemory                     = ntdll.NewProc("RtlCopyMemory")
	procMoveMemory                     = ntdll.NewProc("RtlMoveMemory")
	procVirtualAlloc                   = kernel32.NewProc("VirtualAlloc")
	procCryptBinaryToStringA           = libcrypt32.NewProc("CryptBinaryToStringA")
	procGlobalAlloc                    = kernel32.NewProc("GlobalAlloc")
	procHeapAlloc                 	   = kernel32.NewProc("HeapAlloc")
	procHeapFree                       = kernel32.NewProc("HeapFree")
	procGetProcessHeap                 = kernel32.NewProc("GetProcessHeap")
)

const (
	STATUS_SUCCESS = uint32(windows.STATUS_SUCCESS)
	// MEM_COMMIT is a Windows constant used with Windows API calls
	MEM_COMMIT = 0x1000
	// MEM_RESERVE is a Windows constant used with Windows API calls
	MEM_RESERVE = 0x2000
	// PAGE_EXECUTE_READ is a Windows constant used with Windows API calls
	PAGE_EXECUTE_READ = 0x20
	// PAGE_READWRITE is a Windows constant used with Windows API calls
	PAGE_READWRITE      = 0x04
	CRYPT_STRING_BASE64 = 0x00000001
)

func LsaEnumerateLogonSessions(sessionCount *uint32, sessions *uintptr) error {
	r0, _, _ := syscall.Syscall(procLsaEnumerateLogonSessions.Addr(), 2, uintptr(unsafe.Pointer(sessionCount)), uintptr(unsafe.Pointer(sessions)), 0)
	return LsaNtStatusToWinError(r0)
}
func LsaGetLogonSessionData(luid *windows.LUID, sessionData **SECURITY_LOGON_SESSION_DATA) error {
	r0, _, _ := syscall.Syscall(procLsaGetLogonSessionData.Addr(), 2, uintptr(unsafe.Pointer(luid)), uintptr(unsafe.Pointer(sessionData)), 0)
	return LsaNtStatusToWinError(r0)
}
func LsaFreeReturnBuffer(buffer uintptr) error {
	r0, _, _ := syscall.Syscall(procLsaFreeReturnBuffer.Addr(), 1, buffer, 0, 0)
	return LsaNtStatusToWinError(r0)
}

func LsaLookupAuthenticationPackage(lsaHandle syscall.Handle, packageName *LSA_STRING, authenticationPackage *uint32) error {
	r0, _, _ := syscall.Syscall(procLsaLookupAuthenticationPackage.Addr(), 3, uintptr(lsaHandle), uintptr(unsafe.Pointer(packageName)), uintptr(unsafe.Pointer(authenticationPackage)))
	if uint32(r0) == STATUS_SUCCESS {
		fmt.Println("[*] OK LOOKUP")
	}
	return LsaNtStatusToWinError(r0)
}


func HeapAlloc(hHeap uintptr, dwFlags uint32, dwBytes uintptr) (uintptr, error) {
	r1, _, e1 := procHeapAlloc.Call(hHeap, uintptr(dwFlags), dwBytes)
	if r1 == 0 {
		return 0, e1
	}
	return r1, nil
}

func HeapFree(hHeap uintptr, dwFlags uint32, lpMem uintptr) error {
	r1, _, e1 := procHeapFree.Call(hHeap, uintptr(dwFlags), lpMem)
	if r1 == 0 {
		return e1
	}
	return nil
}

func GetProcessHeap() uintptr {
	r1, _, _ := procGetProcessHeap.Call()
	return r1
}


func CopyMemory(dst uintptr, src uintptr, length uintptr) error {
	r0, _, r2 := procCopyMemory.Call(dst, src, length)
	if uint32(r0) == STATUS_SUCCESS {
		fmt.Printf("[*] OK COPY SYSCALL RETURN %x  |  ERNO %q\n", r0, r2)
	} else {
		fmt.Printf("[X] NOK COPY SYSCALL RETURN %x  |  ERNO %q\n", r0, r2)
	}
	return LsaNtStatusToWinError(r0)
}

func MoveMemory(destination, source uintptr, length uintptr) error {
	_, _, err := procMoveMemory.Call(destination, source, length)
	if err != nil && err.Error() != "The operation completed successfully." {
		return err
	}
	return nil
}
func ExportCall() func(a ...uintptr) (r1 uintptr, r2 uintptr, lastErr error) {
	return procLsaCallAuthenticationPackage.Call
}
func VirtualAlloc(dwSize int) (addr uintptr, err error) {
	ret, _, err := procVirtualAlloc.Call(
		uintptr(0),      // The starting address of the region to allocate
		uintptr(dwSize), // The size of the region of memory to allocate, in bytes.
		MEM_RESERVE|MEM_COMMIT,
		PAGE_READWRITE)
	if int(ret) == 0 {
		return ret, err
	}
	return ret, nil
}

func GlobalAlloc(uFlags uint32, dwBytes uintptr) (uintptr, error) {
	ret, _, err := procGlobalAlloc.Call(uintptr(uFlags), dwBytes)
	if ret == 0 {
		return ret, err
	}
	return ret, nil
}

func CryptBinaryToStringA(data *uint8, size int) (a string, err error) {
	var size2 uint32
	r0, _, r2 := procCryptBinaryToStringA.Call(
		uintptr(unsafe.Pointer(data)),
		uintptr(size),
		uintptr(CRYPT_STRING_BASE64),
		0,
		uintptr(unsafe.Pointer(&size2)),
	)
	if uint32(r0) == STATUS_SUCCESS {
		fmt.Printf("[*] OK CryptBinaryToStringA  SYSCALL RETURN %x  |  ERNO %q\n", r0, r2)
	} else {
		fmt.Printf("[X] NOK CryptBinaryToStringA SYSCALL RETURN %x  |  ERNO %q\n", r0, r2)
	}
	return "", r2
}

func LsaCallAuthenticationPackage(lsaHandle syscall.Handle, authenticationPackage uint32, protocolSubmitBuffer uintptr, submitBufferLength uint32, protocolReturnBuffer *uintptr, returnBufferLength **uint32, pNTSTATUS *windows.NTStatus) (error, uint32) {
	r0, _, _ := syscall.Syscall9(procLsaCallAuthenticationPackage.Addr(), 7, uintptr(lsaHandle), uintptr(authenticationPackage), protocolSubmitBuffer, uintptr(submitBufferLength), uintptr(unsafe.Pointer(protocolReturnBuffer)), uintptr(unsafe.Pointer(returnBufferLength)), uintptr(unsafe.Pointer(pNTSTATUS)), 0, 0)
	if uint32(r0) != STATUS_SUCCESS {
		fmt.Printf("[X] NOK CALL LsaCallAuthenticationPackage  RETURN %x | %q  |  NTSTATUS :%q\n", r0, GetError(r0), pNTSTATUS)

	} 
	return LsaNtStatusToWinError(r0), uint32(r0)
}

func LsaCallAuthenticationPackage2(lsaHandle syscall.Handle, authenticationPackage uint32, protocolSubmitBuffer *byte, submitBufferLength uint32, protocolReturnBuffer *uintptr, returnBufferLength *uint32, pNTSTATUS *windows.NTStatus) (error, uint32) {
	r0, r1, r2 := syscall.Syscall9(procLsaCallAuthenticationPackage.Addr(), 7, uintptr(lsaHandle), uintptr(authenticationPackage), uintptr(unsafe.Pointer(protocolSubmitBuffer)), uintptr(submitBufferLength), uintptr(unsafe.Pointer(protocolReturnBuffer)), uintptr(unsafe.Pointer(returnBufferLength)), uintptr(unsafe.Pointer(pNTSTATUS)), 0, 0)
	if uint32(r0) == STATUS_SUCCESS {
		fmt.Printf("[*] OK CALL SYSCALL RETURN %x  |  NTSTATUS :%q\n", r0, pNTSTATUS)
		fmt.Println(r0, r1, r2)
	} else {
		fmt.Printf("[X] NOK CALL LsaCallAuthenticationPackage  RETURN %x | %q  |  NTSTATUS :%q\n", r0, GetError(r0), pNTSTATUS)
	}
	return LsaNtStatusToWinError(r0), uint32(r0)
}

func LsaNtStatusToWinError(ntstatus uintptr) error {
	r0, _, errno := syscall.Syscall(procLsaNtStatusToWinError.Addr(), 1, ntstatus, 0, 0)
	switch errno {
	case windows.ERROR_SUCCESS:
		if r0 == 0 {
			return nil
		}
	case windows.ERROR_MR_MID_NOT_FOUND:
		return fmt.Errorf("Unknown LSA NTSTATUS code %x", ntstatus)
	}
	return syscall.Errno(r0)
}

func GetError(errCode uintptr) string {
	err := syscall.Errno(errCode)
	return err.Error()
}
