package lsa

import (
	"reflect"
	"unicode/utf16"
	"unsafe"

)

type UnicodeString struct { 
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func (u UnicodeString) String() string {
	var s []uint16
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(u.Buffer))
	hdr.Len = int(u.Length / 2)
	hdr.Cap = int(u.MaximumLength-2 / 2)
	return string(utf16.Decode(s))
}

func (u UnicodeString) GetInt16Slice() []uint16 {
	var s []uint16
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&s))
	hdr.Data = uintptr(unsafe.Pointer(u.Buffer))
	hdr.Len = int(u.Length)
	hdr.Cap = int(u.MaximumLength)
	return s
}

// NewUnicodeString converts its argument to UTF-16 and returns a
// pointer to a UnicodeString that can be used with various Windows
// Native API functions.
func NewUnicodeString(s string) *UnicodeString {
	buf := utf16.Encode([]rune(s))

	return &UnicodeString{
		Length:        uint16(2 * len(buf)),
		MaximumLength: uint16((2 * len(buf))+2),
		Buffer:        &buf[0],
	}
}

// NewEmptyUnicodeString initializes a UnicodeString for length UTF-16
// characters and returns it.
func NewEmptyUnicodeString(length int) *UnicodeString {
	buf := make([]uint16, length, length)
	return &UnicodeString{
		Length:        0,
		MaximumLength: uint16(2 * length)+2,
		Buffer:        &buf[0],
	}
}

// NewUnicodeStringFromBuffer initializes a UnicodeString from a
// pointer and a length value as returned by many NTDLL API calls.
func NewUnicodeStringFromBuffer(buffer *uint16, length int) *UnicodeString {
	return &UnicodeString{
		Length:        uint16(length),
		MaximumLength: uint16(length),
		Buffer:        buffer,
	}
}
