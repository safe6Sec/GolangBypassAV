package sandbox

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

var (
	kernel322                = syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot = kernel322.NewProc("CreateToolhelp32Snapshot")
	Process32First           = kernel322.NewProc("Process32FirstW")
	Process32Next            = kernel322.NewProc("Process32NextW")
	CloseHandle              = kernel322.NewProc("CloseHandle")
)

var (
	//在此处添加沙箱常见用户名
	userNames = []string{
		"John", "Phil",
	}
	//在此处添加沙箱常见主机名
	hostNames = []string{
		"John", "Jason",
	}
)

func checkUserName(param interface{}) (code int) {
	username, err := user.Current()
	if err != nil {
		return 1
	}
	names, ok := param.([]string)
	if !ok {
		//fmt.Println("user names must be []string")
		return 1
	}
	for _, name := range names {
		if strings.Contains(strings.ToLower(username.Username), strings.ToLower(name)) {
			return 0
		}
	}
	//fmt.Printf("1.UserName OK!\n")
	return -1
}

func checkDebugger(param interface{}) (code int) {
	var kernel32, _ = syscall.LoadLibrary("kernel32.dll")
	var IsDebuggerPresent, _ = syscall.GetProcAddress(kernel32, "IsDebuggerPresent")
	var nargs uintptr = 0

	if debuggerPresent, _, err := syscall.Syscall(uintptr(IsDebuggerPresent), nargs, 0, 0, 0); err != 0 {
		//fmt.Printf("Error determining whether debugger present.\n")
	} else {
		if debuggerPresent != 0 {
			return 0
		}
	}
	//fmt.Printf("2.Debugger OK!\n")
	return -1
}

func checkFileName(param interface{}) (code int) {
	length, ok := param.(int)
	if !ok {
		//fmt.Println("the length of filename must be integer")
		return 1
	}
	actualName := filepath.Base(os.Args[0])
	if len(actualName) >= length {
		return 0
	}
	//fmt.Printf("3.FileName OK!\n")
	return -1
}

func checkProcessNum(param interface{}) (code int) {
	minRunningProcesses, ok := param.(int)
	if !ok {
		//fmt.Println("the number of process must be integer")
		return 1
	}
	hProcessSnap, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
	if hProcessSnap < 0 {
		return -1
	}
	defer CloseHandle.Call(hProcessSnap)

	exeNames := make([]string, 0, 100)
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	Process32First.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))

	for {

		exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

		retVal, _, _ := Process32Next.Call(hProcessSnap, uintptr(unsafe.Pointer(&pe32)))
		if retVal == 0 {
			break
		}

	}
	runningProcesses := 0
	for range exeNames {
		runningProcesses += 1
	}

	if runningProcesses < minRunningProcesses {
		return 0
	}
	//fmt.Printf("4.ProcessNum OK!\n")
	return -1
}

func checkDiskSize(param interface{}) (code int) {
	minDiskSizeGB, ok := param.(float32)
	if !ok {
		//fmt.Println("the size of disk must be float32")
		return 1
	}
	//var kernel323 = syscall.NewLazyDLL("kernel32.dll")
	var (
		getDiskFreeSpaceEx                                                   = kernel322.NewProc("GetDiskFreeSpaceExW")
		lpFreeBytesAvailable, lpTotalNumberOfBytes, lpTotalNumberOfFreeBytes int64
	)

	getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:"))),
		uintptr(unsafe.Pointer(&lpFreeBytesAvailable)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
		uintptr(unsafe.Pointer(&lpTotalNumberOfFreeBytes)))

	diskSizeGB := float32(lpTotalNumberOfBytes) / 1073741824
	//fmt.Println(diskSizeGB)
	if diskSizeGB < minDiskSizeGB {
		return 0
	}
	//fmt.Printf("5.DiskSize OK!\n")
	return -1
}
func checkHostName(param interface{}) (code int) {
	hosts, ok := param.([]string)
	if !ok {
		//fmt.Println("slice of hostname must be []string")
		return 1
	}
	hostname, errorout := os.Hostname()
	if errorout != nil {
		os.Exit(1)
	}
	for _, host := range hosts {
		if strings.Contains(strings.ToLower(hostname), strings.ToLower(host)) {
			return 0
		}
	}
	//fmt.Printf("7.HostName OK!\n")
	return -1
}

func checkBlacklist(param interface{}) (code int) {
	EvidenceOfSandbox := make([]string, 0)
	//在此处添加进程黑名单
	sandboxProcesses := [...]string{`sysdiag`, `sysdiag-gui`, `usysdiag`, `Dbgview`}
	hProcessSnap1, _, _ := CreateToolhelp32Snapshot.Call(2, 0)
	if hProcessSnap1 < 0 {
		return -1
	}
	defer CloseHandle.Call(hProcessSnap1)

	exeNames := make([]string, 0, 100)
	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))

	Process32First.Call(hProcessSnap1, uintptr(unsafe.Pointer(&pe32)))

	for {

		exeNames = append(exeNames, syscall.UTF16ToString(pe32.szExeFile[:260]))

		retVal, _, _ := Process32Next.Call(hProcessSnap1, uintptr(unsafe.Pointer(&pe32)))
		if retVal == 0 {
			break
		}

	}

	for _, exe := range exeNames {
		for _, sandboxProc := range sandboxProcesses {
			if strings.Contains(strings.ToLower(exe), strings.ToLower(sandboxProc)) {
				EvidenceOfSandbox = append(EvidenceOfSandbox, exe)
			}
		}
	}

	if len(EvidenceOfSandbox) != 0 {
		return 0
	}
	//fmt.Printf("6.Blacklist OK!\n")
	return -1
}

func exec1(fn func(interface{}) int, param interface{}) {
	if code := fn(param); code >= 0 {
		os.Exit(code)
	}
}

func Check() {
	//反沙箱(选用)
	//检测用户名
	exec1(checkUserName, userNames)
	//判断hostname是否为黑名单
	exec1(checkHostName, hostNames)
	//检测进程数量是否大于后面输入的数
	exec1(checkProcessNum, 50)
	//检测系统盘是否大于后面输入的数
	exec1(checkDiskSize, float32(60))
	//检测调试器
	exec1(checkDebugger, nil)
	//检测文件名长度是否大于后面输入的数
	exec1(checkFileName, 12)
	//判断进程名是否为黑名单
	exec1(checkBlacklist, nil)
}
