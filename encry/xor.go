package encry

import (
	"strconv"
)

var XorKey = []byte{0x13, 0x54, 077, 0x1A, 0xA1, 0x3F, 0x04, 0x8B}

func E(src string) string {
	var result string
	j := 0
	s := ""
	bt := []rune(src)
	for i := 0; i < len(bt); i++ {
		s = strconv.FormatInt(int64(byte(bt[i])^XorKey[j]), 16)
		if len(s) == 1 {
			s = "0" + s
		}
		result = result + (s)
		j = (j + 1) % 8
	}
	return result
}

func D(src string) string {
	var result string
	var s int64
	j := 0
	bt := []rune(src)
	for i := 0; i < len(src)/2; i++ {
		s, _ = strconv.ParseInt(string(bt[i*2:i*2+2]), 16, 0)
		result = result + string(byte(s)^XorKey[j])
		j = (j + 1) % 8
	}
	return result
}

func DD(src string) string {
	xor_shellcode := []byte(src)
	var shellcode []byte
	for i := 0; i < len(xor_shellcode); i++ {
		shellcode = append(shellcode, xor_shellcode[i]^XorKey[1]^XorKey[2])
	}
	return string(shellcode)
}

func EE(src string) string {
	shellcode := []byte(src)
	var xor_shellcode []byte
	for i := 0; i < len(shellcode); i++ {
		xor_shellcode = append(xor_shellcode, shellcode[i]^XorKey[2]^XorKey[1])
	}
	return string(xor_shellcode)
}
