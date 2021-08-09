package encry

import (
	"strconv"
)

var XorKey []byte = []byte{0x12, 0x34, 0x67, 0x6A, 0xA1, 0xFF, 0x04, 0x7B}

type Xor struct {
}

type m interface {
	e(src string) string
	d(src string) string
}

func (a *Xor) e(src string) string {
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

func (a *Xor) D(src string) string {
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
