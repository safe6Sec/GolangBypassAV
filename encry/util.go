package encry

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"
)

func Convert(data string) []byte {
	shellcodeHex, _ := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(data, "\n", ""), "\\x", ""))
	return shellcodeHex
}

func Parse(data string) string {
	var result string

	isArr := strings.Contains(data, ",")
	if isArr {
		context := strings.Split(data, ",")
		size := len(context)
		dataArr := make([]byte, size)
		for i, v := range context {
			val, _ := strconv.Atoi(v)
			dataArr[i] = byte(val)
		}

		result = hex.EncodeToString([]byte(dataArr))
		fmt.Println(result)
	} else {
		val, _ := strconv.Atoi(data)
		data := make([]byte, 1)
		data[0] = byte(val)
		result = hex.EncodeToString([]byte(data))
		fmt.Println(result)
	}

	return result
}

func ReadFile(data string) []byte {
	b, err := ioutil.ReadFile(data) // just pass the file name
	if err != nil {
		fmt.Print(err)
	}
	return b

}
