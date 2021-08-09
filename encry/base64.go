package encry

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func GetShellCode(data string) []byte {
	shellCodeB64, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		fmt.Printf("[!]Error b64decoding string : %s ", err.Error())
		os.Exit(1)
	}
	shellcodeHex, _ := hex.DecodeString(strings.ReplaceAll(strings.ReplaceAll(string(shellCodeB64), "\n", ""), "\\x", ""))
	return shellcodeHex
}

func GetBase64Data(data []byte) string {
	bdata := base64.StdEncoding.EncodeToString(data)
	return bdata
}
