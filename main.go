package main

import (
	"GolangBypassAV/shellcode"
	"io/ioutil"
	"os"
)

func main() {

	if len(os.Args) != 2 {
		os.Exit(1)
	}
	sc, _ := ioutil.ReadFile(os.Args[1])
	shellcode.Run(sc)
}
