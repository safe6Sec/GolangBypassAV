package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Printf("Must have shellcode of file\n")
		os.Exit(1)
	}

	sc, err := ioutil.ReadFile(os.Args[1])
	if os.IsNotExist(err) {
		sc, err = hex.DecodeString(os.Args[1])
		if err != nil {
			fmt.Printf("Error decoding arg 1: %s\n", err)
			os.Exit(1)
		}
	}
	fmt.Println(sc)
	//shellcode.Run(sc)
}
