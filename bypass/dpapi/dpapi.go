package main

import (
	"encoding/base64"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

type cryptProtect uint32

const (
	cryptProtectUIForbidden  cryptProtect = 0x1
	cryptProtectLocalMachine cryptProtect = 0x4

	CRYPTPROTECTMEMORY_SAME_PROCESS  = 0x00
	CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x01
	CRYPTPROTECTMEMORY_SAME_LOGON    = 0x02
)

var (
	dllcrypt32 = windows.NewLazySystemDLL("Crypt32.dll")

	procEncryptData          = dllcrypt32.NewProc("CryptProtectData")
	procDecryptData          = dllcrypt32.NewProc("CryptUnprotectData")
	procCryptProtectMemory   = dllcrypt32.NewProc("CryptProtectMemory")
	procCryptUnprotectMemory = dllcrypt32.NewProc("CryptUnprotectMemory ")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

func EncryptMemory1() {
	_, _, err := procCryptProtectMemory.Call(uintptr(0), uintptr(1), uintptr(CRYPTPROTECTMEMORY_SAME_PROCESS))
	if err != nil {
		panic(err)
	}
}

func EncryptMemory(addr interface{}, size int) {

	_, _, err := procCryptProtectMemory.Call(uintptr(unsafe.Pointer(&addr)), uintptr(size), uintptr(CRYPTPROTECTMEMORY_SAME_PROCESS))
	if err != nil {
		panic(err)
	}

}

func DecryptMemory(addr *interface{}, size int) {
	_, _, err := procCryptUnprotectMemory.Call(uintptr(unsafe.Pointer(addr)), uintptr(size), CRYPTPROTECTMEMORY_SAME_PROCESS)
	if err != nil {
		panic(err)
	}
}

func (b *dataBlob) toByteArray() []byte {
	d := make([]byte, b.cbData)
	/* #nosec# G103 */
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

func (b *dataBlob) zeroMemory() {
	zeros := make([]byte, b.cbData)
	/* #nosec# G103 */
	copy((*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:], zeros)
}

func (b *dataBlob) free() error {
	/* #nosec# G103 */
	_, err := windows.LocalFree(windows.Handle(unsafe.Pointer(b.pbData)))
	if err != nil {
		return errors.Wrap(err, "localfree")
	}

	return nil
}

// Encrypt a string value to a base64 string
func Encrypt(secret string) (string, error) {
	return encrypt(secret, "", cryptProtectUIForbidden)
}

func EncryptEntropy(secret, entropy string) (string, error) {
	return encrypt(secret, entropy, cryptProtectUIForbidden)
}

func encrypt(secret, entropy string, cf cryptProtect) (string, error) {
	var result string
	var b []byte
	b, err := encryptBytes([]byte(secret), []byte(entropy), cf)
	if err != nil {
		return result, errors.Wrap(err, "encryptbytes")
	}
	result = base64.StdEncoding.EncodeToString(b)
	return result, nil
}

// EncryptBytes encrypts a byte array and returns a byte array
func EncryptBytes(data []byte) ([]byte, error) {
	return encryptBytes(data, nil, cryptProtectUIForbidden)
}

func EncryptBytesEntropy(data, entropy []byte) ([]byte, error) {
	return encryptBytes(data, entropy, cryptProtectUIForbidden)
}

func encryptBytes(data []byte, entropy []byte, cf cryptProtect) ([]byte, error) {
	var (
		outblob dataBlob
		r       uintptr
		err     error
	)

	if len(entropy) > 0 {
		/* #nosec# G103 */
		r, _, err = procEncryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	} else {
		/* #nosec# G103 */
		r, _, err = procEncryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	}
	if r == 0 {
		return nil, errors.Wrap(err, "procencryptdata")
	}

	enc := outblob.toByteArray()
	return enc, outblob.free()
}

// EncryptBytesMachineLocal encrypts a byte array and returns a byte array and associates the data
// encrypted with the current computer instead of with an individual user.
func EncryptBytesMachineLocal(data []byte) ([]byte, error) {
	return encryptBytes(data, nil, cryptProtectUIForbidden|cryptProtectLocalMachine)
}

func EncryptBytesMachineLocalEntropy(data, entropy []byte) ([]byte, error) {
	return encryptBytes(data, entropy, cryptProtectUIForbidden|cryptProtectLocalMachine)
}

// EncryptMachineLocal a string value to a base64 string and associates the data encrypted with the
// current computer instead of with an individual user.
func EncryptMachineLocal(secret string) (string, error) {
	return encrypt(secret, "", cryptProtectUIForbidden|cryptProtectLocalMachine)
}

func EncryptMachineLocalEntropy(secret, entropy string) (string, error) {
	return encrypt(secret, entropy, cryptProtectUIForbidden|cryptProtectLocalMachine)
}

// DecryptBytes decrypts a byte array returning a byte array
func decryptBytes(data, entropy []byte, cf cryptProtect) ([]byte, error) {
	var (
		outblob dataBlob
		r       uintptr
		err     error
	)
	if len(entropy) > 0 {
		/* #nosec# G103 */
		r, _, err = procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, uintptr(unsafe.Pointer(newBlob(entropy))), 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	} else {
		/* #nosec# G103 */
		r, _, err = procDecryptData.Call(uintptr(unsafe.Pointer(newBlob(data))), 0, 0, 0, 0, uintptr(cf), uintptr(unsafe.Pointer(&outblob)))
	}
	if r == 0 {
		return nil, errors.Wrap(err, "procdecryptdata")
	}

	dec := outblob.toByteArray()
	outblob.zeroMemory()
	return dec, outblob.free()
}

// Decrypt a string to a string
func Decrypt(data string) (string, error) {
	return DecryptEntropy(data, "")
}

// EncryptBytes encrypts a byte array and returns a byte array
func DecryptBytes(data []byte) ([]byte, error) {
	return decryptBytes(data, nil, cryptProtectUIForbidden)
}

func DecryptBytesEntropy(data, entropy []byte) ([]byte, error) {
	return decryptBytes(data, entropy, cryptProtectUIForbidden)
}

func DecryptEntropy(data, entropy string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", errors.Wrap(err, "decodestring")
	}

	b, err := decryptBytes(raw, []byte(entropy), cryptProtectUIForbidden)
	if err != nil {
		return "", errors.Wrap(err, "decryptbytes")
	}
	return string(b), nil
}
