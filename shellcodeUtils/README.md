多功能shellcode工具

This application is used to transform shellcode binary files. The program depends that the input file is a binary file (.bin) that contains the hex bytes of the shellcode. ShellcodeUtils can just base64 encode your input file or it can XOR, RC4, or AES256-GCM encrypt it. The tools can also be used to decrypt files as well.

ShellcodeUtils help menu:

```text
  -base64
        Base64 encode the output. Can be used with or without encryption
  -i string
        Input file path of binary file
  -key string
        Encryption key
  -mode string
        Mode of operation to perform on the input file [encrypt,decrypt] (default "encrypt")
  -nonce string
        Nonce, in hex, used to decrypt an AES256 input file. Only used during decryption
  -o string
        Output file path
  -salt string
        Salt, in hex, used to generate an AES256 32-byte key through Argon2. Only used during decryption
  -type string
        The type of encryption to use [xor, aes256, rc4, null]
  -v    Enable verbose output
```

Example of only Base64 encoding the input file and saving it a text file:

```text
PS C:\Users\bob> .\ShellcodeUtils.exe -i C:\Users\bob\calc.bin -o C:\Users\bob\calc.b64.txt -base64 -v
[-]Output directory: C:\Users\bob\
[-]Output file name: calc.b64.txt
[-]File contents (hex): 505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3
[-]No encryption type provided, continuing on...
[+]Output (string):
UFFSU1ZXVWpgWmhjYWxjVFlIg+woZUiLMkiLdhhIi3YQSK1IizBIi34wA1c8i1wXKIt0HyBIAf6LVB8kD7csF41SAq2BPAdXaW5Fde+LdB8cSAH+izSuSAH3mf/XSIPEMF1fXltaWVjD
[+] encrypt input and wrote 140 bytes to: C:\Users\bob\calc.b64.txt
```

Example XOR encrypting input file with a key of `Sh3!1z` AND base64 encoding the output:

```text
PS C:\Users\bob> .\ShellcodeUtils.exe -i C:\Users\bob\calc.bin -o C:\Users\bob\calc.xor.b64.txt -mode encrypt -type xor -key Sh3!1z -v
[-]Output directory: C:\Users\bob\
[-]Output file name: calc.xor.b64.txt
[-]File contents (hex): 505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3
[-]XOR encrypting input file with key: Sh3!1z
[+]Output (hex):
03396172672d0602537b5919320450756832d0841b4479f16120b8572932d81e23699c32d8587baa4f4a503f0faa6d6d7be3473e11325296b8752e5e5cdf1f36bc2851c5b21d362d3a067654def127772f693084d85c9d69308dca97e469b2be63356c7f6a200a30f0
[+]xor encrypt input and wrote 105 bytes to: C:\Users\bob\calc.xor.b64.txt
```

Example AES256-GCM encrypting the input file with a password of `Sh3!1z` WITHOUT base64 encoding the ouput:

```text
PS C:\Users\bob> .\ShellcodeUtils.exe -i C:\Users\bob\calc.bin -o C:\Users\bob\calc.aes.bin -mode encrypt -type aes256 -key Sh3!1z -v
[-]Output directory: C:\Users\bob\
[-]Output file name: calc.aes.bin
[-]File contents (hex): 505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3
[-]AES256 encrypting input file
[+]Argon2 salt (hex): db6126d3ac640f8aaa67cda74b8cf1d2c54513db7bf4fbe3422d1b276af1367e
[+]AES256 key (32-bytes) derived from input password Sh3!1z (hex): 096a40f1aef38dd9b5d63284acc19727c4420dd98f21ea052112bef63eb7d94a
[+]AES256 nonce (hex): 13802153c4b2fb6a3e545ff4
[+]Output (hex):
44a974233e37b460dc2181b16846f265e8e3a07959abf9c8760f7d0ac8029575e67571ea5b313bc8b011739db57c690ec156a4b0bba4e4d632c35c1490aeaac24f5ae05e90934adf57798ee3c702a3c27073fe976fbcc6ee5db355da186c1add58913e41a8c5716a0fcfc27371f0cae906e50e680366496a00
[+]aes256 encrypt input and wrote 121 bytes to: C:\Users\bob\calc.aes.bin
```

AES256 requires a 32-byte key. This program uses the Argon2 ID algorithm to take the password provided with the `-key` input paramter to derive a 32-byte key while using a randomly generate salt. You will need the same input password and the salt used with the Argon2 algorithm and the same nonce used with the AES256 algorithm to successfull decrypt the file. Alternatively, the decryption function _could_ be updated to just use the 32-byte Argon2 key instead of the input password and salt.

>**NOTE:** It is up to the operator to decide to just use the generated Argon2 key or to use the password and salt that are used to generate the password.

Example AES256 decrypting the input file:

```text
PS C:\Users\bob> .\ShellcodeUtils.exe -i C:\Users\bob\calc.aes.bin -o C:\Users\bob\calc.aes.decrypted.bin -mode decrypt -type aes256 -key Sh3!1z -nonce 13802153c4b2fb6a3e545ff4 -salt db6126d3ac640f8aaa67cda74b8cf1d2c54513db7bf4fbe3422d1b276af1367e -v
[-]Output directory: C:\Users\bob\
[-]Output file name: calc.aes.decrypted.bin
[-]File contents (hex): 44a974233e37b460dc2181b16846f265e8e3a07959abf9c8760f7d0ac8029575e67571ea5b313bc8b011739db57c690ec156a4b0bba4e4d632c35c1490aeaac24f5ae05e90934adf57798ee3c702a3c27073fe976fbcc6ee5db355da186c1add58913e41a8c5716a0fcfc27371f0cae906e50e680366496a00
[-]AES256 decrypting input file
[-]Argon2 salt (hex): db6126d3ac640f8aaa67cda74b8cf1d2c54513db7bf4fbe3422d1b276af1367e
[-]AES256 key (hex): 096a40f1aef38dd9b5d63284acc19727c4420dd98f21ea052112bef63eb7d94a
[-]AES256 nonce (hex): 13802153c4b2fb6a3e545ff4
[+]Output (hex):
505152535657556a605a6863616c6354594883ec2865488b32488b7618488b761048ad488b30488b7e3003573c8b5c17288b741f204801fe8b541f240fb72c178d5202ad813c0757696e4575ef8b741f1c4801fe8b34ae4801f799ffd74883c4305d5f5e5b5a5958c3
[+]aes256 decrypt input and wrote 105 bytes to: C:\Users\bob\calc.aes.decrypted.bin
```

The application can be compiled with the following command on a Windows host from the project's root directory:

`set GOOS=windows GOARCH=amd64;go build -o ShellcodeUtils.exe .\cmd\ShellcodeUtils\main.go`

# ref 
- https://github.com/Ne0nd0g/go-shellcode/tree/master/cmd/ShellcodeUtils