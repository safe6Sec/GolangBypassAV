# GolangBypassAV
研究利用golang来bypassAV

## 前言
免杀这块本来就不是web狗擅长的，而且作为一个web狗也没必要花太多时间来折腾这个，达到能用就行，不要追求全部免杀，能免杀目标就行。


## 思路
静态免杀比较简单，可选加密payload或者分离payload。  
分离免杀效果比加密payload的效果要好。

## 说明
test1、test2效果还可以。





## 编译命令

```bash

go build -ldflags="-s -w" -o main1.exe -race main.go

go build -ldflags="-s -w" -o main1.exe

go build -ldflags="-s -w -H=windowsgui" -o main2.exe

```
