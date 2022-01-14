# GolangBypassAV


![GolangBypassAV](https://socialify.git.ci/safe6Sec/GolangBypassAV/image?description=1&font=Inter&forks=1&issues=1&language=1&owner=1&pattern=Plus&stargazers=1&theme=Light)

研究利用golang来bypassAV
## 前言
免杀这块本来就不是web狗擅长的，而且作为一个web狗也没必要花太多时间来折腾这个，达到能用就行，不要追求全部免杀，能免杀目标就行。


## 免杀思路
### 静态
静态免杀比较简单，可选加密payload或者分离payload。  
核心：   
把特征去除即可过静态，某些杀毒软件带沙箱，还需要考虑反沙箱。   
除此之外还可以考虑如下方式（由于要引入net包，导致文件大小比较大.我不做测试了.）：
- 把payload分离远程服务器   
- 把payload进行隐写    
- 把shellcode，放在自定义段里面
总之就是各种分离  

### 动态   
敏感api越少越好比如注册表操作、添加启动项、添加服务、添加用户、注入、劫持、创建进程、加载DLL等等    
核心：   
- 想法设法的把shellcode加载到内存里面。    
- 使用系统调用+sysid
- 敏感api脱钩，如地狱之门，二次加载
- 敏感操作可以分步进行，如申请内存先申请读写(rw)，再改成可以执行(rwx)。不要一来就直接申请读写执行的内存。




## 使用
**暂时只支持windows系统编译!!!!**

默认payload位置C:\\Users\\Administrator\\Desktop\\payload.bin  
执行下面命令,即可生成免杀(game.exe)
```cmd
指定payload
main.exe payload.bin

不指定payload，直接运行即可
main.exe
```



## 更新

2022.1.13
学习并添加光环之门免杀。真香

2021.8.29
完善生成命令，不用手动改特征。已经支持全部动态生成，只需要指定payload即可生成免杀。   
源码在gen目录下面   
默认生成的是带弹窗，想不带弹窗，自行修改源码。


2021.8.24  
直接用gen里面代码进行生成,演示视频已经放公众号，目前免杀已达目的更新会放缓。   
注意：建议每次使用之前手动改一下key,如果被杀改一下关键字即可。    







## 编译命令


```bash
免杀效果最好,缺点文件最大
go build main.go

加了race参数,文件更大比原始的还大,效果很垃圾
go build -ldflags="-s -w" -o main1.exe -race main.go

常用编译命令,免杀效果较好,可以减少文件体积
go build -ldflags="-s -w" -o main1.exe

常用编译命令,免杀效果一般,减少文件体积+隐藏窗口
go build -ldflags="-s -w -H=windowsgui" -o main2.exe


set GOOS=windows GOARCH=amd64;go build -o main.exe

```



## 参考
- https://github.com/Ne0nd0g/go-shellcode     
- https://github.com/Rvn0xsy/BadCode    
- https://github.com/timwhitez/Doge-Gabh    
- https://github.com/Airboi/bypass-av-note    
- https://github.com/brimstone/go-shellcode            
- https://github.com/timwhitez/Doge-Loader            
- https://github.com/fcre1938/goShellCodeByPassVT            
