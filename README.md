# latticeguard

我们尚未得知后量子加密支持究竟什么时候合并到现有PGP标准库的主线

啊 , 还好已经有轮子了 , 所以戳两下 LLM 写了一个简单的GUI用于管理PQC PGP证书

> 本项目(用于支持PQC PGP)使用的主要轮子
>
> (BSD-3许可证)
> github.com/ProtonMail/go-crypto-proton
> 
> github.com/cloudflare/circl
> 
> github.com/bwesterb/go-ristretto
> 
> golang.org/x/crypto

> GUI
> 
> fyne.io/fyne/

## 功能

创建与管理PQC证书

<img width="1022" height="547" alt="圖片" src="https://github.com/user-attachments/assets/fd7ef454-834b-4824-9309-23fd03cffcf6" />


文件与文本加解密

<img width="888" height="630" alt="圖片" src="https://github.com/user-attachments/assets/af34cc6e-3d1b-4f83-bf81-204551630f71" />

<img width="1086" height="587" alt="圖片" src="https://github.com/user-attachments/assets/513649d3-402e-4276-8f6d-96ac6db23011" />


设置

<img width="1094" height="546" alt="圖片" src="https://github.com/user-attachments/assets/b159df8d-6a3d-40f9-a558-9057a8768f34" />


## Tips

请务必备份好你的私钥

另外说一下 , 本程序默认会将包括导入私钥在内的数据被放在 `./data`

有问题欢迎反馈

## 快速运行

```
# 运行
go run ./cmd/latticeguard
# 构建
go build -o latticeguard ./cmd/latticeguard
```
