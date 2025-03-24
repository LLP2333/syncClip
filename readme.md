# 局域网剪贴板同步工具

这是一个简单的局域网剪贴板同步工具，可以在同一局域网内的多台计算机之间自动同步剪贴板内容。

## 功能特点

- 支持多台电脑之间的双向剪贴板同步
- 自动发现局域网内的其他实例
- 防止循环同步和冲突
- 支持Windows、Mac和Linux系统
- 提供服务器模式（仅接收不发送）

## 系统要求

- Go 1.13或更高版本
- 支持的操作系统：Windows、MacOS、Linux

## 安装

1. 确保已安装Go开发环境
2. 获取依赖包：
```bash
go get github.com/atotto/clipboard
```
3. 构建应用：
```bash
go build -o clipboard-sync main.go
```

## 使用方法
列出可用网络接口：
```bash
./clipboard-sync  -key password   -list
```
指定网段运行：
```bash
./clipboard-sync -key password -network 192.168.1.255 
```

同时指定网段和端口：
```bash
./clipboard-sync -key password -network 192.168.1.255  -port 9000 -bport 9001
```

仅服务器模式

如果只想接收而不发送剪贴板更新：

```bash
./clipboard-sync -key password -network 192.168.1.255  -server
```
## 参数说明
```text
-key string
加密密钥（必须提供）
-list
列出所有可用的网络接口及其广播地址
-network string
指定广播的网段，如192.168.1.255 (default "255.255.255.255")
-bport int
广播端口 (default 9001)
-port int
监听端口 (default 9000)
-server
仅服务器模式（只接收不发送）
```
## 工作原理

1. 程序启动时，会生成一个唯一的客户端ID
2. 通过UDP广播发现局域网内的其他实例
3. 监控本地剪贴板变化
4. 当检测到剪贴板内容变化时，将新内容发送给所有已知的节点
5. 接收到的更新会写入本地剪贴板

## 注意事项

- 使用唯一ID和时间戳防止循环同步
- 如果连接到某个节点失败，会自动从已知节点列表中移除
- 每5秒广播一次自己的存在，以便新加入的节点能够发现
- 每500毫秒检查一次剪贴板变化

