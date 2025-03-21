#!/bin/bash
# 构建并运行剪贴板同步工具

# 确保依赖包已安装
echo "正在安装依赖..."
go get github.com/atotto/clipboard

# 构建应用
echo "正在构建应用..."
go build -o clipboard-sync main.go

# 显示帮助信息
echo ""
echo "构建完成！可以通过以下命令运行:"
echo ""
echo "普通模式 (发送和接收剪贴板内容):"
echo "./clipboard-sync"
echo ""
echo "自定义端口:"
echo "./clipboard-sync -port 9000 -bport 9001"
echo ""
echo "仅服务器模式 (只接收不发送):"
echo "./clipboard-sync -server"
echo ""