package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
)

type ClipboardData struct {
	Content string `json:"content"`
	Type    string `json:"type"`
}

func main() {
	// 监听TCP端口
	listener, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		fmt.Println("启动服务器失败:", err)
		return
	}
	defer listener.Close()

	fmt.Println("剪贴板同步服务已启动，监听端口9000...")

	for {
		// 接受连接
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("接受连接失败:", err)
			continue
		}

		// 处理连接
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	fmt.Println("开始处理内容")
	defer conn.Close()

	// 读取数据
	buffer := make([]byte, 4096)
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		fmt.Println("读取数据失败:", err)
		return
	}

	// 解析JSON数据
	var data ClipboardData
	err = json.Unmarshal(buffer[:n], &data)
	if err != nil {
		fmt.Println("解析数据失败:", err)
		return
	}

	// 写入到Mac剪贴板
	err = writeToMacClipboard(data.Content)
	if err != nil {
		fmt.Println("写入剪贴板失败:", err)
		return
	}

	fmt.Println("已收到并同步内容:", data.Content)
}

func writeToMacClipboard(content string) error {
	// 使用pbcopy命令写入剪贴板
	cmd := exec.Command("pbcopy")
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	err = cmd.Start()
	if err != nil {
		return err
	}

	_, err = pipe.Write([]byte(content))
	if err != nil {
		return err
	}

	pipe.Close()
	return cmd.Wait()
}
