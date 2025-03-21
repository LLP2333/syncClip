package main

import (
	_ "bytes"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/atotto/clipboard"
)

type ClipboardData struct {
	Content string `json:"content"`
	Type    string `json:"type"`
}

func main() {
	serverAddr := "127.0.0.1:9000"
	var lastContent string

	for {
		// 读取当前剪贴板内容
		currentContent, err := clipboard.ReadAll()
		if err != nil {
			fmt.Println("读取剪贴板失败:", err)
			time.Sleep(1 * time.Second)
			continue
		}

		// 检测内容是否变化
		if currentContent != lastContent && currentContent != "" {
			// 内容变化，发送到Mac
			err := sendToMac(serverAddr, currentContent)
			if err != nil {
				fmt.Println("发送到Mac失败:", err)
			} else {
				lastContent = currentContent
				fmt.Println("已同步:", currentContent)
			}
		}

		// 每秒检查一次
		time.Sleep(1 * time.Second)
	}
}

func sendToMac(serverAddr, content string) error {
	// 准备数据
	data := ClipboardData{
		Content: content,
		Type:    "text",
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	// 建立TCP连接
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 发送数据
	_, err = conn.Write(jsonData)
	return err
}
