package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

// ClipboardData 表示剪贴板数据的结构
type ClipboardData struct {
	Content   string `json:"content"` // 加密后的内容
	Type      string `json:"type"`
	SenderID  string `json:"sender_id"` // 发送者ID，用于防止循环同步
	Timestamp int64  `json:"timestamp"` // 时间戳，用于处理冲突
}

// Config 应用程序配置
type Config struct {
	Port           int      // 监听端口
	BroadcastPort  int      // 用于发现其他客户端的广播端口
	PeersAddresses []string // 已知的对等节点地址
	ServerMode     bool     // 是否为服务器模式（仅接收而不发送）
	ClientID       string   // 客户端唯一标识
	NetworkSegment string   // 局域网网段
	EncryptionKey  string   // 加密密钥
}

var (
	lastContent string
	config      Config
	peers       = make(map[string]bool)
	peersMutex  sync.RWMutex
	lastSync    int64 // 上次同步的时间戳
)

func main() {
	// 解析命令行参数
	port := flag.Int("port", 9000, "监听端口")
	broadcastPort := flag.Int("bport", 9001, "广播端口")
	serverMode := flag.Bool("server", false, "仅服务器模式（只接收不发送）")
	networkSegment := flag.String("network", "255.255.255.255", "指定广播的网段，如192.168.1.255")
	listInterfaces := flag.Bool("list", false, "列出所有可用的网络接口及其广播地址")
	encryptionKey := flag.String("key", "", "加密密钥（必须提供）")
	flag.Parse()

	// 检查加密密钥是否提供
	if *encryptionKey == "" {
		fmt.Println("错误: 必须提供加密密钥，使用 -key 参数")
		flag.Usage()
		os.Exit(1)
	}

	// 生成唯一的客户端ID
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	config = Config{
		Port:           *port,
		BroadcastPort:  *broadcastPort,
		ServerMode:     *serverMode,
		ClientID:       fmt.Sprintf("%s-%d", hostname, time.Now().UnixNano()),
		NetworkSegment: *networkSegment,
		EncryptionKey:  *encryptionKey,
	}

	// 显示可用的网络接口
	if *listInterfaces {
		fmt.Println("可用的网络接口及广播地址:")
		interfaces := getNetworkInterfaces()
		for i, iface := range interfaces {
			fmt.Printf("[%d] %s\n", i, iface)
		}
		os.Exit(0)
	}

	fmt.Printf("剪贴板同步服务已启动，ID: %s\n", config.ClientID)
	fmt.Printf("监听端口: %d, 广播端口: %d\n", config.Port, config.BroadcastPort)
	fmt.Printf("广播网段: %s\n", config.NetworkSegment)
	fmt.Println("加密已启用")
	if config.ServerMode {
		fmt.Println("运行模式: 仅服务器（只接收不发送）")
	} else {
		fmt.Println("运行模式: 客户端和服务器")
	}

	// 并发启动服务器、发现服务和剪贴板监控
	var wg sync.WaitGroup
	wg.Add(3)

	// 启动TCP服务器，接收剪贴板更新
	go func() {
		defer wg.Done()
		startServer()
	}()

	// 启动UDP发现服务，查找局域网内其他实例
	go func() {
		defer wg.Done()
		startDiscoveryService()
	}()

	// 监控本地剪贴板变化
	go func() {
		defer wg.Done()
		if !config.ServerMode {
			monitorClipboard()
		} else {
			// 服务器模式下不发送更新，但仍然保持活跃状态
			select {}
		}
	}()

	wg.Wait()
}

// 加密函数: 使用AES-GCM加密数据
func encrypt(plainText string, key string) (string, error) {
	// 使用SHA-256生成固定长度的密钥
	hash := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 加密数据
	cipherText := gcm.Seal(nonce, nonce, []byte(plainText), nil)

	// 返回Base64编码的密文
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// 解密函数: 使用AES-GCM解密数据
func decrypt(cipherText string, key string) (string, error) {
	// 使用SHA-256生成固定长度的密钥
	hash := sha256.Sum256([]byte(key))
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("密文太短")
	}

	nonce, cipherData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// startServer 启动TCP服务器，接收剪贴板更新
func startServer() {
	listenAddr := fmt.Sprintf("0.0.0.0:%d", config.Port)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Printf("启动服务器失败: %v\n", err)
		return
	}
	defer listener.Close()

	fmt.Printf("TCP服务已启动，监听端口%d...\n", config.Port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("接受连接失败: %v\n", err)
			continue
		}

		go handleConnection(conn)
	}
}

// handleConnection 处理传入的连接
func handleConnection(conn net.Conn) {
	defer conn.Close()

	buffer := make([]byte, 8192) // 增大缓冲区以处理更大的内容
	n, err := conn.Read(buffer)
	if err != nil && err != io.EOF {
		fmt.Printf("读取数据失败: %v\n", err)
		return
	}

	var data ClipboardData
	err = json.Unmarshal(buffer[:n], &data)
	if err != nil {
		fmt.Printf("解析数据失败: %v\n", err)
		return
	}

	// 防止循环同步和过期数据
	if data.SenderID == config.ClientID || data.Timestamp <= lastSync {
		return
	}

	// 更新最后同步时间戳
	lastSync = data.Timestamp

	// 解密接收到的内容
	decryptedContent, err := decrypt(data.Content, config.EncryptionKey)
	if err != nil {
		fmt.Printf("解密内容失败，可能密钥不匹配: %v\n", err)
		return
	}

	lastContent = decryptedContent

	// 写入剪贴板
	setClipboardContent(decryptedContent)
	fmt.Printf("已从 %s 接收并同步内容 (长度: %d)...\n", conn.RemoteAddr(), len(decryptedContent))
}

// monitorClipboard 监控本地剪贴板变化
func monitorClipboard() {
	for {
		currentContent, err := clipboard.ReadAll()
		if err != nil {
			fmt.Printf("读取剪贴板失败: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		// 检测剪贴板内容是否变化并且不为空
		if currentContent != lastContent && currentContent != "" {
			lastContent = currentContent
			lastSync = time.Now().Unix()

			// 加密剪贴板内容
			encryptedContent, err := encrypt(currentContent, config.EncryptionKey)
			if err != nil {
				fmt.Printf("加密内容失败: %v\n", err)
				continue
			}

			// 创建剪贴板数据
			data := ClipboardData{
				Content:   encryptedContent,
				Type:      "text",
				SenderID:  config.ClientID,
				Timestamp: lastSync,
			}

			// 广播到所有已知节点
			broadcastToAllPeers(data)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// broadcastToAllPeers 将剪贴板内容发送给所有已知的对等节点
func broadcastToAllPeers(data ClipboardData) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Printf("JSON编码失败: %v\n", err)
		return
	}

	peersMutex.RLock()
	defer peersMutex.RUnlock()

	if len(peers) == 0 {
		fmt.Println("当前没有已知的对等节点")
		return
	}

	fmt.Printf("正在同步加密内容到 %d 个节点 (内容长度: %d)...\n", len(peers), len(data.Content))

	// 向所有已知节点发送数据
	for peer := range peers {
		go func(peerAddr string) {
			// 尝试建立TCP连接
			conn, err := net.DialTimeout("tcp", peerAddr, 2*time.Second)
			if err != nil {
				fmt.Printf("连接到 %s 失败: %v\n", peerAddr, err)
				// 移除失效的节点
				peersMutex.Lock()
				delete(peers, peerAddr)
				peersMutex.Unlock()
				return
			}
			defer conn.Close()

			// 发送数据
			_, err = conn.Write(jsonData)
			if err != nil {
				fmt.Printf("发送到 %s 失败: %v\n", peerAddr, err)
				return
			}
		}(peer)
	}
}

// startDiscoveryService 启动节点发现服务
func startDiscoveryService() {
	// 开启UDP广播监听
	go listenForBroadcasts()

	// 如果不是服务器模式，则定期广播自己的存在
	if !config.ServerMode {
		go broadcastPresence()
	}
}

// listenForBroadcasts 监听其他节点的UDP广播
func listenForBroadcasts() {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", config.BroadcastPort))
	if err != nil {
		fmt.Printf("解析UDP地址失败: %v\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Printf("监听UDP广播失败: %v\n", err)
		return
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Printf("读取UDP数据失败: %v\n", err)
			continue
		}

		message := string(buffer[:n])
		// 消息格式: "CLIPBOARD_SYNC:<client_id>:<tcp_port>:<key_hash>"
		if strings.HasPrefix(message, "CLIPBOARD_SYNC:") {
			parts := strings.Split(message, ":")
			if len(parts) >= 4 {
				clientID := parts[1]
				if clientID != config.ClientID { // 忽略自己的广播
					// 验证密钥哈希
					receivedKeyHash := parts[3]
					hashBytes := sha256.Sum256([]byte(config.EncryptionKey))
					ourKeyHash := fmt.Sprintf("%x", hashBytes[:8]) // 只使用哈希的前8字节

					if receivedKeyHash == ourKeyHash {
						// 获取发送者的IP地址
						ip := remoteAddr.IP.String()
						port := parts[2]

						// 将节点添加到对等节点列表
						peerAddr := fmt.Sprintf("%s:%s", ip, port)
						peersMutex.Lock()
						if _, exists := peers[peerAddr]; !exists {
							peers[peerAddr] = true
							fmt.Printf("发现新节点: %s (ID: %s)\n", peerAddr, clientID)
						}
						peersMutex.Unlock()
					} else {
						fmt.Printf("忽略密钥不匹配的节点 %s (ID: %s)\n", remoteAddr.IP.String(), clientID)
					}
				}
			}
		}
	}
}

// broadcastPresence 定期广播自己的存在
func broadcastPresence() {
	// 创建广播地址，使用指定的网段
	broadcastAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", config.NetworkSegment, config.BroadcastPort))
	if err != nil {
		fmt.Printf("解析广播地址失败: %v\n", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, broadcastAddr)
	if err != nil {
		fmt.Printf("创建UDP连接失败: %v\n", err)
		return
	}
	defer conn.Close()

	// 计算密钥的哈希值前8字节，用于验证
	hashBytes := sha256.Sum256([]byte(config.EncryptionKey))
	keyHash := fmt.Sprintf("%x", hashBytes[:8]) // 只使用哈希的前8字节
	message := fmt.Sprintf("CLIPBOARD_SYNC:%s:%d:%s", config.ClientID, config.Port, keyHash)

	for {
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("发送广播消息失败: %v\n", err)
		}

		// 每5秒广播一次
		time.Sleep(5 * time.Second)
	}
}

// setClipboardContent 根据不同操作系统设置剪贴板内容
func setClipboardContent(content string) {
	if runtime.GOOS == "darwin" {
		// 使用pbcopy命令写入Mac剪贴板
		cmd := exec.Command("pbcopy")
		pipe, err := cmd.StdinPipe()
		if err != nil {
			fmt.Printf("创建命令管道失败: %v\n", err)
			return
		}

		err = cmd.Start()
		if err != nil {
			fmt.Printf("启动pbcopy命令失败: %v\n", err)
			return
		}

		_, err = pipe.Write([]byte(content))
		if err != nil {
			fmt.Printf("写入管道失败: %v\n", err)
			return
		}

		pipe.Close()
		cmd.Wait()
	} else {
		// 使用clipboard库写入Windows或Linux剪贴板
		err := clipboard.WriteAll(content)
		if err != nil {
			fmt.Printf("写入剪贴板失败: %v\n", err)
			return
		}
	}
}

// 获取所有网络接口的函数
func getNetworkInterfaces() []string {
	var interfaces []string

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("获取网络接口失败: %v\n", err)
		return interfaces
	}

	for _, iface := range ifaces {
		// 忽略回环接口和非活动接口
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// 只考虑IPv4地址
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}

			// 计算广播地址
			ip := ipNet.IP.To4()
			mask := ipNet.Mask
			broadcast := net.IP(make([]byte, 4))
			for i := range ip {
				broadcast[i] = ip[i] | ^mask[i]
			}

			interfaces = append(interfaces, broadcast.String())
		}
	}

	return interfaces
}
