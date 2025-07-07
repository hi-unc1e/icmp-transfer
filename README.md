# ICMP文件传输工具使用指南


## 概述
![image](https://github.com/user-attachments/assets/ea285fe5-736d-4b72-bd75-efbf78c7484c)

这是一个基于ICMP协议的跨局域网文件传输工具，通过伪装成ping包来穿透网络防火墙，实现文件的可靠传输。

## 功能特性

- ✅ **跨平台支持**：Windows、Linux、macOS
- ✅ **可靠传输**：基于序列号的确认机制
- ✅ **实时进度**：传输进度条显示
- ✅ **容错重传**：自动重试机制
- ✅ **数据校验**：CRC校验确保数据完整性
- ✅ **并发处理**：支持多个会话同时传输

## 编译和安装

### 1. 环境要求

- Go 1.21+
- 管理员权限（Windows）或CAP_NET_RAW权限（Linux/macOS）

### 2. 编译步骤

```bash
# 克隆代码
git clone <repository-url>
cd icmp-transfer

# 下载依赖
go mod download

# 编译
go build -o icmp-transfer main.go

# 跨平台编译示例
# Windows
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o icmp-transfer.exe main.go

# Linux
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o icmp-transfer-linux main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o icmp-transfer-mac main.go
```

## 使用方法

### 服务端模式

启动服务端来接收文件：

```bash
# 使用默认存储目录 (./received_files)
sudo ./icmp-transfer server

# 指定存储目录
sudo ./icmp-transfer server /path/to/storage/directory
```

### 客户端模式

发送文件到服务端：

```bash
# 基本用法
sudo ./icmp-transfer client <server_ip> <file_path>

# 示例
sudo ./icmp-transfer client 192.168.1.100 /path/to/file.txt
```

## 权限配置

### Linux/macOS 权限设置

```bash
# 方法1：使用sudo运行
sudo ./icmp-transfer server

# 方法2：设置CAP_NET_RAW权限（推荐）
sudo setcap cap_net_raw+ep ./icmp-transfer

# 之后可以不用sudo运行
./icmp-transfer server
```

### Windows 权限设置

- 必须以管理员身份运行命令提示符或PowerShell
- 或者右键点击程序选择"以管理员身份运行"

## 系统服务部署

### Linux systemd 服务

创建服务文件 `/etc/systemd/system/icmp-transfer.service`：

```ini
[Unit]
Description=ICMP File Transfer Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/icmp-transfer server /var/lib/icmp-transfer
Restart=always
RestartSec=10
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable icmp-transfer
sudo systemctl start icmp-transfer
```

## 防火墙配置

### Linux iptables

```bash
# 允许ICMP流量
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
```

### Windows 防火墙

```powershell
# 允许ICMP Echo Request
netsh advfirewall firewall add rule name="ICMP Allow incoming V4 echo request" protocol=icmpv4:8,any dir=in action=allow

# 允许ICMP Echo Reply
netsh advfirewall firewall add rule name="ICMP Allow outgoing V4 echo reply" protocol=icmpv4:0,any dir=out action=allow
```

## 协议设计

### 数据包格式

```
+------------+------------+------------+------------+------------+
|  类型(1B)  | 会话ID(4B) | 序列号(2B) | 总片数(2B) | 校验和(2B) |
+------------+------------+------------+------------+------------+
|  长度(2B)  |                载荷数据                          |
+------------+----------------------------------------------------+
```

### 消息类型

- `0x01` - 数据包
- `0x02` - 确认包 (ACK)
- `0x03` - 开始包
- `0x04` - 结束包

## 性能优化

### 传输性能

- 最大载荷大小：1200字节
- 滑动窗口大小：32个包
- 默认超时时间：5秒
- 最大重试次数：3次

### 内存优化

- 使用流式处理避免大文件内存占用
- 自动清理完成的会话数据
- 缓冲区重用机制

## 故障排除

### 常见问题

1. **权限不足**
   ```
   Error: operation not permitted
   ```
   解决方案：使用sudo运行或设置CAP_NET_RAW权限

2. **连接被拒绝**
   ```
   Error: connection refused
   ```
   解决方案：检查防火墙设置，确保允许ICMP流量

3. **文件传输失败**
   ```
   Error: checksum mismatch
   ```
   解决方案：网络不稳定，程序会自动重试

### 调试模式

添加详细日志输出：

```bash
# 设置日志级别
export LOG_LEVEL=debug
./icmp-transfer server
```

## 安全注意事项

1. **网络安全**：此工具使用明文传输，不适用于敏感数据
2. **权限管理**：服务端需要特权权限，注意权限控制
3. **防火墙**：确保只在受信任的网络环境中使用
4. **资源限制**：大文件传输可能占用较多系统资源

## 后续优化计划

- [ ] 数据加密传输
- [ ] Web管理界面
- [ ] 传输速度控制
- [ ] 多文件批量传输
- [ ] 断点续传功能
- [ ] 压缩传输支持

## 技术支持

如果遇到问题，请检查：

1. 网络连通性（ping测试）
2. 防火墙配置
3. 程序权限设置
4. 日志输出信息

---

**注意**：此工具仅用于学习和测试目的，请遵守相关法律法规和网络使用协议。
