package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip address start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4   = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6   = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase = 2               // 1addrLen + 2port, plus addrLen
	// lenHmacSha1 = 10
)

var debug ss.DebugLog
var sanitizeIps bool
var udp bool
var managerAddr string


// 从 conn 获取目标服务的地址，形如 "host:port" 的字符串
func getRequest(conn *ss.Conn) (host string, err error) {
	ss.SetReadTimeout(conn)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)

	// buf size 应该等于最大的请求体大小，当 addrType == 3 时，域名的长度最长达到 256 B。
	// 因此：
	//	addrType: 1B
	// 	lenByte: 1B
	// 	host: 255B
	//	port: 2B
	//	hmac-sha1: 10B

	buf := make([]byte, 269)

	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int

	// addrType & 0x0f 决定了地址的格式是 ipv4, ipv6 还是 domain 域名方式，不同方式的地址长度不同。
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4 // IPV4 的长度是: host(4B) + port(2B)
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6 // IPV6 的长度是: host(16B) + port(2B)
	case typeDm:
		// Domain 方式下，域名的字节长度 domainLen 存储在 buf[idDmLen] 中，占 1 个字节，取值范围 0 ~ 255
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		// 真实的 domain 数据尾随到 domainLen 字节后面，当然也要加上 port(2B)
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	// 确定了地址 addr 的长度，从 conn 中将其读取到 buf[reqStart:reqEnd] 里
	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively.
	// So this is not a big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))

	// 至此，确定 host 和 port，并将二者 join 连接后返回
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt = logCntDelta

func sanitizeAddr(addr net.Addr) string {
	if sanitizeIps {
		return "x.x.x.x:zzzz"
	} else {
		return addr.String()
	}
}

// client <=> conn <=> ssSever <=> remote <=> dest
func handleConnection(conn *ss.Conn, port string) {

	var host string

	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr())
	}

	// 这里引入了 closed 布尔变量，用于控制是否应该关闭 conn socket
	// http://blog.fatedier.com/2016/02/19/how-to-shutdown-go-net-dot-listeners-gracefully/
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", sanitizeAddr(conn.RemoteAddr()), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	// 从 conn 获取目标服务的地址，形如 "host:port" 的字符串
	host, err := getRequest(conn)
	if err != nil {
		log.Println("error getting request", sanitizeAddr(conn.RemoteAddr()), conn.LocalAddr(), err)
		closed = true
		return
	}

	// 检查 host 字符串中是否包含 0x00 字符，若包含则报错
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}

	debug.Println("connecting", host)

	// 同 host 建立 tcp 连接
	remote, err := net.Dial("tcp", host)
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}

	defer func() {
		if !closed {
			remote.Close()
		}
	}()

	if debug {
		debug.Printf("piping %s<->%s", sanitizeAddr(conn.RemoteAddr()), host)
	}

	// 创建正向连接: 不断的从 conn 中读取数据并写入到 remote 中
	go func() {
		ss.PipeThenClose(conn, remote, func(Traffic int) {
			passwdManager.addTraffic(port, Traffic) // 累加传输的字节数
		})
	}()
	// 创建反向连接: 不断的从 remote 中读取数据并写入到 conn 中
	ss.PipeThenClose(remote, conn, func(Traffic int) {
		passwdManager.addTraffic(port, Traffic)
	})

	// ???
	closed = true
	return
}







type PortListener struct {
	password string
	listener net.Listener
}

type UDPListener struct {
	password string
	listener *net.UDPConn
}


type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
	trafficStats map[string]int64
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.trafficStats[port] = 0
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener *net.UDPConn) {
	pm.Lock()
	pm.udpListener[port] = &UDPListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) getUDP(port string) (pl *UDPListener, ok bool) {
	pm.Lock()
	pl, ok = pm.udpListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	if udp {
		upl, ok := pm.getUDP(port)
		if !ok {
			return
		}
		upl.listener.Close()
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	delete(pm.trafficStats, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

func (pm *PasswdManager) addTraffic(port string, n int) {
	pm.Lock()
	pm.trafficStats[port] = pm.trafficStats[port] + int64(n)
	pm.Unlock()
	return
}

func (pm *PasswdManager) getTrafficStats() map[string]int64 {
	pm.Lock()
	copy := make(map[string]int64)
	for k, v := range pm.trafficStats {
		copy[k] = v
	}
	pm.Unlock()
	return copy
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string) {
	pl, ok := pm.get(port)
	if !ok {
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password {
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close()
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password)
	if udp {
		pl, ok := pm.getUDP(port)
		if !ok {
			log.Printf("new udp port %s added\n", port)
		} else {
			if pl.password == password {
				return
			}
			log.Printf("closing udp port %s to update password\n", port)
			pl.listener.Close()
		}
		go runUDP(port, password)
	}
}

var passwdManager = PasswdManager{
	portListener: map[string]*PortListener{},
	udpListener:  map[string]*UDPListener{},
	trafficStats: map[string]int64{},
}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {

	// 创建 chan
	var sigChan = make(chan os.Signal, 1)

	// 监听 syscall.SIGHUP 信号
	signal.Notify(sigChan, syscall.SIGHUP)

	// 阻塞监听 sigChan 递达的信号
	for sig := range sigChan {
		// 接收到 SIGHUP 信号，会重新读取配置文件，加载最新配置，而无需重启服务。kill -HUP pid 。
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// 对于其他信号，直接退出进程。
			log.Printf("caught signal %v, exit", sig) 	// is this going to happen?
			os.Exit(0)
		}
	}
}

// 处理 tcp 连接请求
func run(port, password string) {

	// 监听 tcp 端口
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}

	// 保存 port, password, ln 的映射关系
	passwdManager.add(port, password, ln)

	// 定义编解码器
	var cipher *ss.Cipher
	log.Printf("server listening port %v ...\n", port)

	for {

		// 开始接受新连接请求
		conn, err := ln.Accept()
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}

		// 根据 method 和 password 来初始化编解码器（只初始化一次）
		if cipher == nil {	// Creating cipher upon first connection.
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password)
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}

		// ss.NewConn(conn, cipher.Copy()): 用 cipher 为 tcp 连接进行加密封装
		// handleConnection(conn, port): 为 client 和 dest 创建正反双向连接，实现请求代理
		go handleConnection(ss.NewConn(conn, cipher.Copy()), port)
	}
}


func runUDP(port, password string) {
	var cipher *ss.Cipher
	port_i, _ := strconv.Atoi(port)
	log.Printf("listening udp port %v\n", port)


	// 监听 udp 端口
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	})

	// 保存 port, password, udpConn 的映射关系
	passwdManager.addUDP(port, password, conn)
	if err != nil {
		log.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer conn.Close()

	// 根据 method 和 password 来初始化编解码器（只初始化一次）
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}

	// 创建加密的 UDP 连接
	SecurePacketConn := ss.NewSecurePacketConn(conn, cipher.Copy())
	for {
		// 处理 udp 数据报文
		if err := ss.ReadAndHandleUDPReq(SecurePacketConn, func(traffic int) {
			passwdManager.addTraffic(port, traffic)
		}); err != nil {
			debug.Printf("udp read error: %v\n", err)
			return
		}
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

func unifyPortPassword(config *ss.Config) (err error) {

	// 如果没有单独为 port 设置独立密码
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one

		// 则检查全局 serverPort 和 password 是否已经设置，若未设置则报错
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}

		// 若 serverPort 和 password 均已经设置，则把对应 pair<port, passwd> 存储到 config.PortPassword 中
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		// 如果为单独的 port 配置了独立密码，则忽略全局的 serverPort 和 password 配置，这里打印一下警告信息。
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config





func main() {
	log.SetOutput(os.Stdout)

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")
	flag.StringVar(&configFile, "c", "config.json", "specify config file")
	flag.StringVar(&cmdConfig.Password, "k", "", "password")
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime")
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")
	flag.BoolVar((*bool)(&sanitizeIps), "A", false, "anonymize client ip addresses in all output")
	flag.BoolVar(&udp, "u", false, "UDP Relay")
	flag.StringVar(&managerAddr, "manager-address", "", "shadowsocks manager listening address")
	flag.Parse()

	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug)

	var err error
	config, err = ss.ParseConfig(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config)
	} else {
		ss.UpdateConfig(config, &cmdConfig)
	}

	// 设置默认加密方法
	if config.Method == "" {
		config.Method = "aes-256-cfb"
	}

	// 检查是否支持当前加密方法
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// 初始化全局 map<port,passwd> 配置，也即初始化 config.PortPassword
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}

	// 设置 goroutine 并发度
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}

	// 为每个 pair<port, passwd> 构建一个 goroutine
	for port, password := range config.PortPassword {

		// tcp
		go run(port, password)

		// udp?
		if udp {
			go runUDP(port, password)
		}
	}


	// 管理者进程监听地址
	if managerAddr != "" {

		addr, err := net.ResolveUDPAddr("udp", managerAddr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't resolve address: ", err)
			os.Exit(1)
		}

		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error listening:", err)
			os.Exit(1)
		}

		log.Printf("manager listening udp addr %v ...\n", managerAddr)
		defer conn.Close()
		go managerDaemon(conn)

	}


	// 阻塞到信号监听上，如果收到 hup 信号就刷新配置，其他信号则退出进程。
	waitSignal()
}








func managerDaemon(conn *net.UDPConn) {
	// add a report address set for ping response
	// according to https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users#example-code


	ctx := make(chan bool, 1)
	defer close(ctx)

	reportconnSet := make(map[string]*net.UDPAddr, 1024)

	// 后台定时任务，每十秒执行一次
	go func() {
		timer := time.Tick(10 * time.Second)
		for {
			select {
			case <-ctx:
				return
			case <-timer:
				//
				for _, addr := range reportconnSet {
					res := reportStat()
					if len(res) == 0 {
						continue
					}
					conn.WriteToUDP(res, addr)
				}
			}
		}
	}()

	for {


		data := make([]byte, 300)

		// Receiving a message, save to data slice
		_, remote, err := conn.ReadFromUDP(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read UDP manage msg, error: ", err.Error())
			continue
		}

		// data 中存储了需要执行的指令，这里检测指令类型，并作出不同处理。
		command := string(data)
		var res []byte
		switch {
		case strings.HasPrefix(command, "add:"):
			//
			res = handleAddPort(bytes.Trim(data[4:], "\x00\r\n "))
		case strings.HasPrefix(command, "remove:"):
			//
			res = handleRemovePort(bytes.Trim(data[7:], "\x00\r\n "))
		case strings.HasPrefix(command, "ping"):
			// 返回 "pong"
			conn.WriteToUDP(handlePing(), remote)
			reportconnSet[remote.String()] = remote // append the host into the report list
		case strings.HasPrefix(command, "ping-stop"): // add the stop ping command
			// 返回 "pong"
			conn.WriteToUDP(handlePing(), remote)
			delete(reportconnSet, remote.String())
		}


		if len(res) == 0 {
			continue
		}

		// Sending a message back to client
		_, err = conn.WriteToUDP(res, remote)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to write UDP manage msg, error: ", err.Error())
			continue
		}
	}


}


//
func handleAddPort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
		Password   string      `json:"password"`
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil || params.Password == "" {
		fmt.Fprintln(os.Stderr, "Failed to parse add req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	passwdManager.updatePortPasswd(port, params.Password)
	return []byte("ok")
}

//
func handleRemovePort(payload []byte) []byte {
	var params struct {
		ServerPort interface{} `json:"server_port"` // may be string or int
	}
	json.Unmarshal(payload, &params)
	if params.ServerPort == nil {
		fmt.Fprintln(os.Stderr, "Failed to parse remove req: ", string(payload))
		return []byte("err")
	}
	port := parsePortNum(params.ServerPort)
	if port == "" {
		return []byte("err")
	}
	log.Printf("closing port %s\n", port)
	passwdManager.del(port)
	return []byte("ok")
}

func handlePing() []byte {
	return []byte("pong")
}

// reportStat get the stat:trafficStat and return avery 10 sec as for the protocol
// https://github.com/shadowsocks/shadowsocks/wiki/Manage-Multiple-Users
func reportStat() []byte {
	stats := passwdManager.getTrafficStats()
	var buf bytes.Buffer
	buf.WriteString("stat: ")
	ret, _ := json.Marshal(stats)
	buf.Write(ret)
	return buf.Bytes()
}

func parsePortNum(in interface{}) string {
	var port string
	switch in.(type) {
	case string:
		// try to convert to number then convert back, to ensure valid value
		portNum, err := strconv.Atoi(in.(string))
		if portNum == 0 || err != nil {
			return ""
		}
		port = strconv.Itoa(portNum)
	case float64:
		port = strconv.Itoa(int(in.(float64)))
	default:
		return ""
	}
	return port
}
