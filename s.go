// service.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	maxLogSize     = 10 * 1024 * 1024 // 单个日志文件最大 10MB
	processTimeout = 5 * time.Second  // 进程停止超时
)

type appConfig struct {
	name string
	args string
}

// processInfo 保存进程信息和取消函数
type processInfo struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	logFile *os.File
}

var apps = []appConfig{
	{"gost", `-C "%s\gost.json"`},
	{"xray", `run -c "%s\config.json"`},
}

// appArgsMap 用于快速查找应用配置
var appArgsMap = func() map[string]string {
	m := make(map[string]string)
	for _, cfg := range apps {
		m[cfg.name] = cfg.args
	}
	return m
}()

var (
	processes   = make(map[string]*processInfo)
	processesMu sync.Mutex
)

func getExeDir() string {
	// 获取当前exe所在目录
	if path, err := os.Executable(); err == nil {
		return filepath.Dir(path)
	}
	return "."
}

func getSystemUptime() time.Duration {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getTick64 := kernel32.NewProc("GetTickCount64")

	r, _, err := getTick64.Call()
	if err != nil && err.Error() != "The operation completed successfully." {
		return 0 // 返回 0 表示获取失败
	}
	return time.Duration(r) * time.Millisecond
}

func checkUptimeAndWait() {
	uptime := getSystemUptime()
	// 如果系统启动不到 1 分钟
	if uptime < 1*time.Minute {
		fmt.Printf("系统运行时间: %v, 小于 1 分钟, 等待 10 秒后启动应用...\n", uptime.Round(time.Second))
		time.Sleep(10 * time.Second)
	}
}

// parseArgs 解析命令行参数，正确处理带引号的参数（支持带空格的路径）
func parseArgs(input string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range input {
		switch {
		case (r == '"' || r == '\'') && !inQuote:
			inQuote = true
			quoteChar = r
		case r == quoteChar && inQuote:
			inQuote = false
			quoteChar = 0
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func rotateLogIfNeeded(logPath string) error {
	info, err := os.Stat(logPath)
	if err != nil {
		return nil // 文件不存在，忽略
	}
	if info.Size() >= maxLogSize {
		// 重命名旧日志文件
		timestamp := time.Now().Format("20060102_150405")
		oldPath := fmt.Sprintf("%s.%s.log", strings.TrimSuffix(logPath, ".log"), timestamp)
		if err := os.Rename(logPath, oldPath); err != nil {
			return fmt.Errorf("日志轮转失败: %v", err)
		}
	}
	return nil
}

func startApp(name, argsTemplate string) error {
	exeDir := getExeDir()

	// 构建参数（使用 parseArgs 正确处理带空格的路径）
	args := fmt.Sprintf(argsTemplate, exeDir)
	parts := parseArgs(args)

	exePath := filepath.Join(exeDir, name+".exe")

	// 检查可执行文件是否存在
	if _, err := os.Stat(exePath); os.IsNotExist(err) {
		return fmt.Errorf("[%s] 可执行文件不存在: %s", name, exePath)
	}

	// 创建日志文件前先检查是否需要轮转
	logPath := filepath.Join(exeDir, name+".log")
	if err := rotateLogIfNeeded(logPath); err != nil {
		fmt.Printf("[%s] 警告: %v\n", name, err)
	}

	// 创建日志文件
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("[%s] 创建日志文件失败: %v", name, err)
	}

	// 创建带缓冲的写入器，定期刷新
	writer := logFile

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, exePath, parts...)
	cmd.Dir = exeDir
	cmd.Stdout = writer
	cmd.Stderr = writer
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}

	if err := cmd.Start(); err != nil {
		cancel()
		logFile.Close()
		return fmt.Errorf("[%s] 启动失败: %v", name, err)
	}

	processesMu.Lock()
	pInfo := &processInfo{cmd: cmd, cancel: cancel, logFile: logFile}
	processes[name] = pInfo
	processesMu.Unlock()

	// 启动后台协程监听进程退出并定期刷新日志
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[%s] 监控协程 panic: %v\n", name, r)
			}
			// 确保日志文件关闭
			processesMu.Lock()
			if pInfo.logFile != nil {
				pInfo.logFile.Sync()
				pInfo.logFile.Close()
				pInfo.logFile = nil
			}
			processesMu.Unlock()
		}()

		// 定期刷新日志（每 3 秒）
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				processesMu.Lock()
				if pInfo.logFile != nil {
					pInfo.logFile.Sync()
				}
				processesMu.Unlock()
			case <-ctx.Done():
				// 收到取消信号，等待进程退出
				_ = cmd.Wait()
				return
			}
		}
	}()

	// 启动监控协程：进程退出后尝试重启（可选功能）
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[%s] 重启监控协程 panic: %v\n", name, r)
			}
		}()

		_ = cmd.Wait()

		// 进程异常退出（非手动停止），尝试重启
		processesMu.Lock()
		stillExists := processes[name] == pInfo
		processesMu.Unlock()

		if stillExists {
			fmt.Printf("[%s] 进程异常退出，3 秒后尝试重启...\n", name)
			select {
			case <-time.After(3 * time.Second):
				// 检查是否已被手动停止
				processesMu.Lock()
				_, exists := processes[name]
				processesMu.Unlock()
				if exists {
					args, ok := appArgsMap[name]
					if ok {
						_ = startApp(name, args)
					}
				}
			case <-ctx.Done():
				// 收到取消信号，不重启
			}
		}
	}()

	fmt.Printf("[%s] 已启动, PID: %d, 参数: %s, 日志: %s\n", name, cmd.Process.Pid, args, logPath)
	return nil
}

func stopApp(name string) {
	processesMu.Lock()
	info, exists := processes[name]
	processesMu.Unlock()

	if !exists || info.cmd == nil || info.cmd.Process == nil {
		return
	}

	pid := info.cmd.Process.Pid

	// 先发送取消信号让监控协程退出
	info.cancel()

	// 使用 taskkill 强制杀死进程及其所有子进程 (/T /F)，带超时
	done := make(chan struct{})
	go func() {
		_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid)).Run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(processTimeout):
		fmt.Printf("[%s] 警告: 进程停止超时\n", name)
	}

	if info.logFile != nil {
		_ = info.logFile.Close()
	}

	processesMu.Lock()
	delete(processes, name)
	processesMu.Unlock()

	fmt.Printf("[%s] 已停止 (PID: %d)\n", name, pid)
}

func stopAllApps() {

	processesMu.Lock()
	names := make([]string, 0, len(processes))
	for name := range processes {
		names = append(names, name)
	}
	processesMu.Unlock()

	for _, name := range names {
		stopApp(name)
	}
}

type myService struct{}

func (m *myService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// 检查系统启动时间
	checkUptimeAndWait()

	// 启动所有应用
	allStarted := true
	for _, cfg := range apps {
		if err := startApp(cfg.name, cfg.args); err != nil {
			fmt.Printf("错误: %v\n", err)
			allStarted = false
		}
		time.Sleep(500 * time.Millisecond)
	}

	if !allStarted {
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			fmt.Println("收到停止信号，正在关闭...")
			stopAllApps()
			changes <- svc.Status{State: svc.StopPending}
			return false, 0
		default:
			// 忽略其他命令
		}
	}
	return false, 0
}

func installService(name, desc string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// 检查服务是否已存在
	if existingService, err := m.OpenService(name); err == nil {
		existingService.Close()
		return fmt.Errorf("服务 [%s] 已存在，请先卸载后再安装", name)
	}

	exepath, err := os.Executable()
	if err != nil {
		return err
	}

	svcCfg := mgr.Config{
		DisplayName: name,
		Description: desc,
		StartType:   mgr.StartAutomatic,
	}

	s, err := m.CreateService(name, exepath, svcCfg)
	if err != nil {
		return err
	}
	defer s.Close()

	fmt.Printf("服务 [%s] 安装成功\n", name)
	return nil
}

func startService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("无法打开服务: %v", err)
	}
	defer s.Close()

	if err := s.Start(); err != nil {
		return fmt.Errorf("启动服务失败: %v", err)
	}

	fmt.Printf("服务 [%s] 启动成功\n", name)
	return nil
}

func uninstallService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("服务 [%s] 不存在或无法打开: %v", name, err)
	}
	defer s.Close()

	// 获取服务状态
	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		return fmt.Errorf("请先停止服务再卸载")
	}

	// 删除服务
	if err := s.Delete(); err != nil {
		return fmt.Errorf("删除服务失败: %v", err)
	}

	fmt.Printf("服务 [%s] 已卸载\n", name)
	return nil
}

func stopService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("无法打开服务: %v", err)
	}
	defer s.Close()

	status, err := s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("停止服务失败: %v", err)
	}

	// 等待服务停止
	timeout := time.Now().Add(30 * time.Second)
	for status.State != svc.Stopped {
		if time.Now().After(timeout) {
			return fmt.Errorf("等待服务停止超时")
		}
		time.Sleep(500 * time.Millisecond)
		status, err = s.Query()
		if err != nil {
			return fmt.Errorf("查询服务状态失败: %v", err)
		}
	}

	fmt.Printf("服务 [%s] 已停止\n", name)
	return nil
}

// printUsage 打印使用说明
func printUsage() {
	fmt.Println("=== GostXrayService 使用说明 ===")
	fmt.Println()
	fmt.Println("命令行参数:")
	fmt.Println("  install     - 安装 Windows 服务")
	fmt.Println("  start       - 启动服务")
	fmt.Println("  stop        - 停止服务")
	fmt.Println("  uninstall   - 卸载服务")
	fmt.Println("  console     - 控制台调试模式")
	fmt.Println("  version     - 显示版本信息")
	fmt.Println("  help        - 显示此帮助信息")
	fmt.Println()
	fmt.Println("服务说明:")
	fmt.Println("  该服务用于管理 gost 和 xray 两个代理程序的启动和停止")
	fmt.Println("  配置文件: gost.json (gost配置), config.json (xray配置)")
	fmt.Println("  日志文件: gost.log, xray.log")
}

func main() {
	const serviceName = "GostXrayService"

	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Printf("检查服务模式失败: %v\n", err)
		os.Exit(1)
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := installService(serviceName, "gost + xray 代理服务"); err != nil {
				fmt.Printf("安装失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "start":
			if err := startService(serviceName); err != nil {
				fmt.Printf("启动失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "stop":
			if err := stopService(serviceName); err != nil {
				fmt.Printf("停止失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			if err := uninstallService(serviceName); err != nil {
				fmt.Printf("卸载失败: %v\n", err)
				os.Exit(1)
			}
			return
		case "console":
			// 控制台调试模式
			fmt.Println("=== 控制台模式运行 ===")
			exeDir := getExeDir()
			fmt.Printf("工作目录: %s\n", exeDir)

			// 检查系统启动时间
			checkUptimeAndWait()

			for _, cfg := range apps {
				if err := startApp(cfg.name, cfg.args); err != nil {
					fmt.Printf("错误: %v\n", err)
				}
			}
			fmt.Println("按 Ctrl+C 停止...")

			// 等待中断信号
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			<-sigChan

			fmt.Println("\n正在停止所有应用...")
			stopAllApps()
			// 等待 goroutine 清理
			time.Sleep(500 * time.Millisecond)
			fmt.Println("已退出")
			return
		case "version":
			fmt.Println("GostXrayService 版本: 1.0.0")
			return
		case "help":
			printUsage()
			return
		}
	}

	if isService {
		if err := svc.Run(serviceName, &myService{}); err != nil {
			fmt.Printf("服务运行错误: %v\n", err)
		}
	} else {
		// 显示使用说明
		fmt.Println("=== 使用说明 ===")
		fmt.Println("安装服务: service.exe install")
		fmt.Println("启动服务: service.exe start")
		fmt.Println("停止服务: service.exe stop")
		fmt.Println("调试模式: service.exe console")
	}
}
