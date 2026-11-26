// Command dsh-auth-proxy 是 dsh web 网关的入口。
//
// 这里刻意保持极薄：只负责把退出码翻译给操作系统，命令树与业务逻辑都在
// internal/cli。这样任何一条命令都能在测试里构造并断言，不必启动进程。
package main

import (
	"os"

	"github.com/bingoct/dsh-auth-gateway/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
