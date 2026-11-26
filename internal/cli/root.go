package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version 是用户可见的干净 SemVer（major.minor.patch）；scoop 的版本号由
// deploy.ps1 单独算，两者刻意分离，避免二进制里带构建时间戳。
var version = "0.1.0"

// Execute 构造命令树并执行，返回值交给 main 决定退出码。
func Execute() error {
	return newRootCmd().Execute()
}

// newRootCmd 构造命令树。抽出来是为了能单测 help / flag 解析而不真的起网关。
//
// 命名约定：名词用单数（device / config），动作作为子命令（list / alias / revoke）；
// 顶层只放"对整台网关"的动作，避免 `alias`、`revoke` 这类动词在顶层裸奔——
// 它们离开 `device` 之后语义会漂移（将来还要 revoke 别的对象）。
func newRootCmd() *cobra.Command {
	var configPath, publicOrigin string

	root := &cobra.Command{
		Use:           "dsh-auth-proxy",
		Short:         "dsh web gateway: supervisor, cookie broker and auth gate",
		Version:       version,
		SilenceUsage:  true, // 运行时错误不该再打一遍 usage
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		// 不带子命令时等价于 serve：保留 `dsh-auth-proxy` 直接启动的习惯，
		// 服务包装器（WinSW）也不必改参数。
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGateway(configPath, publicOrigin)
		},
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to gateway.toml (default: $DSH_HOME/gateway.toml)")
	root.PersistentFlags().StringVar(&publicOrigin, "public-origin", "", "external https origin, e.g. https://dsh.example.com (required unless set in config)")

	root.AddCommand(newServeCmd(&configPath, &publicOrigin))
	root.AddCommand(newInitCmd(&configPath))
	root.AddCommand(newConfigCmd(&configPath))
	root.AddCommand(newDeviceCmd(&configPath))
	root.AddCommand(newVersionCmd())

	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print the version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "dsh-auth-proxy version %s\n", version)
		},
	}
}
