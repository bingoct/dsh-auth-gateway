package cli

import (
	_ "embed"
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/spf13/cobra"
	"os"
)

// runConfigInit 把带注释的模板写到 gateway.toml；已有文件默认拒绝，--force 才覆盖。
func runConfigInit(configPath string, force bool) error {
	path := configPath
	if path == "" {
		path = config.DefaultConfigPath()
	}
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; edit it directly or pass --force to overwrite", path)
	}
	if err := os.MkdirAll(dirOf(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(configTemplate), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "配置模板已写入 %s（按注释改完再启动网关）\n", path)
	return nil
}

//go:embed config.example.toml
var configTemplate string

func newConfigCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "manage gateway.toml",
		Args:  cobra.NoArgs,
	}
	var force bool
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "write the annotated config template to gateway.toml",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfigInit(*configPath, force)
		},
	}
	initCmd.Flags().BoolVar(&force, "force", false, "overwrite an existing gateway.toml")
	cmd.AddCommand(initCmd)
	return cmd
}
