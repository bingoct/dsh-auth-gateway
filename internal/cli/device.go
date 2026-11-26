package cli

import (
	"fmt"
	"github.com/bingoct/dsh-auth-gateway/internal/audit"
	"github.com/bingoct/dsh-auth-gateway/internal/auth"
	"github.com/bingoct/dsh-auth-gateway/internal/config"
	"github.com/spf13/cobra"
	"os"
	"strings"
)

// ledgerFor 只加载配置来定位设备台账，不校验凭据、不起网关。
// 台账路径来自配置；CLI 直接读写这个文件，与运行中的网关共享同一份状态。
func ledgerFor(configPath string) (*auth.Ledger, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return auth.NewLedger(cfg.SessionStorePath, auth.PolicyFromConfig(cfg)), nil
}

func runDeviceList(configPath string) error {
	ledger, err := ledgerFor(configPath)
	if err != nil {
		return err
	}
	devices := ledger.List("")
	if len(devices) == 0 {
		fmt.Fprintln(os.Stderr, "没有有效设备")
		return nil
	}
	fmt.Printf("%s%s%s%s%s\n",
		padRight("FAMILY", 14), padRight("设备", 26), padRight("IP 段", 26),
		padRight("类型", 8), "最近使用")
	for _, d := range devices {
		kind := "临时"
		if d.Persist {
			kind = "持久"
		}
		name := d.Device
		if d.Alias != "" {
			name = d.Alias
		}
		fmt.Printf("%s%s%s%s%s\n",
			padRight(shortID(d.FamilyID), 14), padRight(name, 26), padRight(d.IP, 26),
			padRight(kind, 8), d.LastSeen.Local().Format("01-02 15:04"))
	}
	fmt.Fprintf(os.Stderr, "\n共 %d 台。起别名: dsh-auth-proxy device alias --family <FAMILY> --name <名字>\n撤销单台: dsh-auth-proxy device revoke --family <FAMILY>\n", len(devices))
	return nil
}

func runDeviceAlias(configPath, familyID, name string) error {
	if familyID == "" {
		return fmt.Errorf("use --family <id>")
	}
	ledger, err := ledgerFor(configPath)
	if err != nil {
		return err
	}
	target, ok := resolveFamily(ledger, familyID)
	if !ok || !ledger.SetAlias(target, name) {
		return fmt.Errorf("no session matched %q", familyID)
	}
	if strings.TrimSpace(name) == "" {
		fmt.Fprintf(os.Stderr, "已清除 %s 的别名\n", shortID(target))
		return nil
	}
	fmt.Fprintf(os.Stderr, "已把 %s 命名为 %q\n", shortID(target), strings.TrimSpace(name))
	return nil
}

// resolveFamily 支持用 devices 列表里的短 ID 前缀匹配。
func resolveFamily(l *auth.Ledger, prefix string) (string, bool) {
	if len(prefix) >= 22 {
		return prefix, true
	}
	for _, d := range l.List("") {
		if strings.HasPrefix(d.FamilyID, prefix) {
			return d.FamilyID, true
		}
	}
	return prefix, false
}

func runDeviceRevoke(configPath, familyID string, all bool) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}
	ledger := auth.NewLedger(cfg.SessionStorePath, auth.PolicyFromConfig(cfg))
	alog := audit.New(cfg.AuditLogPath)
	switch {
	case all:
		n := ledger.RevokeAll()
		alog.Log(audit.Event{Event: audit.EvRevoke, OK: true, Detail: fmt.Sprintf("all records=%d", n)})
		fmt.Fprintf(os.Stderr, "已撤销 %d 条记录（所有设备需重新登录）\n", n)
	case familyID != "":
		// 支持用 devices 列表里的短 ID 前缀匹配。
		target := familyID
		if len(familyID) < 22 {
			for _, d := range ledger.List("") {
				if strings.HasPrefix(d.FamilyID, familyID) {
					target = d.FamilyID
					break
				}
			}
		}
		if !ledger.Revoke(target) {
			return fmt.Errorf("no session matched %q", familyID)
		}
		alog.Log(audit.Event{Event: audit.EvRevoke, OK: true,
			Family: audit.ShortFamily(target), Detail: "device revoked"})
		fmt.Fprintf(os.Stderr, "已撤销该设备；它下次请求需要重新登录\n")
	default:
		return fmt.Errorf("use --family <id> or --all")
	}
	return nil
}

func shortID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:10]
}

// ---- 命令 ----
//
// 三个动作都挂在 `device` 下面。顶层不放裸动词：`alias`、`revoke` 离开
// 设备这个语境之后语义会漂移（将来还要 revoke 别的东西）。

func newDeviceCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "manage signed-in devices",
		// 不加 "devices" 别名：名词和动作不是一个东西。`devices` 是列设备的
		// 旧称，已经废弃；把它挂成别名会让 `dsh-auth-proxy devices` 打印帮助
		// 而不是报错，脚本会静默失效。
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newDeviceListCmd(configPath))
	cmd.AddCommand(newDeviceAliasCmd(configPath))
	cmd.AddCommand(newDeviceRevokeCmd(configPath))
	return cmd
}

func newDeviceListCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "list signed-in devices",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceList(*configPath)
		},
	}
}

func newDeviceAliasCmd(configPath *string) *cobra.Command {
	var family, name string
	cmd := &cobra.Command{
		Use:   "alias",
		Short: "set or clear a friendly name for a device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceAlias(*configPath, family, name)
		},
	}
	cmd.Flags().StringVar(&family, "family", "", "family id (a short prefix from `device list` is enough)")
	cmd.Flags().StringVar(&name, "name", "", "name shown in `device list`; pass an empty string to clear")
	return cmd
}

func newDeviceRevokeCmd(configPath *string) *cobra.Command {
	var family string
	var all bool
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "revoke one session family or every session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDeviceRevoke(*configPath, family, all)
		},
	}
	cmd.Flags().StringVar(&family, "family", "", "family id to revoke (omit with --all)")
	cmd.Flags().BoolVar(&all, "all", false, "revoke every session")
	return cmd
}
