package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// 主 help 必须列出 init：这是首次部署的必经步骤，藏在子命令里等于不存在。
// 这条断言锁住上一步手搓 flag 时踩过的坑。
func TestRootHelpListsInit(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	help := out.String()
	if !strings.Contains(help, "init") {
		t.Fatalf("root help must list init subcommand:\n%s", help)
	}
	if !strings.Contains(help, "--config") {
		t.Fatalf("root help must list --config:\n%s", help)
	}
	// 标准库 flag 的默认输出会带 os.Args[0] 绝对路径，cobra 不应再出现。
	if strings.Contains(help, `C:\`) || strings.Contains(help, "/home/") {
		t.Fatalf("help leaked an absolute path:\n%s", help)
	}
}

// init 子命令的参数解析：三个正交 flag + 全局 --config/--public-origin 都要能传进去，
// 且不触发真正的 runInit（那会写凭据文件）。
func TestInitFlagParsing(t *testing.T) {
	root := newRootCmd()
	initCmd, _, err := root.Find([]string{"init"})
	if err != nil || initCmd == nil {
		t.Fatalf("init subcommand missing: %v", err)
	}
	for _, flag := range []string{"password-stdin", "force", "password-only"} {
		if initCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("init must have --%s flag", flag)
		}
	}
	if initCmd.Flags().Lookup("password") != nil {
		t.Fatal("--password must be gone (replaced by --password-stdin)")
	}
	if root.PersistentFlags().Lookup("config") == nil {
		t.Fatal("root must have persistent --config flag")
	}
	if root.PersistentFlags().Lookup("public-origin") == nil {
		t.Fatal("root must have persistent --public-origin flag")
	}
	if _, _, err := root.Find([]string{"config", "init"}); err != nil {
		t.Fatalf("config init subcommand missing: %v", err)
	}
}

// 版本输出统一用 dsh-auth-proxy 这个名字，不再出现 dsh-gateway 的旧称。
func TestVersionOutput(t *testing.T) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "dsh-auth-proxy") {
		t.Fatalf("version output must use the shipped name: %q", got)
	}
	if strings.Contains(got, "dsh-gateway") {
		t.Fatalf("version output leaked internal module name: %q", got)
	}
}

// 命令树：设备相关动作必须挂在 device 下面；顶层旧名只作兼容壳。
// 如果哪天有人把 alias 又搬回顶层，这条会失败——语义漂移从这里开始。
func TestDeviceCommandTree(t *testing.T) {
	root := newRootCmd()

	dev, _, err := root.Find([]string{"device"})
	if err != nil || dev == nil || dev.Name() != "device" {
		t.Fatalf("device command missing: %v", err)
	}
	for _, name := range []string{"list", "alias", "revoke"} {
		c, _, err := root.Find([]string{"device", name})
		if err != nil || c == nil || c.Name() != name {
			t.Fatalf("device %s missing: %v", name, err)
		}
		if c.Deprecated != "" {
			t.Fatalf("device %s must not be deprecated", name)
		}
	}

	// 未发布阶段不留旧名：顶层 devices / alias / revoke 必须彻底不存在。
	// 留着兼容壳会让"命令该挂哪一层"这件事反复被拉扯。
	for _, gone := range []string{"devices", "alias", "revoke"} {
		if c, _, _ := root.Find([]string{gone}); c != nil && c.Name() == gone {
			t.Fatalf("top-level %q must not exist", gone)
		}
	}
}

// 不带子命令时等价于 serve：服务包装器的命令行里没有子命令，这条不能断。
func TestRootRunsGatewayByDefault(t *testing.T) {
	root := newRootCmd()
	if root.RunE == nil {
		t.Fatal("root must run the gateway when no subcommand is given")
	}
	if _, _, err := root.Find([]string{"serve"}); err != nil {
		t.Fatalf("serve subcommand missing: %v", err)
	}
}

// 根目录那份模板是给人看的，embed 的那份才是 `config init` 真正写出去的。
// 两份必须逐字节一致，否则改了文档模板却生成旧配置——这类偏差只有用户踩到才发现。
func TestEmbeddedTemplateMatchesRoot(t *testing.T) {
	want, err := os.ReadFile("../../config.example.toml")
	if err != nil {
		t.Fatalf("read root template: %v", err)
	}
	if string(want) != configTemplate {
		t.Fatal("config.example.toml 与 internal/cli/config.example.toml 不一致")
	}
}
