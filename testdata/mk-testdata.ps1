<#
  从生产配置派生隔离测试配置，输出到 %TEMP%\dsh-gateway-test\。

  凭据只在临时目录落地：项目目录里不留 password_hash / totp_secret_b32 的副本。

  用法：
    powershell -ExecutionPolicy Bypass -File .\testdata\mk-testdata.ps1
#>
$ErrorActionPreference = 'Stop'

$src = Join-Path $env:USERPROFILE '.dsh\gateway.toml'
if (-not (Test-Path $src)) { throw "missing source config: $src" }

$outDir = Join-Path $env:TEMP 'dsh-gateway-test'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$text = Get-Content -LiteralPath $src -Raw

$mockUrl = Join-Path $outDir 'mock-url.txt'
[IO.File]::WriteAllText($mockUrl, "dsh web: http://127.0.0.1:54321/?token=testlaunchtoken123`n", [Text.UTF8Encoding]::new($false))
Write-Host "wrote $mockUrl"

function New-Variant {
    param([string]$Name, [int]$Port, [string]$LocalCidrs, [bool]$Attach)
    $t = $text
    $t = $t -replace '(?m)^listen_host\s*=\s*"[^"]*"', 'listen_host = "127.0.0.1"'
    $t = $t -replace '(?m)^listen_port\s*=\s*\d+', "listen_port = $Port"
    $t = $t -replace '(?m)^local_cidrs\s*=\s*"[^"]*"', "local_cidrs = `"$LocalCidrs`""
    $t = $t -replace '(?m)^trust_proxy\s*=\s*\w+', 'trust_proxy = false'
    $t = $t -replace '(?m)^attach\s*=\s*\w+', "attach = $($Attach.ToString().ToLower())"
    if ($Attach) {
        $mockUrlPath = $mockUrl -replace '\\', '/'
        $t = $t -replace '(?m)^token_file\s*=\s*"[^"]*"', "token_file = `"$mockUrlPath`""
    }
    $path = Join-Path $outDir "$Name.toml"
    [IO.File]::WriteAllText($path, $t, [Text.UTF8Encoding]::new($false))
    Write-Host "wrote $path"
}

# probe：本机不免认证，用于跑认证门禁断言
New-Variant -Name 'probe' -Port 34099 -LocalCidrs '10.255.255.255/32' -Attach $false
# spawn：本机免认证，用于验证真实拉起
New-Variant -Name 'spawn' -Port 34101 -LocalCidrs '127.0.0.0/8,::1/128' -Attach $false
# attach：本机免认证，配合 mock 后端
New-Variant -Name 'attach' -Port 34102 -LocalCidrs '127.0.0.0/8,::1/128' -Attach $true
