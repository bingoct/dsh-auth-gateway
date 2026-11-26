// 假 dsh web：给 gateway 的 spawn 路径做集成测试。
// 行为对齐真 dsh 的三件事：打印带 token 的 URL、用 token 换 303 + Set-Cookie、把 cookie 回显出来。
//
// 参数（由 gateway 传入）：--profile= --no-open --host= --port=
// 环境变量：FAKE_DSH_MODE=silent 只挂起不打印 token；=crash 就绪后 300ms 退出。
const http = require('http');

const argv = process.argv.slice(2);
const pick = (name) => {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : '';
};

const wantPort = parseInt(pick('port') || '0', 10);
const mode = process.env.FAKE_DSH_MODE || '';

if (mode === 'error') {
  // 模拟启动即崩溃：stderr 带唯一标记，供失败页断言。
  process.stderr.write('FAKE_BOOT_FAILURE: cannot open profile\n');
  process.exit(1);
}

if (mode === 'silent') {
  // 不打印 token，模拟启动卡住，用于测就绪超时。
  setInterval(() => {}, 1000);
} else {
  const srv = http.createServer((req, res) => {
    if (req.url.startsWith('/?token=')) {
      res.writeHead(303, {
        Location: './',
        'Set-Cookie': `dsh-auth-FAKE=v1-${Math.random().toString(36).slice(2, 10)}; Path=/; HttpOnly`,
      });
      res.end();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(
      `FAKE_DSH path=${req.url.split('?')[0]} cookie=${req.headers.cookie || ''}`
    );
  });

  srv.listen(wantPort, '127.0.0.1', () => {
    const port = srv.address().port;
    process.stdout.write(`dsh web: http://127.0.0.1:${port}/?token=fakelaunchtoken\n`, () => {
      if (mode === 'crash') {
        setTimeout(() => process.exit(1), 300);
      }
    });
  });
}
