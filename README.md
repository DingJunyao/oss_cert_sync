# cert-uploader

把 Caddy 自动续期管理的 TLS 证书，自动同步（上传）到阿里云 OSS 自定义域名（CNAME 绑定），让 OSS 托管的静态域名（例如图片域名）始终使用最新证书，支持 HTTPS 访问，再也不用手动去阿里云控制台申请、下载、上传证书。

- **证书来源**：Caddy（Docker 容器或宿主机）自动签发/续期的证书，也支持任意 PEM 文件
- **上传方式**：阿里云 OSS `PutCname` 接口（内联证书 + `Force=true`，直接替换已绑定域名的证书）
- **运行环境**：普通 Linux 服务器即可，不需要 root（读 Docker 容器内证书用的是 `docker exec`）
- **变更检测**：证书内容 SHA-256 与上次上传一致就跳过；Caddy 每次续期后哈希变化会自动触发上传
- **上传后校验**：读取 OSS 侧证书指纹比对，可选读回验证

## 解决什么问题

典型场景：图片等静态资源放在阿里云 OSS，绑定自定义域名（如 `static.example.com`）。OSS 上的 HTTPS 证书要在阿里云控制台手动申请，每隔几个月到期一次，人工续期既麻烦又容易忘记（证书一过期，所有引用该域名的图片全部加载失败）。

而服务器上的 Caddy 已经用 DNS-01 验证签发了通配符证书（如 `*.a4ding.com`），完全可以覆盖这个域名。cert-uploader 把"Caddy 里的新证书"自动推送到 OSS，形成闭环：**Caddy 续期 → 哈希变化 → 定时任务发现 → 上传 OSS → 线上证书更新**。

## 工作原理

`cert-uploader sync` 每次运行时：

1. **发现证书**：通过 `docker exec`（或直接读文件）枚举 Caddy 存储目录 `certificates/<颁发机构>/<证书名>/` 下的所有证书；
2. **匹配目标**：解析每张证书的 SAN，按 "精确匹配 > 通配符匹配" 打分，多张可覆盖时取有效期最长（最新续期）的那张；
3. **校验**：证书与私钥公钥匹配、未过期、SAN 覆盖目标域名；无证书链或即将到期（<14 天）会告警；
4. **变更检测**：对 `证书 + 私钥` 计算 SHA-256，与 state 文件记录一致则跳过（`--force` 可强制上传）；
5. **上传**：调用 OSS `PutBucketCname`，内联 PEM 证书 + 私钥，`Force=true`（无 PreviousCertId 时必须）；
6. **验证**：读回 CNAME 证书信息，比对远端指纹与本地指纹（不一致仅告警）；
7. **记录状态**：写 state JSON（摘要、指纹、有效期、上传时间、来源、远端 cert_id），供下次去重与 `status` 查询。

## 目录结构

```
cert_uploader/
├── bin/cert-uploader          # 启动器（优先 .venv，否则 vendor/）
├── cert_uploader/             # Python 包
│   ├── certs.py               # 证书解析/匹配/指纹
│   ├── certsource.py          # 证书来源（docker exec / 本地目录 / 指定文件）
│   ├── config.py              # TOML 配置
│   ├── ossclient.py           # OSS PutCname 封装（重试）
│   ├── state.py               # 状态文件 + 文件锁
│   ├── cli.py                 # sync / status / doctor
│   ├── __main__.py
│   └── __init__.py
├── deploy/
│   ├── install.sh             # 服务器安装脚本
│   ├── cert-uploader.service  # systemd 服务
│   └── cert-uploader.timer    # systemd 定时器（每 15 分钟）
├── config.example.toml        # 配置样例
├── pyproject.toml
└── README.md
```

## 快速开始（服务器，无需 root）

前提：`python3 >= 3.11`，用户在 `docker` 组（能 `docker ps`）或可直接读 Caddy 存储目录。

```bash
# 1. 上传项目到服务器（本机执行）
scp -r cert_uploader/ 4ading:/home/ecs-user/cert-uploader
ssh 4ading

# 2. 安装依赖（Debian 12 无 python3-venv 时用 --target）
cd ~/cert-uploader
pip3 install --target vendor -i https://mirrors.aliyun.com/pypi/simple/ 'oss2>=2.18,<3' 'cryptography>=41'
# 或：./deploy/install.sh --app-dir ~/cert-uploader --config-dir ~/cert-uploader/config

# 3. 写配置
cp config.example.toml config.toml && chmod 600 config.toml
vi config.toml   # 改 region / domain / bucket

# 4. 凭据（推荐环境变量）
export OSS_ACCESS_KEY_ID=LTAI你的AK
export OSS_ACCESS_KEY_SECRET=你的SK

# 5. 体检
python3 -m cert_uploader doctor --config config.toml

# 6. 试运行（不真正上传）
python3 -m cert_uploader sync --config config.toml --dry-run

# 7. 正式上传
python3 -m cert_uploader sync --config config.toml

# 8. 定时任务（每 15 分钟）
crontab -e
# 7,22,37,52 * * * * /home/ecs-user/cert-uploader/bin/cert-uploader sync --config /home/ecs-user/cert-uploader/config.toml >> /home/ecs-user/cert-uploader/sync.log 2>&1
```

也可以直接跑安装脚本（root 时自动装 systemd timer，普通用户打印 crontab 行）：

```bash
./deploy/install.sh                       # 默认 /opt/cert-uploader + /etc/cert-uploader
./deploy/install.sh --no-systemd          # 不动 systemd
./deploy/install.sh --app-dir ~/apps/cert-uploader --config-dir ~/conf
```

## 配置说明

| 配置项 | 默认 | 说明 |
| --- | --- | --- |
| `source.type` | `caddy` | 目前仅支持 Caddy 存储布局；零散 PEM 文件用 target 的 `cert_file/key_file` |
| `source.access` | `docker` | `docker`=docker exec 读取；`local`=直接读文件（宿主机 Caddy 或 root） |
| `source.container` | `caddy` | Docker 容器名 |
| `source.storage` | `/data/caddy` | Caddy 数据卷内路径（容器内视角） |
| `aliyun.region` | 必填 | Bucket 所在区域，如 `cn-shanghai` |
| `aliyun.endpoint` | 自动 | 默认 `https://oss-<region>.aliyuncs.com` |
| `aliyun.access_key_id/secret` | 建议 env | 支持写 `"${OSS_ACCESS_KEY_ID}"` 从环境变量展开；建议留空用环境变量 |
| `[[target]].domain` | 必填 | 绑定到 Bucket 的自定义域名（小写） |
| `[[target]].bucket` | 必填 | Bucket 名 |
| `[[target]].endpoint` | 继承 | 单独覆盖该 Bucket 的 endpoint |
| `[[target]].cert_file/key_file` | 无 | 指定 PEM 文件来源（设置则该 target 不走全局 source；两者必须同时给） |
| `state_file` | 配置目录下 `state.json` | 变更检测状态；同目录会创建 `.lock` 防并发 |
| `upload_attempts` | `3` | 上传 API 重试次数 |
| `log_level` | `INFO` | 日志级别 |

多域名 = 多个 `[[target]]`，一次 `sync` 全部处理，单个失败不影响其他 target。

## 阿里云 RAM 权限（关键）

用于上传的 AK 对应的 RAM 子账号需要以下权限（DNS 解析权限不够！Caddy 用的那只 DNS AK 会被拒绝）：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "oss:PutCname",
        "oss:ListCname"
      ],
      "Resource": "acs:oss:*:*:4ading/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "yundun-cert:CreateSSLCertificate",
        "yundun-cert:DescribeSSLCertificatePrivateKey",
        "yundun-cert:DescribeSSLCertificatePublicKeyDetail"
      ],
      "Resource": "*"
    }
  ]
}
```

说明：

- OSS 内联证书实际由 SSL 证书服务（CAS）托管，所以 `oss:PutCname` 之外还需要 `yundun-cert:*` 三项；
- `Resource` 按需改成你的 bucket：`acs:oss:*:*:<bucket>/*`；
- 控制台路径：RAM 访问控制 → 用户 → 创建用户（勾选 OpenAPI 调用访问）→ 授权上述策略；
- 若报错 `EC=0003-00000905`（ImplicitDeny, ResourceGroupLevelIdentityBasedPolicy）：说明子账号被资源组隔离，需在**账号级别**授权，或把子账号加入 Bucket 所属资源组；
- `status`/`doctor` 只读操作需要 `oss:ListCname`。

## 定时执行

**方式一：systemd timer（推荐，root 安装）**，`deploy/install.sh` 自动完成，或手动：

```bash
install -m 644 deploy/cert-uploader.service /etc/systemd/system/
install -m 644 deploy/cert-uploader.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now cert-uploader.timer
systemctl list-timers cert-uploader.timer
journalctl -u cert-uploader.service -f      # 查看运行日志
```

凭据写进 `/etc/cert-uploader/env`（`chmod 600`，owner 与 service 的 `User` 一致）：

```
OSS_ACCESS_KEY_ID=LTAI...
OSS_ACCESS_KEY_SECRET=...
```

**方式二：crontab（无 root）**：见快速开始第 8 步，错开分钟避免整点拥堵。

Caddy 续期窗口是到期的 2/3 处（约每 60 天一次），15 分钟一轮的轮询足够及时；重复运行几乎零成本（哈希相同直接跳过）。

## CLI 参考

| 命令 | 作用 |
| --- | --- |
| `cert-uploader sync [--dry-run] [--force] [--no-verify] [--target DOMAIN]` | 同步证书；`--dry-run` 只看不上传；`--force` 忽略去重；`--target` 只处理指定域名（可多次） |
| `cert-uploader status` | 本地证书、状态文件、OSS 侧绑定与证书信息一览 |
| `cert-uploader doctor` | 体检：依赖、证书源、各 target 证书、OSS 凭据/权限、DNS |
| 通用：`--config PATH` | 指定配置（默认依次找 `CERT_UPLOADER_CONFIG` 环境变量、`./config.toml`、`/etc/cert-uploader/config.toml`、`~/.config/cert-uploader/config.toml`） |
| 通用：`-q` | 只输出错误 |

退出码：`0` 成功；`1` 一般错误（网络/OSS API 等）；`2` 配置错误；`3` 证书错误（不匹配/过期/不覆盖域名/找不到）。cron/监控可按退出码告警。

## 验证上传结果

```bash
# 命令行看
python3 -m cert_uploader status

# 线上验证（上传后 OSS 证书生效通常即时，个别情况几分钟）
curl -vI https://static.a4ding.com/
openssl s_client -connect static.a4ding.com:443 -servername static.a4ding.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| `AccessDenied ... EC=0003-00000905`（ImplicitDeny，ResourceGroupLevelIdentityBasedPolicy） | RAM 子账号被资源组隔离：改为账号级授权，或把子账号加入 Bucket 所在资源组 |
| `The bucket you access does not belong to you` | AK 没有该 Bucket 权限（例如只给了 DNS 权限），按上面 RAM 策略补授权 |
| `InvalidCertificate` / 上传 400 | 证书或私钥格式不对：确认为 PEM 全文（含 BEGIN/END 行）、证书链完整、证书与私钥匹配 |
| `no certificate found ... covers <domain>` | Caddy 还没给覆盖该域名的证书（未在 Caddyfile 中启用该站点/通配符）；或 `source.storage` 路径不对 |
| doctor 报 docker 相关错误 | 用户不在 docker 组：`sudo usermod -aG docker $USER` 重新登录；或改 `access = "local"` |
| 上传成功但浏览器仍旧证书 | OSS 证书生效有分钟级延迟；确认域名 CNAME 指向该 Bucket；清浏览器缓存 |
| `LockHeld` | 上一次运行还在进行（或异常残留锁文件），稍后重试；确认没有死循环的 cron |
| 私钥读取失败（docker exec） | Caddy 容器内证书 root:0600，必须走 `docker exec`（`access = "docker"`），不要直接挂载读取 |

## 安全注意事项

- **凭据最小化**：为上传单开一只 RAM 子账号，只授上述策略；不要复用 Caddy 的 DNS AK，也不要用主账号 AK；
- **私钥面**：证书私钥经由本工具上传到阿里云（OSS/CAS 托管），与控制台手动上传等价；本工具不落盘私钥（仅内存中转），state 文件只存哈希与指纹；
- **文件权限**：`config.toml`（若写有 AK）、`env` 文件一律 `chmod 600`；state/lock 文件默认 0600；
- **不要提交**：`.gitignore` 已排除 `config.toml`、`env`、`state.json*`；
- **传输安全**：与 OSS 的 API 通信全程 HTTPS。

## FAQ

**Q：不用 Caddy，只有一堆 PEM 文件行吗？**
行。给 target 配 `cert_file`/`key_file`（每次续期后重写这两个文件，工具按内容哈希检测变化）。配合 acme.sh 的 `--install-cert` 钩子或定时扫描均可。

**Q：多个域名/多个 Bucket？**
配多个 `[[target]]`。每张证书独立匹配、独立上传、独立记录状态。

**Q：宿主机直装的 Caddy（非 Docker）怎么配？**
`source.access = "local"`，`source.storage` 填 Caddy 数据目录（默认 `/var/lib/caddy/.local/share/caddy`），运行用户需有读权限。

**Q：会不会把 OSS 上的证书删掉？**
不会。工具从不调用删除证书接口（`delete_certificate` 固定为 false），只做替换（`Force=true`）。

**Q：怎么强制重传？**
`sync --force`。

**Q：Caddy 容器名/存储路径在哪看？**
`docker inspect <容器> | grep -A3 Mounts`，数据卷容器内路径一般是 `/data`，证书在其下 `caddy/certificates/...`，对应 `source.storage = "/data/caddy"`。

---

MIT License，见 [LICENSE](LICENSE)。
