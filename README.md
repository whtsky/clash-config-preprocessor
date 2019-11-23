## Clash Config Preprocessor

Process multiple clash configure files , integrate them to single clash configure file.



### How to use

```bash
python main.py /path/to/preprocessor.config.yml > /path/to/config.yml
```

preprocessor.config.yml **NOT** clash configure



### example

preprocessor configure example

```yaml
# 针对预处理器的配置
preprocessor:
  version: 1                      # 目标预处理器版本号 目前仅能使用 1

# clash 的 基础配置
# 将会被放置在 输出文件 的 根节点
# 内容参见 https://github.com/Dreamacro/clash/blob/dev/README.md
clash-general:
  port: 1081
  socks-port: 1080
  #redir-port: 1081

  allow-lan: true
  mode: Rule
  log-level: info

  external-controller: '0.0.0.0:6170'
  secret: ''

  dns:
    enable: true # set true to enable dns (default is false)
    ipv6: true  # default is false
    listen: 0.0.0.0:1053
    enhanced-mode: redir-host
    nameserver:
      - 127.0.0.1:8053

# 代理数据来源
# 预处理器 将会从这些来源中读取代理信息 用于下面的 Proxy Group 生成
# 读取的文件 必须是 一个标准的 clash 配置文件
proxy-sources:
  - type: url
    url: "https://raw.githubusercontent.com/Kr328/clash-config-preprocessor/master/example/proxies.yml"
    udp: true # 对订阅中没有 udp 字段的服务器增加 udp，会导致不支持 udp 的服务器出错，请自行测试
    prefix: "xxcloud - " # 节点名称添加前缀
    suffix: " - xxcloud" # 节点名称添加后缀
    plugin: obfs         # 为订阅中没有混淆信息的订阅添加混淆（仅ss）
    plugin-opts:
      mode: tls
      host: download.windowsupdate.com

  - type: plain
    data:
      name: "ss1"
      type: ss
      server: server
      port: 443
      cipher: AEAD_CHACHA20_POLY1305
      password: "password"
      udp: true

# 代理组(Proxy Group) 生成规则
# 预处理器将会读取 *所有载入的代理信息*
# 并将其 分配到 输出文件 的 代理组
proxy-group-dispatch:
  - name: PROXY               # 代理组名称
    proxies-filters:          # 分配给代理组 的 过滤正则表达式
      black-regex: ".*vmess.*"   # 匹配到的代理 将不会分配到 此代理组
      white-regex: ".*ss.*"      # 匹配到的代理 将会分配到 此代理组
    flat-proxies:              # 强制某个代理组内的代理并加至最前
      - "vmess"
    back-flat-proxies:         # 强制某个代理组内的代理并加至最后
      - "socks"
    type: url-test            # 类型 参见 clash 配置
    url: "https://www.google.com/generate_204" # 测试 url 参见 clash 配置
    interval: 300             # 超时 参见 clash 配置

# 规则集
# 从外部载入一个规则集 并将其应用于规则
rule-sets:
  - name: lhie # 名称
    type: clash  # 类型
    source: url  # 来源，url 或 file
    url: 'https://raw.githubusercontent.com/lhie1/Rules/master/Clash/Rule.yml'  # 如果是 file 则需要 path
    target-map:             # 用于替换 单条规则 的 目标代理组 不需要请把该行一起删除，勿留空列表
      - 'AdBlock,REJECT'
      - 'Media,PROXY'
      - 'GlobalTV,PROXY'
      - 'AsianTV,DIRECT'
      - 'Domestic,DIRECT'
      - 'Proxy,PROXY'
    rule-skip:              # 跳过部分匹配 规则  不需要请把该行一起删除，勿留空列表
      - 'GEOIP'
      - 'MATCH'
    target-skip:            # 跳过部分目标代理组 不需要请把该行一起删除，勿留空列表
      - 'Final'
      - 'Others'

  - name: lhie-AD
    type: surge-ruleset
    source: url
    url: 'https://raw.githubusercontent.com/lhie1/Rules/master/Surge3/Reject.list'
    target: 'REJECT'

# 规则
# 将会 处理后 输出到 目标文件的 Rule
rule:
  - 'RULE-SET,lhie-AD'                      # 将会从上述规则集展开
  - 'RULE-SET,lhie'                      # 将会从上述规则集展开
  - 'DOMAIN-SUFFIX,google.com,PROXY'
  - 'DOMAIN-KEYWORD,google,PROXY'
  - 'DOMAIN,google.com,PROXY'
  - 'DOMAIN-SUFFIX,ad.com,REJECT'
  - 'IP-CIDR,127.0.0.0/8,DIRECT'
  - 'SOURCE-IP-CIDR,192.168.1.201/32,DIRECT'
  - 'GEOIP,CN,DIRECT'
  - 'MATCH,PROXY'
```



then output click [this](https://github.com/Kr328/clash-config-preprocessor/blob/master/example/example.output.yml)
