## Clash Config Preprocessor

Process multiple clash configure files , integrate them to single clash configure file.

### How to use

```bash
pipx install clash_config_preprocessor
clash_config_preprocessor /path/to/preprocessor.config.yml -o /path/to/config.yml
```

preprocessor.config.yml **NOT** clash configure

### example

preprocessor configure example v2

```yaml
# 针对预处理器的配置
preprocessor:
  version: 2 # 目标预处理器版本号 目前有 1 和 2

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

  external-controller: "0.0.0.0:6170"
  secret: ""

  dns:
    enable: true # set true to enable dns (default is false)
    ipv6: true # default is false
    listen: 0.0.0.0:1053
    enhanced-mode: redir-host
    nameserver:
      - 127.0.0.1:8053

# 代理数据来源
# 预处理器 将会从这些来源中读取代理信息 用于下面的 Proxy Group 生成
# 读取的文件 必须是 一个标准的 clash 配置文件
proxy-sources:
  - type: url
    url: "https://raw.githubusercontent.com/Howard-00/clash-config-preprocessor/master/example/proxies.yml"
    udp: true # 对订阅中没有 udp 字段的服务器增加 udp，会导致不支持 udp 的服务器出错，请自行测试
    prefix: "xxcloud - " # 节点名称添加前缀
    suffix: " - xxcloud" # 节点名称添加后缀
    plugin: obfs # 为订阅中没有混淆信息的订阅添加混淆（仅ss）
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
# 把 black-regex
# 替换为 - - type: black-regex\n          pattern:
# 把 white-regex:
# 替换为   - type: white-regex\n          pattern:
# \n 是换行 可以实现简单的迁移
proxy-group-dispatch:
  - name: ✈️ Proxy # 代理组名称
    proxies-filters: # 分配给代理组 的 过滤器，目前支持 black-regex 和 white-regex，越靠前的优先级越高
      # 一个节点被重复匹配会去重，保留它第一次匹配的位置

      - - type: white-regex
          pattern: ".*" # 匹配到的代理 将会分配到 此代理组
        - type: black-regex
          pattern: ".*高倍率.*" # 匹配到的代理 将不会分配到 此代理组

      - - type: white-regex # 可以弄多组过滤器，用来控制顺序
          pattern: ".*高倍率.*"

    flat-proxies: # 强制某个代理组内的代理并加至最前
      - "vmess"
    back-flat-proxies: # 强制某个代理组内的代理并加至最后
      - "socks"
    type: fallback # 类型 参见 clash 配置
    url: "https://www.google.com/generate_204" # 测试 url 参见 clash 配置
    interval: 300 # 超时 参见 clash 配置

  - name: "🌑 Others"
    type: select
    flat-proxies: ["✈️ Proxy", "DIRECT"]

# 规则集
# 从外部载入一个规则集 并将其应用于规则
rule-sets:
  - name: ConnersHua_domains # 名称，在 Rule 中使用 RULE-SET,<name> 即可展开
    type: clash # 类型，目前支持 clash 和 surge-ruleset
    source: url # 来源，url 和 file
    url: "https://raw.githubusercontent.com/ConnersHua/Profiles/master/Clash/Pro.yaml" # 如果是 file， 则需要填写 path
    filters:
      - operation: remove # 操作，目前支持 pick, remove, target-map, add-no-resolve，匹配成功后将执行
        type: # 有三种过滤，type 和 target 是对规则类型和目标的完整匹配，采用列表的方式，可以写多条。
          - IP-CIDR # 而 patter 是对规则模版的匹配，使用正则表达式，没写的类型默认匹配成功
          - IP-CIDR6 # 这些过滤器按顺序执行，执行过 target-map 后目标会立即被修改并用于下一个过滤器的匹配
      - operation: remove
        type:
          - GEOIP
        pattern: "CN"
        target:
          - "DIRECT"

      - operation: remove
        type:
          - MATCH

      - operation: target-map
        target-map:
          - "PROXY,✈️ Proxy"
          - "Apple,🍎 Apple"
          - "GlobalMedia,📺 GlobalMedia"
          - "HKMTMedia,🎬 HKMTMedia"
          - "Hijacking,🚫 Hijacking"

      - operation: add-no-resolve
  - name: ConnersHua_ips
    type: clash
    source: url
    url: "https://raw.githubusercontent.com/ConnersHua/Profiles/master/Clash/Pro.yaml" # 如果是 file， 则需要填写 path
    filters:
      - operation: target-map
        target-map:
          - "PROXY,✈️ Proxy"
          - "Apple,🍎 Apple"
          - "GlobalMedia,📺 GlobalMedia"
          - "HKMTMedia,🎬 HKMTMedia"
          - "Hijacking,🚫 Hijacking"
      - operation: pick
        type:
          - IP-CIDR
          - IP-CIDR6
  - name: lhie-AD
    type: surge-ruleset # 目前仅支持 surge 的 list 规则
    source: url
    url: "https://raw.githubusercontent.com/lhie1/Rules/master/Surge3/Reject.list"
    target: "REJECT"

# 规则
# 将会 处理后 输出到 目标文件的 Rule
rule:
  - "RULE-SET,lhie-AD" # 将会从上述规则集展开
  - "RULE-SET,ConnersHua_domains" # 将会从上述规则集展开
  - "DOMAIN-SUFFIX,google.com,✈️ Proxy"
  - "DOMAIN-KEYWORD,google,✈️ Proxy"
  - "DOMAIN,google.com,✈️ Proxy"
  - "DOMAIN-SUFFIX,ad.com,REJECT"
  - "RULE-SET,ConnersHua_ips" # 将会从上述规则集展开
  - "IP-CIDR,127.0.0.0/8,DIRECT"
  - "SOURCE-IP-CIDR,192.168.1.201/32,DIRECT"
  - "GEOIP,CN,DIRECT"
  - "MATCH,✈️ Proxy"
```
