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
# Clash Config Preprocessor

preprocessor:
  version: 1                      # preprocesspr config version

clash-general: # clash config output root ,see also https://github.com/Dreamacro/clash/blob/dev/README.md
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

proxy-sources:   # load all proxy from clash configure file
  - type: url
    url: "https://raw.githubusercontent.com/Kr328/clash-config-preprocessor/master/example/proxies.yml"
  - type: file
    path: "/path/to/config.yml"
  - type: plain
    data: 
      name: "ss1"
      type: ss
      server: server
      port: 443
      cipher: AEAD_CHACHA20_POLY1305
      password: "password"
  
proxy-group-dispatch:
  - name: PROXY               # name
    proxies-filters:          # load from proxy-source
      black-regex: ".*vmess.*"
      white-regex: ".*ss.*"
    flat-proxies:                  # for hardcode proxies ,will *NOT* filter by filters
      - "vmess"
    type: url-test            # type
    url: "https://www.google.com/generate_204"
    interval: 300             # interval

rule-sets: # load rules from url and map target
  - name: lhie
    type: url
    url: 'https://raw.githubusercontent.com/lhie1/Rules/master/Clash/Rule.yml'
    target-map:             # replace target proxy group, "SOURCE,TARGET"
      - 'AdBlock,REJECT'
      - 'Media,PROXY'
      - 'GlobalTV,PROXY'
      - 'AsianTV,DIRECT'
      - 'Domestic,DIRECT'
      - 'Proxy,PROXY'

rule:
  - 'RULE-SET,lhie'                      # will expend from rule-set
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



