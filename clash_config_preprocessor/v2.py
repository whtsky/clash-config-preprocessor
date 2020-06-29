from clash_config_preprocessor.utils import safe_load_yaml
import requests
import re
from typing import List, Optional

supported_rules: dict = {
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "DOMAIN": "DOMAIN",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "GEOIP": "GEOIP",
    "SRC-IP-CIDR": "SRC-IP-CIDR",
    "SRC-IP-CIDR6": "SRC-IP-CIDR6",
    "DST-PORT": "DST-PORT",
    "SRC-PORT": "SRC-PORT",
    "PORT": "DST-PORT",
}


def handle_v2(data: dict) -> dict:
    result: dict = dict()

    general_block: dict = data["clash-general"]
    result.update(general_block)

    proxy_sources_dicts: list = data["proxy-sources"]
    proxies: list = []

    for item in proxy_sources_dicts:
        proxies += load_proxies(item)

    proxy_group_dispatch_dicts: list = data["proxy-group-dispatch"]
    proxy_groups: list = []

    for item in proxy_group_dispatch_dicts:
        group_data: dict = item.copy()
        ps: list = []

        if "flat-proxies" in item and item["flat-proxies"] is not None:
            ps += item["flat-proxies"]

        if "proxies-filters" in item and item["proxies-filters"] is not None:
            for filters in item["proxies-filters"]:
                if filters[0]["type"] == "plain":
                    for i in range(1, len(filters)):
                        ps.append(filters[i])
                    continue
                filters_init(filters)  # convert
                for p in proxies:
                    p_name: str = p["name"]
                    if proxy_filter(p_name, filters):
                        ps.append(p_name)

        if "back-flat-proxies" in item and item["back-flat-proxies"] is not None:
            ps += item["back-flat-proxies"]

        group_data.pop("proxies-filters", None)
        group_data.pop("flat-proxies", None)
        group_data.pop("back-flat-proxies", None)

        group_data["proxies"] = sorted(set(ps), key=ps.index)  # unique

        proxy_groups.append(group_data)

    rule_sets_dicts: list = data["rule-sets"]
    rule_sets: dict = {}

    if rule_sets_dicts:
        for item in rule_sets_dicts:
            item_name: str = item["name"]
            item_type: str = item["type"]
            if item_type == "clash":
                item_source: str = item["source"]
                item_map: dict = {}
                if item_source == "url":
                    rule_sets[item_name] = load_clash_url_rule_set(item["url"])
                elif item_source == "file":
                    rule_sets[item_name] = load_clash_file_rule_set(item["path"])

            elif item_type == "surge-ruleset":
                item_source: str = item["source"]
                item_target: str = item["target"]
                if item_source == "url":
                    rule_sets[item_name] = load_surge_url_rule_set(
                        item["url"], item_target
                    )
                elif item_source == "file":
                    rule_sets[item_name] = load_surge_file_rule_set(
                        item["path"], item_target
                    )

            if item.get("filters"):
                rule_sets[item_name] = rule_filter(
                    rule_sets[item_name], item["filters"]
                )
    rules: list = []

    for rule in data["rule"]:
        if str(rule).startswith("RULE-SET"):
            rules.extend(rule_sets[str(rule).split(",")[1]])
        else:
            rules.append(rule)

    result["proxies"] = proxies
    result["proxy-groups"] = proxy_groups
    result["rules"] = sorted(set(rules), key=rules.index)  # unique

    return result


def filters_init(filters):
    for filter in filters:
        if "pattern" in filter:
            filter["pattern"] = re.compile(filter["pattern"])
        if "target-map" in filter:
            maps = filter["target-map"]
            for i in range(len(maps)):
                maps[i] = maps[i].split(",")


def proxy_filter(name: str, filters):
    for filter in filters:
        if filter["type"] == "white-regex" and filter["pattern"].fullmatch(name):
            return True
        elif filter["type"] == "black-regex" and filter["pattern"].fullmatch(name):
            return False
    return False


def load_proxies(item):
    if item["type"] == "plain":
        return [item["data"]]
    if item["type"] == "url":
        data = requests.get(item["url"])
        data_yaml: dict = safe_load_yaml(data.content.decode())
    else:
        with open(item["path"], "r") as f:
            data_yaml: dict = safe_load_yaml(f)
    proxy_yaml = data_yaml["Proxy"]
    for p in proxy_yaml:
        if "udp" in item and "udp" not in p:
            p["udp"] = item["udp"]
        if "prefix" in item:
            p["name"] = item["prefix"] + p["name"]
        if "suffix" in item:
            p["name"] += item["suffix"]
        if p["type"] == "ss":
            if "plugin" in item and "plugin" not in p:
                p["plugin"] = item["plugin"]
                if "plugin-opts" in item:
                    p["plugin-opts"] = item["plugin-opts"]
    return proxy_yaml


def load_clash_data(data: dict) -> list:
    if "Rule" in data:
        return list(data["Rule"])
    if "rules" in data:
        return list(data["rules"])
    return []


def load_clash_url_rule_set(url: str) -> list:
    data = safe_load_yaml(requests.get(url).content)
    return load_clash_data(data)


def load_clash_file_rule_set(path: str) -> list:
    with open(path, "r") as f:
        data = safe_load_yaml(f)
    return load_clash_data(data)


def load_surge_url_rule_set(url: str, target: str):
    data = requests.get(url).text.splitlines()
    result: list = []

    for raw_rule in data:
        rule = raw_rule.split(",")
        if rule[0] in supported_rules:
            result.append(supported_rules[rule[0]] + "," + rule[1] + "," + target)

    return result


def load_surge_file_rule_set(path: str, target: str):
    with open(path, "r") as f:
        data = f.read()

    result: list = []

    for raw_rule in data:
        rule = raw_rule.split(",")
        if rule[0] in supported_rules:
            result.append(supported_rules[rule[0]] + "," + rule[1] + "," + target)

    return result


def rule_filter(rules: list, filters: list) -> list:
    filters_init(filters)
    filtered_rules = []
    for rule in rules:
        processed_rule = process_rule(rule, filters)
        if processed_rule:
            filtered_rules.append(processed_rule)
    return filtered_rules


def process_rule(rule_str: str, filters: list) -> Optional[str]:
    rule: List[str] = rule_str.split(",")
    for filter in filters:
        operation = filter["operation"]
        if check(rule, filter):
            if operation == "remove":
                return
            elif operation == "target-map":
                for mapping in filter["target-map"]:
                    if rule[2] == mapping[0]:
                        rule[2] = mapping[1]
            elif operation == "add-no-resolve":
                if rule[0] in {"IP-CIDR", "IP-CIDR6"} and len(rule) == 3:
                    rule.append("no-resolve")
        elif operation == "pick":
            return
    return ",".join(rule)


def check(rule: list, filter: dict) -> bool:
    if filter.get("type"):
        match = False
        for p in filter["type"]:
            if p == rule[0]:
                match = True
        if not match:
            return False

    if filter.get("pattern"):
        if not filter["pattern"].fullmatch(rule[1]):
            return False

    if len(rule) > 2 and filter.get("target"):
        match = False
        for p in filter["target"]:
            if p == rule[2]:
                match = True
        if not match:
            return False

    return True
