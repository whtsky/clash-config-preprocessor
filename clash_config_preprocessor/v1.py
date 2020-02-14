import requests
from clash_config_preprocessor.utils import ParseException, safe_load_yaml
import re

supported_rules: dict = {
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "DOMAIN": "DOMAIN",
    "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
    "DOMAIN-SUFFIX": "DOMAIN-SUFFIX",
    "GEOIP": "GEOIP",
}


def handle_v1(data: dict) -> dict:
    preprocessor: dict = data["preprocessor"]

    if preprocessor is None or preprocessor["version"] != 1:
        raise ParseException("Version != 1")

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

        black_regex = re.compile(item["proxies-filters"]["black-regex"])
        white_regex = re.compile(item["proxies-filters"]["white-regex"])

        flat_proxies: set = set()
        back_flat_proxies: set = set()
        if "flat-proxies" in item and item["flat-proxies"] is not None:
            flat_proxies = set(item["flat-proxies"])
            ps += item["flat-proxies"]
        if "back-flat-proxies" in item and item["back-flat-proxies"] is not None:
            back_flat_proxies = set(item["back-flat-proxies"])
        for p in proxies:
            p_name: str = p["name"]
            if (
                white_regex.fullmatch(p_name)
                and not black_regex.fullmatch(p_name)
                and p_name not in flat_proxies
                and p_name not in back_flat_proxies
            ):
                ps.append(p_name)

        if "back-flat-proxies" in item and item["back-flat-proxies"] is not None:
            ps += item["back-flat-proxies"]

        group_data.pop("proxies-filters", None)
        group_data.pop("flat-proxies", None)
        group_data.pop("back-flat-proxies", None)

        group_data["proxies"] = ps

        proxy_groups.append(group_data)

    rule_sets_dicts: list = data["rule-sets"]
    rule_sets: dict = {}

    if not rule_sets_dicts is None:
        for item in rule_sets_dicts:
            item_name: str = item["name"]
            item_type: str = item["type"]
            if item_type == "clash":
                item_source: str = item["source"]
                item_map: dict = {}
                item_rule_skip = item.get("rule-skip", {})
                item_target_skip = item.get("target-skip", {})
                for target_map_element in item.get("target-map", {}):
                    kv: list = target_map_element.split(",")
                    item_map[kv[0]] = kv[1]

                if item_source == "url":
                    rule_sets[item_name] = load_clash_url_rule_set(
                        item["url"], item_map, item_rule_skip, item_target_skip
                    )
                elif item_source == "file":
                    rule_sets[item_name] = load_clash_file_rule_set(
                        item["path"], item_map, item_rule_skip, item_target_skip
                    )

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

    rules: list = []

    for rule in data["rule"]:
        if str(rule).startswith("RULE-SET"):
            rules.extend(rule_sets[str(rule).split(",")[1]])
        else:
            rules.append(rule)

    result["Proxy"] = proxies
    result["Proxy Group"] = proxy_groups
    result["Rule"] = rules

    return result


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


def load_clash_url_rule_set(
    url: str, targetMap: dict, skipRule: set, skipTarget: set
) -> list:
    data = safe_load_yaml(requests.get(url).content)
    result: list = []

    for rule in data["Rule"]:
        original_target = str(rule).split(",")[-1]
        map_to: str = targetMap.get(original_target)
        if (
            str(rule).split(",")[0] not in skipRule
            and original_target not in skipTarget
        ):
            if not map_to is None:
                result.append(str(rule).replace(original_target, map_to))
            else:
                result.append(str(rule))

    return result


def load_clash_file_rule_set(
    path: str, targetMap: dict, skipRule: set, skipTarget: set
) -> list:
    with open(path, "r") as f:
        data = safe_load_yaml(f)
    result: list = []

    for rule in data["Rule"]:
        original_target = str(rule).split(",")[-1]
        map_to: str = targetMap.get(original_target)
        if (
            str(rule).split(",")[0] not in skipRule
            and original_target not in skipTarget
        ):
            if not map_to is None:
                result.append(str(rule).replace(original_target, map_to))
            else:
                result.append(rule)

    return result


def load_surge_url_rule_set(url: str, target: str):
    data = requests.get(url).text.splitlines()
    result: list = []

    for raw_rule in data:
        rule = raw_rule.split(",")
        if rule[0] in supported_rules:
            result.append(supported_rules[rule[0]] + "," + rule[1] + "," + target)
        # else:
        # print('# ' + raw_rule)

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
