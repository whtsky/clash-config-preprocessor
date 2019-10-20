#!/usr/bin/env python3
from collections import OrderedDict

import sys
import yaml
import utils
import v1

_HELP_TEXT = """\
Usage: python main.py <source-path>
    <source-path>: path to clash config preprocessor config

See also:
    https://github.com/Kr328/clash-config-preprocessor
"""


def main():
    utils.setup_order_yaml()

    if len(sys.argv) != 2:
        print("Argument source required")
        print(_HELP_TEXT)
        return

    with open(sys.argv[1], "r") as f:
        data: OrderedDict = yaml.load(f, Loader=yaml.Loader)

    if data["preprocessor"]["version"] == 1:
        result = v1.handle_v1(data)
    else:
        print("Unsupported version")
        return

    print(yaml.dump(result, default_flow_style=False))


if __name__ == "__main__":
    main()
