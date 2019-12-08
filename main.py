#!/usr/bin/env python3
from collections import OrderedDict

import sys
import yaml
import utils
import v1
import v2

_HELP_TEXT = """\
Usage: python main.py <source-path>
    <source-path>: path to clash config preprocessor config

See also:
    https://github.com/Howard-00/clash-config-preprocessor
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
    elif data["preprocessor"]["version"] == 2:
        result = v2.handle_v2(data)
    else:
        print("Unsupported version")
        return

    thedumper = yaml.Dumper
    thedumper.ignore_aliases = lambda self, data: True

    print(yaml.dump(result, default_flow_style=False, Dumper=thedumper))


if __name__ == "__main__":
    main()
