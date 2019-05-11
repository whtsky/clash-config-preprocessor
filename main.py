from collections import OrderedDict

import sys
import yaml
import utils
import v1


def main():
    utils.setup_order_yaml()

    if len(sys.argv) != 2:
        print("Argument source required")
        return

    with open(sys.argv[1], "r") as f:
        data: OrderedDict = yaml.load(f, Loader=yaml.Loader)

    if data["preprocessor"]["version"] == 1:
        result = v1.handle_v1(data)
    else:
        result = None
        print("Unsupported version")

    print(yaml.dump(result, default_flow_style=False))


if __name__ == "__main__":
    main()
