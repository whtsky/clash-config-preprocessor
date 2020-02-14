from typing import IO
import yaml

import yaml
import yaml.resolver


class ParseException(Exception):
    def __init__(self, message: str):
        self.message = message


def safe_load_yaml(f: IO) -> dict:
    return yaml.load(f, Loader=yaml.SafeLoader)


def process_config(f: IO) -> str:
    data: dict = safe_load_yaml(f)
    if data["preprocessor"]["version"] == 1:

        from clash_config_preprocessor.v1 import handle_v1

        result = handle_v1(data)
    elif data["preprocessor"]["version"] == 2:
        from clash_config_preprocessor.v2 import handle_v2

        result = handle_v2(data)
    else:
        raise Exception("Unsupported versoin")

    thedumper = yaml.Dumper
    thedumper.ignore_aliases = lambda self, data: True

    return yaml.dump(result, default_flow_style=False, Dumper=thedumper)


def setup_order_yaml():
    def constructor_dict_order(self, node):
        return dict(self.construct_pairs(node))

    yaml.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, constructor_dict_order
    )
