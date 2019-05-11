from collections import OrderedDict

import yaml
import yaml.resolver


def setup_order_yaml():
    def represent_dict_order(self, data):
        return self.represent_mapping('tag:yaml.org,2002:map', data.items())

    def constructor_dict_order(self, node):
        return OrderedDict(self.construct_pairs(node))

    yaml.add_representer(OrderedDict, represent_dict_order)
    yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, constructor_dict_order)


class ParseException(Exception):
    def __init__(self, message: str):
        self.message = message
