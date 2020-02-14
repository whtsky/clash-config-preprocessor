import pytest
from clash_config_preprocessor.utils import safe_load_yaml
from clash_config_preprocessor.v2 import rule_filter


@pytest.mark.parametrize(
    "filters",
    [
        """
filters:
- operation: remove
  target:
    - "B"
- operation: target-map
  target-map:
    - "A,1"
    - "B,2"
    - "C,3"
    - "D,4"
- operation: pick
  type:
    - IP-CIDR
""",
        """
filters:
- operation: remove
  target:
    - "B"
- operation: target-map
  target-map:
    - "A,1"
    - "B,2"
    - "C,3"
    - "D,4"
- operation: remove
  type:
    - IP-CIDR
""",
    ],
)
def test_rule_filter(filters, snapshot):
    rules = [
        "DOMAIN-SUFFIX,local,A",
        "IP-CIDR,101.227.0.0/16,B",
        "IP-CIDR,11.22.33.44/16,D",
        "MATCH,C",
    ]
    snapshot.assert_match(rule_filter(rules, safe_load_yaml(filters)["filters"]))
