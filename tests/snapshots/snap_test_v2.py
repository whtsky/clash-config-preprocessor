# -*- coding: utf-8 -*-
# snapshottest: v1 - https://goo.gl/zC4yUc
from __future__ import unicode_literals

from snapshottest import Snapshot


snapshots = Snapshot()

snapshots[
    'test_rule_filter[ filters: - operation: remove target: - "B" - operation: target-map target-map: - "A,1" - "B,2" - "C,3" - "D,4" - operation: pick type: - IP-CIDR ] 1'
] = ["IP-CIDR,11.22.33.44/16,4"]

snapshots[
    'test_rule_filter[ filters: - operation: remove target: - "B" - operation: target-map target-map: - "A,1" - "B,2" - "C,3" - "D,4" - operation: remove type: - IP-CIDR ] 1'
] = ["DOMAIN-SUFFIX,local,1"]
