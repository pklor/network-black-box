from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set

# if the src_ip hits more than 20 dst_port, then its a portscan
# wathes for bruteforce login attempts from the port 21, 22, 23, & 3389
# if one source has more than 30 flow, then it sends an alert
# if source makes over 200 dns queries, then it's dns spike
# all the rules thresholds in one place
@dataclass
class Detect:
    portscan_ports: int = 20

    bruteforce_ports: Set[int] = field(
        default_factory=lambda: {21, 22, 23, 3389}
    )
    bruteforce_attempts: int = 30

    dns_spike_queries: int = 200

# internal_subnets creates a list of ranges as range to know what's inside the network
# sus_ports are ports that are treated as sus ports just for being used
# output_dir is used to where the reports/evidence would go
# flow_idle_timeout_sec is when the flow stopped over 60 sec then ingestion will close and write to db
# thresholds uses class Detect, so it gives all the rule number
# everything my tool needs to know about ports, thresholds, and timeouts
@dataclass
class BlackboxConfig:
    internal_subnets: List[str] = field(
        default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8"]
    )
    sus_ports: Set[int] =field(default_factory=lambda: {23, 4444, 6667})
    output_dir: Path = Path("output")
    flow_idle_timeout_sec: int = 60
    thresholds: Detect = field(default_factory=Detect)

# how the rest of the code gets config
def load_config() -> BlackboxConfig:
    return BlackboxConfig()