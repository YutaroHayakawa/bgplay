# bgplay

`bgplay` is a tool (and golang library) to record the BGP messages and replay
it later. This is useful for crafting the test cases with the real BGP message
for your BGP implementation. Instead of doing complicated lab setup for every
CI run, you can manually record the BGP messages from the real lab once and
just replay it for your CI.

## How to use

### Recording BGP messages

Please setup the peer appropreately and make a peer with the `record` command.
Once the capture is done, just hit the Ctrl-C to finish it.

```
$ bgplay record test.bgpcap --local-asn 65001 --peer-addr 127.0.0.1 --router-id 10.0.0.1 test.bgpcap
Recording BGP messages
BGP Open:
  Version: 4
  MyAS: 65001
  HoldTime: 3
  RouterID: 192.168.64.5
  Capabilities:
    Option Capability:
        multiprotocol
    Option Capability:
        route-refresh
<skipped...>
BGP Update:
  Updated Routes:
    172.20.20.0/24
  Withdrawn Routes:
  Path Attributes:
    {Origin: ?}
    {AsPath: }
    {Nexthop: 127.0.0.1}
    {Med: 0}
    {LocalPref: 100}
  Path Attribute Flags:
<skipped...>
BGP Update (End of RIB):
  Family: ipv4-unicast
```

### Dump the recorded BGP messages

You can dump the recorded BGP messages from the file with the `report` command.

```
$ bgplay report test.bgpcap
BGP Open:
  Version: 4
  MyAS: 65001
  HoldTime: 3
  RouterID: 192.168.64.5
  Capabilities:
    Option Capability:
        multiprotocol
    Option Capability:
        route-refresh
<skipped...>
BGP Update:
  Updated Routes:
    172.20.20.0/24
  Withdrawn Routes:
  Path Attributes:
    {Origin: ?}
    {AsPath: }
    {Nexthop: 127.0.0.1}
    {Med: 0}
    {LocalPref: 100}
  Path Attribute Flags:
<skipped...>
BGP Update (End of RIB):
  Family: ipv4-unicast
```

### Replay the recorded BGP messages

You can replay the recorded BGP messages from the file with the `replay` command.

```
$ bplay replay --peer-addr 127.0.0.1 test.pcap
```
