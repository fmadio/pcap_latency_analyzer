# pcap_diff
pcap_diff is a simple packet capture analysis tool used to extract time difference between the same packets in 2 different pcap files. 

An example situation is calculating the latency profile of a switch/or other network device where the same packet is recorded with a highly accurate hardware timestamped packet capture device both before the network device and after it.  Using this script a simple text based latency statistics and histogram can be generated.

Command line options 

```
Options:
 --packet-trace        | write each packet events to stdout
 --tcp-length <number> | filter tcp packets to include only payload length of <number>
 --tcp-only            | only match tcp packets
 --udp-only            | only match udp packets
 --full-packet         | use entire packet contents for hash (.e.g no protocol)
 --full-packet-tcp-only  use entire packet contents for hash but only for tcp packets

  --file-diff           | special mode of comparing packets between 2 files (instead of within the same file)
  --file-diff-min       | minimum time delta for histogram. default -1e6 ns
  --file-diff-max       | maximum time delta for histogram. default 1e6 ns
  --file-diff-unit      | duration of a single histogram slot. default 100ns

```

### Examples

1) *Diff 2 PCAP files*

there are 2 10g packet capture devices, capturing the same lines (e.g. for redundancy). The following searches for each packet in both files and reports the time difference between the 2 files. 

$ ./pcap_diff  captureA.pcap  captureB.pcap  --file-diff --full-packet-tcp-only --file-diff-unit 100


2) *Diff same packets within a single PCAP*

$ ./pcap_diff  capture.pcap  --tcp-only --packet-trace 

