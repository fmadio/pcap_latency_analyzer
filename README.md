# pcap_diff
pcap_diff is a simple packet capture analysis tool used to extract time difference between the same packets in 2 different pcap files. 

An example situation is calculating the latency profile of a switch/or other network device where the same packet is recorded with a highly accurate hardware timestamped packet capture device both before the network device and after it.  Using this script a simple text based latency statistics and histogram can be generated.

**Algo**

It works by generating a 128b DEK hash of the entire packet (--full-packet) or just the payload (TCP payload / UDP payload) which gets stored into a large hash table. When a packet`s hash matches an existing entry in the table it appends the packet for further analysis. In addition to 128b DEK hash the match also checks the first 16B of the packet which includes the MAC header + first few bytes of the next layer. This is done because of the low entropy level of small say 64B packets which generates many false positives. 


Command line options 

```

Options:
 --packet-trace            | write each packet events to stdout
 --length-histo            | print packet length histogram
 --hash-memory             | (int MB) amount of memory to use for hashing. default 128MB
 --disable-mmap            | use fread not mmap of the pcap files
 --packet-time-delta-max   | reset time between new and old packets with the same hash.

 --tcp-length <number>     | filter tcp packets to include only payload length of <number>
 --tcp-only                | only match tcp packets
 --udp-only                | only match udp packets
Hash the entire packet
 --full-packet             | use entire packet contents for hash (.e.g no protocol)
 --full-packet-tcp-only    | use entire packet contents for hash but only for tcp packets
 --full-packet-udp-only    | use entire packet contents for hash but only for udp packets

Compare 2 PCAP files: --file-diff               | special mode of comparing packets between 2 files (instead of within the same file)
 --file-diff               | special mode of comparing packets between 2 files (instead of within the same file)
 --file-diff-min           | minimum time delta for histogram. default -1e6 ns
 --file-diff-max           | maximum time delta for histogram. default 1e6 ns
 --file-diff-unit          | duration of a single histogram slot. default 100ns
 --file-diff-no-timesync   | do not attempt to time sync the two files. reads 1MB chunks at a time
 --file-diff-strict        | only matches with two entries in a hash node will be sampled
 --file-diff-nofcs-a       | file A has no FCS (ethernet crc) value
 --file-diff-nofcs-b       | file B has no FCS (ethernet crc) value
 --file-diff-missing-trace | trace all packets that are missing

 --ts-last-byte-a         | adjust timestamp of first file A from last byte to first byte (assumes 10G)
 --ts-last-byte-b         | adjust timestamp of first file B from last byte to first byte (assumes 10G)

```

### Examples

1) **Diff 2 PCAP files**

there are 2 10g packet capture devices, capturing the same lines (e.g. for redundancy). The following searches for each packet in both files and reports the time difference between the 2 files. 

$ ./pcap_diff  captureA.pcap  captureB.pcap  --file-diff --full-packet-tcp-only --file-diff-unit 100


2) **Trace the same packets within a single PCAP**

$ ./pcap_diff  capture.pcap  --tcp-only --packet-trace 

3) **Trace the same packets within a single PCAP of a specific packet length**

$ ./pcap_diff  capture.pcap  --tcp-only --packet-trace  --tcp-length 200 

