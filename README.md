# pcap_latency_analyzer

![Alt text](http://fmad.io/analytics/logo_latency_analyzer.png "fmadio latency analyzer logo")

pcap_diff is a simple **packet analyzer** tool used to extract time difference between the same packets in 2 different pcap files. 

More detailed examples can be found at http://fmad.io/blog-packet-analyzer.html 

An example situation is calculating the latency profile of a switch/or other network device where the same packet is recorded with a highly accurate hardware timestamped packet capture device both before the network device and after it.  Using this script a simple text based latency statistics and histogram can be generated.

**Algo**

It works by generating a 128b DEK hash of the entire packet (--full-packet) or just the payload (TCP payload / UDP payload) which gets stored into a large hash table. When a packet`s hash matches an existing entry in the table it appends the packet for further analysis. In addition to 128b DEK hash the match also checks the first 16B of the packet which includes the MAC header + first few bytes of the next layer. This is done because of the low entropy level of small say 64B packets which generates many false positives. 


Command line options 

```

Options:
 --packet-trace                  | write each packet events to stdout
 --length-histo                  | print packet length histogram
 --latency-histo                 | print latency histogram
 --hash-memory                   | (int MB) amount of memory to use for hashing. default 128MB
 --disable-mmap                  | use fread not mmap of the pcap files
 --packet-time-delta-max         | reset time between new and old packets with the same hash.
 --packet-max <number>           | maximum number of packets to process

 --tcp-length <number>           | filter tcp packets to include only payload length of <number>
 --tcp-only                      | only match tcp packets
 --udp-only                      | only match udp packets
 --udp-length <number>           | specifiy udp packets of only length <number>
 --udp-length-chomp <number>     | remove <number> bytes from the end of the UDP packet

Hash the entire packet
 --full-packet                   | use entire packet contents for hash (.e.g no protocol)
 --full-packet-tcp-only          | use entire packet contents for hash but only for tcp packets
 --full-packet-udp-only          | use entire packet contents for hash but only for udp packets

Diff 2 PCAP files: --file-diff                     | special mode of comparing packets between 2 files (instead of within the same file)
 --file-diff                     | special mode of comparing packets between 2 files (instead of within the same file)
 --file-diff-no-timesync         | do not attempt to time sync the two files. reads 1MB chunks at a time
 --file-diff-strict              | only matches with two entries in a hash node will be sampled
 --file-diff-nofcs-a             | file A has no FCS (ethernet crc) value
 --file-diff-nofcs-b             | file B has no FCS (ethernet crc) value
 --file-diff-missing-trace       | trace all packets that are missing
 --file-diff-latency-trace <number in ns> | trace packets that have latency greather than <number>

Diff 2 MAC address: --mac-diff                      | compare packets from 2 mac address in a single PCAP
 --mac-diff-a 00:11:22:33:44:55  | specify MAC address A
 --mac-diff-b 66:77:88:99:aa:bb  | specify MAC address B

Latency histogram shaping
 --latency-histo-min             | minimum time delta for histogram. default -1e6 ns
 --latency-histo-max             | maximum time delta for histogram. default 1e6 ns
 --latency-histo-unit            | duration of a single histogram slot. default 100ns

 --ts-last-byte-a                | adjust timestamp of first file A from last byte to first byte (assumes 10G)
 --ts-last-byte-b                | adjust timestamp of first file B from last byte to first byte (assumes 10G)

```

### Examples

1) **Diff 2 PCAP files**

there are 2 10g packet capture devices, capturing the same lines (e.g. for redundancy). The following searches for each packet in both files and reports the time difference between the 2 files. 

$ ./pcap_latency_analyzer  captureA.pcap  captureB.pcap  --latency-histo --latency-histo-unit 100 --file-diff --full-packet-tcp-only 

2) **Trace the same packets within a single PCAP**

$ ./pcap_latency_analyzer  capture.pcap  --tcp-only --packet-trace 

3) **Trace the same packets within a single PCAP of a specific packet length**

$ ./pcap_latency_analyzer  capture.pcap  --tcp-only --packet-trace  --tcp-length 200 

4) **Generate latency profile of the same packet from 2 different MACs**

$ ./pcap_latency_analyzer  capture.pcap  --mac-diff --mac-diff-a 00:11:22:33:44:55 --mac--diff-b 66:77:88:99:aa:bb --latency-histo

### Output 

Example output of packet latency analysis

```

pacp_diff --file-diff-udp-only --latency-histo --latency-histo-unit 100 ./fmadio-10g-capture-A.pcap
./fmadio-10g-capture-B.pcap
.
.
[snip]
.
.

6200 .ns : 0.0001 (0.0000) : *
6300 .ns : 0.0011 (0.0001) : *
6400 .ns : 0.0032 (0.0004) : *
6500 .ns : 0.0117 (0.0014) : *
6600 .ns : 0.0387 (0.0046) : *
6700 .ns : 0.0743 (0.0108) : ***
6800 .ns : 0.1198 (0.0209) : *****
6900 .ns : 0.1522 (0.0337) : *******
7000 .ns : 0.2156 (0.0518) : **********
7100 .ns : 0.2956 (0.0766) : **************
7200 .ns : 0.3748 (0.1081) : ******************
7300 .ns : 0.4784 (0.1482) : ***********************
7400 .ns : 0.5714 (0.1962) : ****************************
7500 .ns : 0.7193 (0.2566) : ***********************************
7600 .ns : 0.8366 (0.3268) : *****************************************
7700 .ns : 0.8878 (0.4014) : ********************************************
7800 .ns : 0.9444 (0.4807) : ***********************************************
7900 .ns : 0.9624 (0.5615) : ************************************************
8000 .ns : 1.0000 (0.6454) : **************************************************
8100 .ns : 0.8957 (0.7206) : ********************************************
8200 .ns : 0.7725 (0.7855) : **************************************
8300 .ns : 0.7094 (0.8450) : ***********************************
8400 .ns : 0.5818 (0.8939) : *****************************
9500 .ns : 0.4292 (0.9299) : *********************
9600 .ns : 0.2947 (0.9547) : **************
9600 .ns : 0.2090 (0.9722) : **********
9700 .ns : 0.1325 (0.9833) : ******
9800 .ns : 0.0853 (0.9905) : ****
9900 .ns : 0.0576 (0.9953) : **
10000 ns : 0.0287 (0.9977) : *
10100 ns : 0.0141 (0.9989) : *
10200 ns : 0.0046 (0.9993) : *
10300 ns : 0.0036 (0.9996) : *
10400 ns : 0.0025 (0.9998) : *
10500 ns : 0.0015 (1.0000) : *
10600 ns : 0.0005 (1.0000) : *
10700 ns : 0.0000 (1.0000) : *

```

### Support 

This tool is part of the fmadio **10G sniffer appliance**, more information can be found at http://fmad.io 

Contact us for any bugs/patches/requests send a mail to: support at fmad.io 
