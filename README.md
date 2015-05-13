# pcap_diff
pcap_diff is a simple packet capture analysis tool used to extract time difference between the same packets in 2 different pcap files. 

An example situation is calculating the latency profile of a switch/or other network device where the same packet is recorded with a highly accurate hardware timestamped packet capture device both before the network device and after it.  Using this script a simple text based latency statistics and histogram can be generated.

Command line options 

Options:
 --packet-trace        | write each packet events to stdout
 --tcp-length <number> | filter tcp packets to include only payload length of <number>
 --tcp-only            | only match tcp packets
 --udp-only            | only match udp packets
 --full-packet         | use entire packet contents for hash (.e.g no protocol)
 --full-packet-tcp-only  use entire packet contents for hash but only for tcp packets

Example:

there are 2 10g packet capture devices, capturing the same lines (e.g. for redundancy). The following searches for each packet in both files and reports the time difference between the 2 files. 

$ ./pcap_diff  captureA.pcap  captureB.pcap  --file-diff --full-packet-tcp-only --file-diff-unit 100


Mean: -1001.927310 ns StdDef: 137.923019 ns Samples:2153531.000000
HistoMin : -1000000 ns
HistoMax : 1000000 ns
HistoUnit: 100 ns
   -1700 ns :            6 : *
   -1600 ns :           21 : *
   -1500 ns :         4260 : *
   -1400 ns :        53617 : ********
   -1300 ns :        54177 : ********
   -1200 ns :       366271 : *******************************************************
   -1100 ns :       658499 : ***************************************************************************************************
   -1000 ns :       664778 : ****************************************************************************************************
    -900 ns :       149816 : **********************
    -800 ns :       125827 : ******************
    -700 ns :        75972 : ***********
    -600 ns :          132 : *
    -500 ns :          133 : *



