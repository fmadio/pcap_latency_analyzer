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
[captureA.pcap] FileSize: 1GB
[captureB.pcap] FileSize: 1GB
[0.0000] 0.00M  116 : 0.13GB 1 Matches
[0.0295] 1.00M   90 : 0.13GB 435974 Matches
[0.0592] 2.00M  116 : 0.13GB 871579 Matches
[0.0888] 3.00M   72 : 0.13GB 1307403 Matches
[0.1435] 4.00M  438 : 0.13GB 1389581 Matches
[0.2005] 5.00M  438 : 0.13GB 1429501 Matches
[0.2566] 6.00M  174 : 0.13GB 1473194 Matches
[0.3125] 7.00M  149 : 0.13GB 1515911 Matches
[0.3673] 8.00M  174 : 0.13GB 1560914 Matches
[0.4213] 9.00M   64 : 0.13GB 1607034 Matches
[0.4742] 10.00M  174 : 0.13GB 1658501 Matches
[0.5260] 11.00M  116 : 0.13GB 1714027 Matches
[0.5785] 12.00M  149 : 0.13GB 1769297 Matches
[0.6314] 13.00M  174 : 0.13GB 1824975 Matches
[0.6845] 14.00M  146 : 0.13GB 1882150 Matches
[0.7368] 15.00M  116 : 0.13GB 1940288 Matches
[0.7893] 16.00M  174 : 0.13GB 1997677 Matches
[0.8416] 17.00M  234 : 0.13GB 2054285 Matches
[0.8943] 18.00M  174 : 0.13GB 2107793 Matches
[0.9472] 19.00M  174 : 0.13GB 2130242 Matches
[1.0000] 20.00M  174 : 0.13GB 2153539 Matches

Index used: 0.13GB
nodes allocated: 820207
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



