//---------------------------------------------------------------------------------------------
//
// Copyright (c) 2015, fmad engineering llc 
//
// The MIT License (MIT) see LICENSE file for details 
//
// pcap latency diff  
//
//---------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <fcntl.h>

#include "fTypes.h"

//---------------------------------------------------------------------------------------------

typedef struct
{
	char* Path;				// path to the file
	char	Name[128];		// short name
	int		fd;				// file handler of the mmap attached data
	u64		Length;			// exact file length
	u64		MapLength;		// 4KB aligned mmap length
	u8*		Map;			// raw mmap ptr

	u64		TimeScale;		// 1000ns for usec pcap, 1ns for nano pcap
	u64		ReadPos;		// current read pointer
	u64		PktCnt;			// number of packets processed

} PCAPFile_t;

#define PKTTYPE_TCP				1			// tcp packet
#define PKTTYPE_UDP				2			// udp packet
#define PKTTYPE_FULL			3			// raw entire packet 

typedef struct
{
	PCAPPacket_t*	Pkt[8];			// offset to packet 
	u8				FID[8];			// which file

	u64				Hash;			// exact hash value
	u32				Next;			// next in hash index
	u8				Cnt;			// number of hits
	u16				Length;			// hash length
	u8				Type;			// what kind of packet it is, tcp/ udp /other etc. 
									// means dont have parse all the headers each time
	u8				pad[2];

	u32				LRUPrev;		// access linked list. top of the list is more recent 
	u32				LRUNext;		// 
	u64				LRUTS;		

} HashNode_t;

//---------------------------------------------------------------------------------------------
// tunables

static bool		s_EnablePacketTrace	= false;	// verbosely dump all packet traces
static bool		s_EnableFullHash	= false;	// hash the entire packet 
static bool		s_EnableFullHashTCP	= false;	// hash the entire packet only for tcp packets
static bool		s_EnableFullHashUDP	= false;	// hash the entire packet only for udp packets
static bool		s_EnableFullHashAll	= false;	// hash everything dont inspect 

static int		s_TCPLengthMin	= 64;			// minimum tcp payload length to consider
static int		s_TCPLengthMax	= 9600;			// minimum tcp payload length to consider
static bool		s_TCPEnable		= true;			// enable tcp packets to diff

static bool		s_UDPEnable		= true;			// enable udp packets to diff

static bool		s_EnableFileDiff	= false;	// special case of diff between 2 files
static bool		s_EnableFileDiffTimeSync = true;	// attempt to time sync the two files for better packet matching

static u64		s_TimeZoneOffset	= 0;		// local machines timezone offset
static u64		s_HashOverflow		= 0;		// number of hash`s wich oveflow the packet count

static double	s_FileDiffSum0		= 0;
static double	s_FileDiffSum1		= 0;
static double	s_FileDiffSum2		= 0;

// file diff hisogram 
static u32*		s_FileDiffHisto		= NULL;		// histgram
static s64		s_FileDiffHistoMin	= -1e6;		// delat min value 
static s64		s_FileDiffHistoMax	=  1e6;		// delat max value 
static s64		s_FileDiffHistoUnit	=  100;		// number of ns each hiso bucket occupies 
static s64		s_FileDiffHistoCnt	=  0;		// number of buckets 

static u64		s_FileDiffMissingA	= 0;		// number of packets mssing from PCAP A
static u64		s_FileDiffMissingB	= 0;		// number of packets mssing from PCAP B

static u64		s_HashMemory		= kMB(128);	// default hash memory size

//---------------------------------------------------------------------------------------------
// mmaps a pcap file in full
static PCAPFile_t* OpenPCAP(char* Path)
{
	PCAPFile_t* F = (PCAPFile_t*)malloc( sizeof(PCAPFile_t) );
	memset(F, 0, sizeof(PCAPFile_t));

	struct stat fstat;	
	if (stat(Path, &fstat) < 0)
	{
		fprintf(stderr, "failed to get file size [%s]\n", Path);
		return NULL;
	}
	F->Path		= Path;
	F->Length 	= fstat.st_size;

	F->fd = open64(Path, O_RDONLY, S_IRWXU | S_IRWXG);	
	if (F->fd < 0)
	{
		fprintf(stderr, "failed to open file [%s]\n", Path);
		return NULL;
	}

	// note always map as read-only 

	F->MapLength = (F->Length + 4095) & (~4095);
	F->Map = mmap64(0, F->MapLength, PROT_READ, MAP_SHARED, F->fd, 0);
	if (F->Map == (u8*)-1)
	{
		fprintf(stderr, "failed to map stream index [%s] %i\n", Path, errno);
		return 0;	
	}
	madvise(F->Map, F->MapLength, POSIX_MADV_SEQUENTIAL);

	PCAPHeader_t* Header = (PCAPHeader_t*)F->Map;
	switch (Header->Magic)
	{
	case PCAPHEADER_MAGIC_USEC: F->TimeScale = 1000; break;
	case PCAPHEADER_MAGIC_NANO: F->TimeScale = 1; break;
	default:
		fprintf(stderr, "invalid pcap header %08x\n", Header->Magic);
		return NULL;
	}

	F->ReadPos +=  sizeof(PCAPHeader_t);

	return F;
}

//---------------------------------------------------------------------------------------------
// helpers for network formating 
static u64 PCAPTimeStamp(PCAPPacket_t* Pkt)
{
	return s_TimeZoneOffset + Pkt->Sec * k1E9 + Pkt->NSec;
}
static fEther_t * PCAPETHHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	
	return E;
}

static IP4Header_t* PCAPIP4Header(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	return IP4;
}

static TCPHeader_t* PCAPTCPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);
	u32 TCPOffset = ((TCP->Flags&0xf0)>>4)*4;

	return TCP;
}

static UDPHeader_t* PCAPUDPHeader(PCAPPacket_t* Pkt)
{
	fEther_t* E = (fEther_t*)(Pkt+1);	

	IP4Header_t* IP4 = (IP4Header_t*)(E + 1);
	u32 IPOffset = (IP4->Version & 0x0f)*4; 

	UDPHeader_t* UDP = (UDPHeader_t*)( ((u8*)IP4) + IPOffset);

	return UDP;
}

//---------------------------------------------------------------------------------------------
// DEK packets usually have enough entropy for this to be enough 
static u64 PayloadHash(u8* Payload, u32 Length)
{
	u64 Hash = 0;
	for (int i=0; i < Length; i++)
	{
		Hash = ((Hash << 5ULL) ^ (Hash >> 59ULL)) ^ (u64)Payload[i];
	}
	return Hash;
}

//---------------------------------------------------------------------------------------------
// usees a fifo of hash nodes and recycles then constantly

static u32*			s_IndexLevel0 = NULL;	// first level index

static HashNode_t* s_HashList = NULL;		// memory allocated for nodes
static u32			s_HashPos = 0;			// current allocation position
static u64			s_HashCnt = 0;			// total allocated cnt 
static u32			s_HashMax = 0;			// max number of hash positions 

static HashNode_t*	s_HashLRUHead = NULL;	// head (most recently used) of LRU ndoe list
static HashNode_t*	s_HashLRUTail = NULL;	// tail (least recently used) of nodes 

static void TracePacket(HashNode_t* N)
{
	printf("PacketTrace: Count:%i length:%4i Hash:%016llx dCycle:%lli\n", N->Cnt, N->Length, N->Hash, rdtsc() - N->LRUTS);

	// no need to print no match packets 
	if (N->Cnt == 0) return;
	if (N->Cnt == 1) return;


	int c = N->Cnt - 1;
	if (c > 7) c = 7;  

	int i=0;
	u64 LastTS = PCAPTimeStamp(N->Pkt[c]);
	for (; c >= 0; c--)
	{
		if (c >= 8) break;

		u64 TS = PCAPTimeStamp(N->Pkt[c]);
		fEther_t* 	 ETHn = PCAPETHHeader( N->Pkt[c] );

		printf("  [%i:%i]  %s | %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x | ", 
					i,
					N->FID[c],
					FormatTS(TS),

					ETHn->Src[0],
					ETHn->Src[1],
					ETHn->Src[2],
					ETHn->Src[3],
					ETHn->Src[4],
					ETHn->Src[5],

					ETHn->Dst[0],
					ETHn->Dst[1],
					ETHn->Dst[2],
					ETHn->Dst[3],
					ETHn->Dst[4],
					ETHn->Dst[5]
		);

		switch (N->Type)
		{
		case PKTTYPE_FULL:
		{
			printf("FULL %04x (+%6lli ns)", 

					swap16(ETHn->Proto), 
					TS - LastTS
				  );
		}
		break;


		case PKTTYPE_TCP:
		{
			fEther_t* 	 ETHn = PCAPETHHeader( N->Pkt[c] );
			IP4Header_t* IP4n = PCAPIP4Header( N->Pkt[c] );
			TCPHeader_t* TCPn = PCAPTCPHeader( N->Pkt[c] );


			printf("%3i.%3i.%3i.%3i -> %3i.%3i.%3i.%3i | TCP %05i %05i (+%6lli ns)", 

					IP4n->Src.IP[0],
					IP4n->Src.IP[1],
					IP4n->Src.IP[2],
					IP4n->Src.IP[3],

					IP4n->Dst.IP[0],
					IP4n->Dst.IP[1],
					IP4n->Dst.IP[2],
					IP4n->Dst.IP[3],

					swap16(TCPn->PortSrc), 
					swap16(TCPn->PortDst),
					TS - LastTS
				  );
		}
		break;

		case PKTTYPE_UDP:
		{
			fEther_t* 	 ETHn = PCAPETHHeader( N->Pkt[c] );
			IP4Header_t* IP4n = PCAPIP4Header( N->Pkt[c] );
			UDPHeader_t* UDPn = PCAPUDPHeader( N->Pkt[c] );

			printf("%3i.%3i.%3i.%3i -> %3i.%3i.%3i.%3i | UDP %05i %05i (+%6lli ns)", 

					IP4n->Src.IP[0],
					IP4n->Src.IP[1],
					IP4n->Src.IP[2],
					IP4n->Src.IP[3],

					IP4n->Dst.IP[0],
					IP4n->Dst.IP[1],
					IP4n->Dst.IP[2],
					IP4n->Dst.IP[3],

					swap16(UDPn->PortSrc), 
					swap16(UDPn->PortDst),
					TS - LastTS
				  );
		}
		break;
		}
		printf("\n");

		LastTS = TS;
		i++;
	}
	printf("\n");
}

//---------------------------------------------------------------------------------------------
// process a single node hit. happens when the node is about to be recycled + flushed at the end
// of processing
static void NodeOutput(HashNode_t* N)
{
	// dump packet trace info
	if (s_EnablePacketTrace)	
	{
		TracePacket(N);
	}

	// special case of diffing 2 nearly identical files for latency deltas
	if (s_EnableFileDiff)
	{
		s64 TS1 = 0;
		u32 FID1 = -1;

		s64 TS0 	= PCAPTimeStamp(N->Pkt[0]);
		u64 FID0 	= N->FID[0];

		for (int c =0; c < N->Cnt; c++)
		{
			if (c >= 8) break;

			if (N->FID[c] != FID0)
			{
				TS1 	= PCAPTimeStamp(N->Pkt[c]);
				FID1 	= N->FID[c];
				break;
			}
		}

		// always assume File0 -> File1 
		if (FID0 == 1)
		{
			u64 TS2 = TS0;
			int FID2 = FID0;

			TS0 = TS1;
			TS1 = TS2;

			FID0 = FID1;
			FID1 = FID2;
		}

		// if packet was in both files 

		if ((TS0 != 0) && (TS1 != 0))
		{
			s64 dT = (TS1 - TS0);

			// online mean/stde calc 

			s_FileDiffSum0 += 1;
			s_FileDiffSum1 += dT;
			s_FileDiffSum2 += dT*dT;

			// center / align and slice dT for histogram 
			s64 dTH = dT;
			dTH 	= (dTH > s_FileDiffHistoMax) ? s_FileDiffHistoMax : dTH;
			dTH 	= (dTH < s_FileDiffHistoMin) ? s_FileDiffHistoMin : dTH;
			dTH		+= -s_FileDiffHistoMin;

			// convert to histo buckets

			s32 Index = dTH / s_FileDiffHistoUnit;
			Index = (Index < 0) ? 0 : Index;
			Index = (Index >= s_FileDiffHistoCnt) ? s_FileDiffHistoCnt -1 : Index;

			s_FileDiffHisto[Index]++;
			//printf("%f ns %016llx %016llx\n", dT, TS0, TS1); 
		}
		// packet was nott in both files
		else
		{
			// its possible the packet just fell off the
			// per node history (8 deep) e.g. same packet
			// is seen alot (8+) times in the capture 
			if (N->Cnt < 8)
			{
				if (FID0 == 0)
				{
					//printf("missing packet. Not in File B\n");
					s_FileDiffMissingA++;
				}
				if (FID0 == 1)
				{
					//printf("missing packet. Not in File A\n");
					s_FileDiffMissingB++;
				}
				//TracePacket(N);
			}
		}
	}
	// count packets with hash overflow 
	if (N->Cnt < 8)
	{
		s_HashOverflow++;
	}
}

//---------------------------------------------------------------------------------------------
// LRU double linked list to recycle the LRU node thus increasing packet search window 
static void NodeLRUUnlink(HashNode_t* N)
{
	// remove from head
	if (s_HashLRUHead == N)
	{
		if (N->LRUNext == 0) s_HashLRUHead = NULL;
		else 				 s_HashLRUHead = s_HashList + N->LRUNext;
	}
	if (s_HashLRUTail == N) 
	{
		if (N->LRUPrev == 0) s_HashLRUTail = NULL; 
		else				 s_HashLRUTail = s_HashList + N->LRUPrev; 
	}

	// unlik
	if (N->LRUPrev != 0) s_HashList[ N->LRUPrev ].LRUNext = N->LRUNext;
	if (N->LRUNext != 0) s_HashList[ N->LRUNext ].LRUPrev = N->LRUPrev;
}

static void NodeLRUAdd(HashNode_t* N)
{
	// set at head
	N->LRUPrev 				= 0; 
	N->LRUNext 				= 0; 
	if (s_HashLRUHead)
	{
		N->LRUNext 				= s_HashLRUHead - s_HashList; 
		s_HashLRUHead->LRUPrev 	= N - s_HashList;
	}
	s_HashLRUHead 	= N;
	if (s_HashLRUTail == NULL) s_HashLRUTail = N;
}

static void NodeLRUDump(void)
{
	u32 Count 		= 1e9;
	HashNode_t* N 	= s_HashLRUHead;

	u64 TSC = rdtsc();
	int Cnt = 0;
	while (N)
	{
		u32 id = N - s_HashList;
		printf("%i: %8i: %p %016llx %s\n", Cnt, id, N, N->LRUTS, TSC < N->LRUTS ? "X" : " ");
		assert(TSC > N->LRUTS);
		TSC = N->LRUTS;
		Cnt++;

		//printf("%i : %p %i\n", Count, N, N->LRUNext);
		if (N->LRUNext == 0)
		{
			break;
		}
		N = s_HashList + N->LRUNext;
		assert(N != s_HashLRUHead);
		assert(--Count  != 0);
	}
}

static u64 NodeLRUValidate(void)
{
	u32 Count 		= 1e9;
	HashNode_t* N 	= s_HashLRUHead;

	bool Valid = true;

	u64 TSC = rdtsc();
	u64 c = 0;
	while (N)
	{
		if (TSC < N->LRUTS) { Valid = false; break; }
		TSC = N->LRUTS;

		//printf("%i : %p %i\n", Count, N, N->LRUNext);
		if (N->LRUNext == 0)
		{
			assert(s_HashLRUTail == N);
			break;
		}
		N = s_HashList + N->LRUNext;
		assert(--Count  != 0);
		c++;
	}
	if (!Valid)
	{
		fprintf(stderr, "lru fail\n");
		NodeLRUDump(); 
		assert(false); 
	}
	return c;
}

//---------------------------------------------------------------------------------------------
// release node
static void NodeFree(HashNode_t* N)
{
	// add stats
	NodeOutput(N);

	HashNode_t* Root = s_HashList + s_IndexLevel0[ N->Hash & 0x00ffffff];
	HashNode_t* NS = Root; 
	HashNode_t* NP = NULL; 
	while (NS)
	{
		if (NS == N)
		{
			// root node
			if (NP == NULL)
			{
				s_IndexLevel0[ N->Hash & 0x00ffffff] = N->Next;
			}
			else
			{
				NP->Next = N->Next;	
			}
			break;
		}
		if (NS->Next == 0) break;
		NP = NS;
		NS = s_HashList + NS->Next;
	}

	// remove from LRU list 
	NodeLRUUnlink(N);	
}

//---------------------------------------------------------------------------------------------

static HashNode_t* NodeAllocate(void)
{
	HashNode_t* N = &s_HashList[s_HashPos++];
	s_HashCnt++;
	if (s_HashCnt >= s_HashMax)
	{
		// recycle and use node from LRU
		N = s_HashLRUTail;
		NodeFree(N);
	}

	memset(N, 0, sizeof(HashNode_t));
	return N;
}

//---------------------------------------------------------------------------------------------
// force output of all remaining nodes
static void HashFlush(void)
{
	for (int i=0; i < s_HashMax; i++)
	{
		HashNode_t* N = &s_HashList[i];
		if (N->Hash == 0) continue;
		NodeFree(N);
	}
}

//---------------------------------------------------------------------------------------------
// create or append a packet to the current hash node list 
static void HashPacket(u32 FID, PCAPPacket_t* Pkt, u32 Type, u64 Hash, u32 Length)
{
	HashNode_t* N = NULL;

	// search for hash
	bool NodeHit = false;	
	HashNode_t* NS = &s_HashList[ s_IndexLevel0[ Hash & 0x00ffffff] ];
	u32 Count = 1e6;
	while (NS)
	{
		if ((NS->Hash == Hash) && (NS->Type == Type))
		{
			NS->Cnt++;

			for (int i=7; i >= 1; i--)
			{
				NS->Pkt[i] = NS->Pkt[i-1];
				NS->FID[i] = NS->FID[i-1];
			}
			NS->Pkt[0] = Pkt; 
			NS->FID[0] = FID; 

			NodeHit = true;
			N = NS;

			NodeLRUUnlink(N);

			break;
		}
		if (NS->Next == 0) break;
		NS = s_HashList + NS->Next;
		assert(--Count != 0);
	}

	// allocate Node
	if (!NodeHit)
	{
		N = NodeAllocate(); 
		N->Hash 	= Hash;
		N->Pkt[0]	= Pkt;
		N->FID[0]	= FID;
		N->Cnt		= 1;
		N->Length	= Length;
		N->Type		= Type;

		HashNode_t* OldN = &s_HashList[ s_IndexLevel0[ Hash & 0x00ffffff] ];
		N->Next = OldN - s_HashList;	

		s_IndexLevel0[ Hash & 0x00ffffff] = N - s_HashList; 
	}

	NodeLRUAdd(N);
	N->LRUTS		= rdtsc();
}

//---------------------------------------------------------------------------------------------

static void TCPProcess(u32 FID, PCAPPacket_t* Pkt, fEther_t* E, IP4Header_t* IP4, u32 IPOffset)
{
	if (!s_TCPEnable) return;

	TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);

	u32 TCPOffset 	= ((TCP->Flags&0xf0)>>4)*4;
	u8* TCPPayload 	= (u8*)TCP + TCPOffset;
	u32 TCPLength 	= swap16(IP4->Len) - TCPOffset - IPOffset;

	assert(TCPLength < 16*1024);

	if ((TCPLength >= s_TCPLengthMin)  && (TCPLength <= s_TCPLengthMax))
	{
		// generate payload hash  
		u64 Hash = PayloadHash(TCPPayload, TCPLength); 
		HashPacket(FID, Pkt, PKTTYPE_TCP, Hash, TCPLength);
	}
	//printf("tcp %i %i %x %x %x : %08x\n", swap16(TCP->PortSrc), swap16(TCP->PortDst), TCPOffset, sizeof(TCPHeader_t)/4, TCP->Flags, TCPPayload[0]); 
}

//---------------------------------------------------------------------------------------------

static void UDPProcess(u32 FID, PCAPPacket_t* Pkt, fEther_t* E, IP4Header_t* IP4, u32 IPOffset)
{
	if (!s_UDPEnable) return;

	UDPHeader_t* UDP 	= (UDPHeader_t*)( ((u8*)IP4) + IPOffset);
	u8* Payload			= (u8*)(UDP + 1); 
	u32 Length 			= swap16(UDP->Length);

	assert(Length < 16*1024);
	
	// generate payload hash  
	u64 Hash = PayloadHash(Payload, Length); 
	HashPacket(FID, Pkt, PKTTYPE_UDP, Hash, Length);
}

//---------------------------------------------------------------------------------------------

static void PrintFileDiffHisto(PCAPFile_t* PCAPFile[])
{
	double Mean 	= s_FileDiffSum1 / s_FileDiffSum0;
	double Top 		= s_FileDiffSum0 * s_FileDiffSum2 - s_FileDiffSum1 * s_FileDiffSum1;
	double StdDev 	= sqrt(Top) / s_FileDiffSum0; 

	printf("Stats\n");
	printf("  Mean    : %f ns\n", Mean);
	printf("  Std Dev : %f ns\n", StdDev);
	printf("  Samples : %.f\n",  s_FileDiffSum0);
	printf("\n");

	printf("Histogram\n");
	printf("  Min     : %10lli ns\n", s_FileDiffHistoMin);
	printf("  Max     : %10lli ns\n", s_FileDiffHistoMax);
	printf("  Unit    : %10lli ns\n", s_FileDiffHistoUnit);
	printf("\n");

	// output histogram
	u32 HMin 	= s_FileDiffHistoCnt-1;
	u32 HMax 	= 0;
	u32 Max		= 0; 
	for (int i=0; i < s_FileDiffHistoCnt; i++)
	{
		if (s_FileDiffHisto[i] == 0) continue; 

		HMin = (HMin > i) ? i : HMin;
		HMax = (HMax < i) ? i : HMax;
		Max = (s_FileDiffHisto[i] > Max) ? s_FileDiffHisto[i] : Max;
	}
	for (int i=HMin; i <= HMax; i++)
	{
		s64 dT = s_FileDiffHistoMin + i * s_FileDiffHistoUnit;
		printf("%8lli ns : %12i : ", dT, s_FileDiffHisto[i]);

		int StarCnt = (100*s_FileDiffHisto[i]) / Max;
		if ((s_FileDiffHisto[i] > 0) && StarCnt == 0) StarCnt = 1;

		for (int s=0; s < StarCnt; s++) printf("*");

		printf("\n");
	}
	printf("\n");

	printf("Missing Packets:\n");
	printf("  [%s] packets not in [%s] : %lli Pkts\n", PCAPFile[0]->Path, PCAPFile[1]->Path, s_FileDiffMissingA);  
	printf("  [%s] packets not in [%s] : %lli Pkts\n", PCAPFile[1]->Path, PCAPFile[0]->Path, s_FileDiffMissingB);  
}

//---------------------------------------------------------------------------------------------

static void print_usage(void)
{
	printf("pcap_diff: <pcap A> <pcap B>\n");
	printf("\n");
	printf("Version: %s %s\n", __DATE__, __TIME__);
	printf("Contact: support at fmad.io\n"); 
	printf("\n");
	printf("Options:\n");
	printf(" --packet-trace        | write each packet events to stdout\n");
	printf(" --tcp-length <number> | filter tcp packets to include only payload length of <number>\n");
	printf(" --tcp-only            | only match tcp packets\n"); 
	printf(" --udp-only            | only match udp packets\n"); 
	printf(" --full-packet         | use entire packet contents for hash (.e.g no protocol)\n"); 
	printf(" --full-packet-tcp-only  use entire packet contents for hash but only for tcp packets\n"); 
	printf("\n");
	printf(" --file-diff           | special mode of comparing packets between 2 files (instead of within the same file)\n");
	printf(" --file-diff-min       | minimum time delta for histogram. default -1e6 ns\n"); 
	printf(" --file-diff-max       | maximum time delta for histogram. default 1e6 ns\n"); 
	printf(" --file-diff-unit      | duration of a single histogram slot. default 100ns\n"); 
	printf("\n");
	printf(" --hash-memory         | (int MB) amount of memory to use for hashing. default 128MB\n");
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	int 	FileNameListPos = 0;
	char 	FileNameList[16][256];

	for (int i=1; i < argc; i++)
	{
		if (argv[i][0] != '-')
		{
			strcpy(FileNameList[FileNameListPos], argv[i]);
			FileNameListPos++;
		}
		if (strcmp(argv[i], "--packet-trace") == 0)
		{
			s_EnablePacketTrace = true;
		}

		// specifiy an exact tcp length to use 
		if (strcmp(argv[i], "--tcp-length") == 0)
		{
			s_TCPLengthMin = atoi(argv[i+1]);	
			s_TCPLengthMax = atoi(argv[i+1]);	

			fprintf(stderr, "TCP Length == %i\n", s_TCPLengthMin);
			i += 1;
		}

		// only check tcp packets
		if (strcmp(argv[i], "--tcp-only") == 0)
		{
			s_TCPEnable = true;
			s_UDPEnable = false;
		}

		// full packet hash 
		if (strcmp(argv[i], "--full-packet") == 0)
		{
			s_TCPEnable 	= false;
			s_UDPEnable 	= false;
			s_EnableFullHash = true;
			s_EnableFullHashAll = true;
		}
		if (strcmp(argv[i], "--full-packet-tcp-only") == 0)
		{
			s_EnableFullHash 	= true;
			s_EnableFullHashTCP = true;
		}

		// specal case of 2 pcap diff. compare first hash entrys between files
		if (strcmp(argv[i], "--file-diff") == 0)
		{
			s_EnableFileDiff 	= true;
		}
		// min file diff position 
		if (strcmp(argv[i], "--file-diff-min") == 0)
		{
			s_FileDiffHistoMin	= atoi(argv[i+1]); 
			i+= 1;
		}
		// max file diff position 
		if (strcmp(argv[i], "--file-diff-max") == 0)
		{
			s_FileDiffHistoMax	= atoi(argv[i+1]);
			i+= 1;
		}
		// unit size of each sample 
		if (strcmp(argv[i], "--file-diff-unit") == 0)
		{
			s_FileDiffHistoUnit= atoi(argv[i+1]);
			i+= 1;
		}
		// amount of memory to allocate for hash nodes 
		if (strcmp(argv[i], "--hash-memory") == 0)
		{
			s_HashMemory = atoi(argv[i+1])*1024*1024;
			i+= 1;
		}
	}

	// needs atleast 2 files
	if (FileNameListPos <= 0)
	{
		print_usage();
		return 0;
	}
	if ((s_EnableFileDiff) && (FileNameListPos != 2))
	{
		fprintf(stderr, "File Diff mode requires 2 pcap files\n");
		return 0;
	}

	// get timezone offset

  	time_t t = time(NULL);
	struct tm lt = {0};

	localtime_r(&t, &lt);
	s_TimeZoneOffset = lt.tm_gmtoff * 1e9;
	
	// open pcap diff files

	PCAPFile_t* PCAPFile[16];
	for (int i=0; i < FileNameListPos; i++)
	{
		PCAPFile[i] = OpenPCAP(FileNameList[i]);	
		if (!PCAPFile[i]) return 0;

		printf("[%30s] FileSize: %lliGB\n", PCAPFile[i]->Path, PCAPFile[i]->Length / kGB(1)); 
	}

	u64 PktCnt 		= 0;
	u64 HashSum 	= 0;
	u64 TotalMemory = 0;

	// first level index 
	s_IndexLevel0 		= (u32*)malloc( sizeof(void*) * (1<<24) );
	memset(s_IndexLevel0, 0, sizeof(void*) * (1<<24) );
	TotalMemory 		+= 	sizeof(void*) * (1<<24);

	s_HashPos 			= 1;
	s_HashMax 			= s_HashMemory / sizeof(HashNode_t); 
	s_HashList 			= (HashNode_t*)malloc(s_HashMax * sizeof(HashNode_t));
	memset(s_HashList, 0, s_HashMax * sizeof(HashNode_t));
	printf("HashMemory: %lliMB %i Nodes\n", (s_HashMax * sizeof(HashNode_t)) / kMB(1), s_HashMax );

	// file only histogram

	s_FileDiffHistoCnt 	= (s_FileDiffHistoMax  - s_FileDiffHistoMin) /  s_FileDiffHistoUnit;
	s_FileDiffHisto 	= (u32*)malloc(sizeof(u32) *  s_FileDiffHistoCnt);
	memset(s_FileDiffHisto, 0, sizeof(u32) * s_FileDiffHistoCnt);

	u64 SyncTS  = 0; 
	while (true)
	{
		bool Done = true;
		for (int FID=0; FID < FileNameListPos; FID++)
		{
			PCAPFile_t* PCAP = PCAPFile[FID];
			if (PCAP->ReadPos < PCAP->Length) Done = false;
		}
		if (Done) break;

		for (int FID=0; FID < FileNameListPos; FID++)
		{
			PCAPFile_t* PCAP = PCAPFile[FID];
			u64 StartPos = PCAP->ReadPos;

			// read next 1MB

			while (PCAP->ReadPos < PCAP->Length)
			{
				PCAPPacket_t* Pkt = (PCAPPacket_t*)(PCAP->Map + PCAP->ReadPos);

				// if file terminates in the middle of a packet 
				if (PCAP->ReadPos + sizeof(PCAPPacket_t) > PCAP->Length) break;
				if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length) break;

				u64 TS = Pkt->Sec*k1E9 + Pkt->NSec;

				// want to increment file 0 by 128KB each time, but want 
				// the other file to attempt time sync with file0. this maximizes
				// the hash cache
				if (s_EnableFileDiffTimeSync)
				{
					if (FID == 0)
					{
						if (PCAP->ReadPos > StartPos + kMB(1)) break;

						// include fudge window
						SyncTS  = TS;
					}
					else
					{
						if (TS > SyncTS)
						{
							// when File0`s last timestamp is less thean FileA 
							if (PCAPFile[0]->ReadPos < PCAPFile[0]->Length)
							{
								break;
							}
						}
					}
				}
				// if time sync fails user can alwser specifiy pure file size
				else
				{
					if ((PCAP->ReadPos > StartPos + kMB(1))) break;
				}

				fEther_t* E = PCAPETHHeader(Pkt);
				if (s_EnableFullHash)
				{
					bool HashIt = s_EnableFullHashAll;
					switch (swap16(E->Proto))
					{
					case ETHER_PROTO_IPV4:
						{
							IP4Header_t* IP4 = PCAPIP4Header(Pkt); 
							u32 IPOffset = (IP4->Version & 0x0f)*4; 
							switch (IP4->Proto)
							{
							case IPv4_PROTO_TCP: HashIt = s_EnableFullHashTCP; break;
							case IPv4_PROTO_UDP: HashIt = s_EnableFullHashUDP; break;
							}
						}
					}
					if (HashIt)
					{
						u64 Hash = PayloadHash((u8*)E, Pkt->LengthCapture); 
						HashPacket(FID, Pkt, PKTTYPE_FULL, Hash, Pkt->LengthCapture);
					}
				}
				else
				{
					switch (swap16(E->Proto))
					{
					case ETHER_PROTO_IPV4:
						{
							IP4Header_t* IP4 = PCAPIP4Header(Pkt); 
							u32 IPOffset = (IP4->Version & 0x0f)*4; 
							switch (IP4->Proto)
							{
							case IPv4_PROTO_TCP: TCPProcess(FID, Pkt, E, IP4, IPOffset); break;
							case IPv4_PROTO_UDP: UDPProcess(FID, Pkt, E, IP4, IPOffset); break;
							}
						}
						break;
					}
				}

				PCAP->ReadPos += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				PCAP->PktCnt++;

				if (PktCnt % 1000000 == 0)
				{
					u64 Depth = 0; //NodeLRUValidate();
					fprintf(stderr, "[%.4f%%] %.2fM %4i : %.2fGB %lli Matches %lli\n", PCAP->ReadPos / (double)PCAP->Length, PktCnt / 1e6, Pkt->LengthCapture, TotalMemory / 1e9, s_HashCnt, Depth);
				}
				PktCnt++;
			}
		}
	}
	printf("read done\n");
	printf("%llx %llx\n", PCAPFile[0]->ReadPos, PCAPFile[1]->ReadPos);

	printf("Validating...\n");
	NodeLRUValidate();

	// dump out remaining nodes
	printf("Flushing..\n");
	HashFlush();		

	printf("Done\n");

	//printf("Index used: %.2fGB \n", TotalMemory / 1e9);	
	//printf("nodes allocated: %i\n", s_HashPos);
	//printf("nodes overflow:  %lli\n", s_HashOverflow);

	if (s_EnableFileDiff) PrintFileDiffHisto(PCAPFile);
}

/* vim: set ts=4 sts=4 */
