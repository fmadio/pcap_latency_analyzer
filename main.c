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
	FILE*	F;				// bufferd io file handle
	int		fd;				// file handler of the mmap attached data
	u64		Length;			// exact file length
	u64		MapLength;		// 4KB aligned mmap length
	u8*		Map;			// raw mmap ptr

	u64		TimeScale;		// 1000ns for usec pcap, 1ns for nano pcap
	u64		ReadPos;		// current read pointer
	u64		PktCnt;			// number of packets processed

	u8*		PacketBuffer;	// temp read buffer
	bool	Finished;		// read completed

	u64		TS;				// last TS processed

} PCAPFile_t;

#define PKTTYPE_TCP				1			// tcp packet
#define PKTTYPE_UDP				2			// udp packet
#define PKTTYPE_FULL			3			// raw entire packet 

#define NODE_DEPTH 		16	

typedef struct
{
	PCAPPacket_t*	Pkt[NODE_DEPTH];	// offset to packet 
	u64				TS[NODE_DEPTH];		// timestamp of the packet
	u8				FID[NODE_DEPTH];	// which file

	u128			Hash;				// exact hash value
	u32				Next;				// next in hash index
	u32				Prev;				// previous in hash index 
	u8				Cnt;				// number of hits
	u16				Length;				// hash length
	u8				Type;				// what kind of packet it is, tcp/ udp /other etc. 

	u128			MAC;				// mac header
										// means dont have parse all the headers each time
	u8				pad[2];

	u32				LRUPrev;			// access linked list. top of the list is more recent 
	u32				LRUNext;			// 
	u64				LRUTS;		

} HashNode_t;

double TSC2Nano = 0;

//---------------------------------------------------------------------------------------------
// tunables

static bool		s_EnablePacketTrace		= false;			// verbosely dump all packet traces
static bool		s_EnableFullHash		= false;			// hash the entire packet 
static bool		s_EnableFullHashTCP		= false;			// hash the entire packet only for tcp packets
static bool		s_EnableFullHashUDP		= false;			// hash the entire packet only for udp packets
static bool		s_EnableFullHashAll		= false;			// hash everything dont inspect 
static u64		s_FullHashLengthMin		= 92;				// minimum packet size to attempt has on

static bool		s_HashMatchMAC			= false;			// when searching for a node hit, ensure MAC address matches		
															// helpful when doing full packet hashing, but need to disable
															// when doing payload matching 

static int		s_TCPLengthMin				= 64;			// minimum tcp payload length to consider
static int		s_TCPLengthMax				= 9600;			// minimum tcp payload length to consider
static bool		s_TCPEnable					= true;			// enable tcp packets to diff
static int		s_TCPPayloadMax				= 9600;			// max TCP payload to hash. useful for sliced packets

static bool		s_UDPEnable					= true;			// enable udp packets to diff
static u32		s_UDPLengthMin				= 16;			// set a default min udp length
static u32		s_UDPLengthMax				= 8192;			// max length to be consider 
static s32		s_UDPLengthChomp			= 0;			// chomp the udp packet length 

static bool		s_EnableFileDiff			= false;		// special case of diff between 2 files
static bool		s_EnableFileDiffTimeSync 	= true;			// attempt to time sync the two files for better packet matching
static bool		s_EnableFileDiffStrict 		= false;			// means for a single hash node, only 2 entries can exist for it to sample.
															// file A entry and file B entry

static u64		s_TimeZoneOffset			= 0;			// local machines timezone offset
static u64		s_HashOverflow				= 0;			// number of hash`s wich oveflow the packet count
static u64		s_DroppedPkts				= 0;

static double	s_FileDiffSum0				= 0;
static double	s_FileDiffSum1				= 0;
static double	s_FileDiffSum2				= 0;

static bool		s_MACDiffEnable				= false;		// use MAC for a/b selection
static u128		s_MACDiff[2];								// source mac for A/B
static u128		s_MACMask					= 0;			// value to mask packets first 128b worth

// latnecy histogram 
static bool		s_LatencyHistoEnable		= false;		// if to print a latency histogram
static u64*		s_LatencyHisto				= NULL;			// histgram
static s64		s_LatencyHistoMin			= -1e6;			// delat min value 
static s64		s_LatencyHistoMax			=  1e6;			// delat max value 
static s64		s_LatencyHistoUnit			=  100;			// number of ns each hiso bucket occupies 
static s64		s_LatencyHistoCnt			=  0;			// number of buckets 

// packet length histogram 
static bool		s_LengthHistoEnable			= false;		// if to print a length histogram
static u64		s_LengthHistoUnit			= 1;			// size of output bucket
static u64		s_LengthHisto[16*1024];

static u64		s_FileDiffMissingA			= 0;			// number of packets mssing from PCAP A
static u64		s_FileDiffMissingB			= 0;			// number of packets mssing from PCAP B
static bool		s_FileDiffMissingTraceA 	= false;		// trace all packets that are missing
static bool		s_FileDiffMissingTraceB 	= false;		// trace all packets that are missing

static bool		s_FileDiffNoFCSFileA		= false;		// compensate for no FCS in file A
static bool		s_FileDiffNoFCSFileB		= false;		// compensate for no FCS in file B
static bool		s_FileDiffNoFCS				= true;			// strip FCS from hash 

static bool		s_FileDiffStampAdjust		= false;		// adjust the timestamp based on first byte or last byte 
static double	s_FileDiffTimeOffset[16];					// length scale toe move timestamp to start of packet 
															// no adjust the scale is 0

static s64		s_FileDiffLatencyTraceMin	= 1e12;			// latency threshold to start printing. set via cmd line arg

static u64		s_HashMemory				= kMB(128);		// default hash memory size
static bool		s_EnableMMAP				= true;			// disable use of mmap, use fread instead
static bool		s_EnableTraceOverflow 		= false;		// dump overflow packet info to console
static s64		s_TimeDeltaMaxNS			= 100e6;		// max time between packets before discarding

static bool		s_EnableWTF					= false;		// dump everything	

static bool		s_EnableLengthHisto			= false;		// display packet length histogram
static u64		s_MaxPackets				= (1ULL<<63);	// max number of packets to process

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

	F->F = fopen(Path, "r");
	if (F->F == NULL)
	{
		fprintf(stderr, "failed to open buffered file [%s]\n", Path);
		return NULL;
	}


	// note always map as read-only 
	PCAPHeader_t Header1;
	PCAPHeader_t* Header = NULL; 
	if (s_EnableMMAP)
	{

		F->MapLength = (F->Length + 4095) & (~4095);
		F->Map = mmap64(0, F->MapLength, PROT_READ, MAP_SHARED, F->fd, 0);
		if (F->Map == (u8*)-1)
		{
			fprintf(stderr, "failed to map stream index [%s] %i\n", Path, errno);
			return 0;	
		}
		madvise(F->Map, F->MapLength, POSIX_MADV_SEQUENTIAL);

		Header = (PCAPHeader_t*)F->Map;
	}
	else
	{
		int ret = fread(&Header1, 1, sizeof(Header1), F->F);
		if (ret != sizeof(PCAPHeader_t))
		{
			fprintf(stderr, "failed to read header\n");
			return NULL;
		}

		Header = &Header1;
		F->PacketBuffer	= malloc(32*1024);
	}

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
// get the next packet
static PCAPPacket_t* ReadPCAP(PCAPFile_t* PCAP)
{
	if (s_EnableMMAP)
	{
		if (PCAP->ReadPos >= PCAP->Length) return NULL;
		if (PCAP->ReadPos + sizeof(PCAPPacket_t) > PCAP->Length) return NULL; 

		PCAPPacket_t* Pkt = (PCAPPacket_t*)(PCAP->Map + PCAP->ReadPos);
		if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length) return NULL; 

		return Pkt;
	}
	else
	{
		int ret;
		PCAPPacket_t* Pkt = (PCAPPacket_t*)PCAP->PacketBuffer;
		ret = fread(Pkt, 1, sizeof(PCAPPacket_t), PCAP->F);
		if (ret != sizeof(PCAPPacket_t)) return NULL;

		if (PCAP->ReadPos + sizeof(PCAPPacket_t) + Pkt->LengthCapture > PCAP->Length) return NULL; 

		ret = fread(Pkt+1, 1, Pkt->LengthCapture, PCAP->F);
		if (ret != Pkt->LengthCapture) return NULL;
		return Pkt;
	}
}

//---------------------------------------------------------------------------------------------
// helpers for network formating 
static u64 PCAPTimeStamp(u32 FID, PCAPPacket_t* Pkt)
{
	s64 Offset = s_FileDiffTimeOffset[FID] * (double)Pkt->Length;
	return Offset + s_TimeZoneOffset + Pkt->Sec * k1E9 + Pkt->NSec;
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
static u128 PayloadHash(u8* Payload, u32 Length)
{
	/*
	u32 Hash[4];

	MurmurHash3_x86_32(Payload, Length, 0xbeefc0de, Hash);
	//printf("%08x %08x %08x %08x\n", Hash[0], Hash[1], Hash[2], Hash[3]);

	u64 Hash64 = 0;
	Hash64  = ((u64)Hash[0]<<32ULL) | (u64)Hash[1];
	Hash64 += ((u64)Hash[2]<<32ULL) | (u64)Hash[3];

	return Hash64; 
	*/

	// DEK packets usually have enough entropy for this to be enough 
	u128 Hash = 0; 
	for (int i=0; i < Length; i++)
	{
		Hash = ((Hash << 5ULL) ^ (Hash >> 123ULL)) ^ (u64)Payload[i];
	}
	return Hash;

/*
	// fnv-1a
	#define FNV_PRIME_32 16777619ULL
	#define FNV_OFFSET_32 2166136261ULL

    u64 hash = FNV_OFFSET_32, i;
    for(int i = 0; i < Length; i++)
    {
        hash = hash ^ ((u64)Payload[i]); 
        hash = hash * FNV_PRIME_32;
    }
    return hash;
*/
}

//---------------------------------------------------------------------------------------------
// usees a fifo of hash nodes and recycles then constantly

static u32*			s_IndexLevel0 = NULL;	// first level index

static HashNode_t* 	s_HashList = NULL;		// memory allocated for nodes
static u32			s_HashPos = 0;			// current allocation position
static u64			s_HashCnt = 0;			// total allocated cnt 
static u32			s_HashMax = 0;			// max number of hash positions 

static HashNode_t*	s_HashLRUHead = NULL;	// head (most recently used) of LRU ndoe list
static HashNode_t*	s_HashLRUTail = NULL;	// tail (least recently used) of nodes 

static void TracePacket(HashNode_t* N)
{
	printf("PacketTrace: Count:%i length:%4i Hash:%016llx_%016llx MAC:%016llx_%016llx\n", N->Cnt, N->Length, (u64)(N->Hash>>64), (u64)N->Hash, (u64)(N->MAC>>64), (u64)N->MAC);

	// no need to print no match packets 
	if (N->Cnt == 0) return;
	//if (N->Cnt == 1) return;

	int c = N->Cnt - 1;
	if (c > NODE_DEPTH-1) c = NODE_DEPTH-1;  

	int i=0;
	u64 LastTS = N->TS[c];
	for (; c >= 0; c--)
	{
		if (c >= NODE_DEPTH) break;

		u64 TS = N->TS[c];
		fEther_t* ETHn = PCAPETHHeader( N->Pkt[c] );

		printf("  [%i:%i]  %s %p | %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x | ", 
					i,
					N->FID[c],
					FormatTS(N->TS[c]),
					N->Pkt[c],

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

	bool DoSample = false;

	s64 TS0 	= 0x7fffffffffffffffULL; 
	s32 FID0 	= -1;

	s64 TS1 	= 0x7fffffffffffffffULL; 
	s32 FID1 	= -1;

	// special case of diffing 2 nearly identical files for latency deltas
	if (s_EnableFileDiff)
	{
		TS0 	= N->TS[0];
		FID0 	= N->FID[0];

		// find the first instance with FID0
		for (int c =0; c < N->Cnt; c++)
		{
			if (c >= NODE_DEPTH) break;

			if ((N->FID[c] == FID0) && (N->TS[c] < TS0))
			{
				TS0 = N->TS[c];
			}
		}

		// find first instance with !FID0 

		for (int c =0; c < N->Cnt; c++)
		{
			if (c >= NODE_DEPTH) break;

			if ((N->FID[c] != FID0) && (N->TS[c] < TS1))
			{
				TS1 	= N->TS[c];
				FID1 	= N->FID[c];
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

		// conditions to sample packet 

		if ((FID0 != -1) && (FID1 != -1))
		{
			// strict packet hashes
			DoSample 		|= (N->Cnt == 2);	
			DoSample 		|= ((!s_EnableFileDiffStrict) && (N->Cnt >= 2));
		}
	}
	// diff within a file
	else if (N->Cnt >= 2)
	{
		// search for the first + next packet
		if (!s_MACDiffEnable)
		{
			// find the first instance 
			for (int c =0; c < N->Cnt; c++)
			{
				if (c >= NODE_DEPTH) break;

				if (N->TS[c] < TS0)
				{
					TS0 	= N->TS[c];
					FID0 	= N->FID[0];
				}
			}

			// find next instance 

			for (int c =0; c < N->Cnt; c++)
			{
				if (c >= NODE_DEPTH) break;

				if ((N->TS[c] != TS0) && (N->TS[c] < TS1))
				{
					TS1 	= N->TS[c];
					FID1 	= N->FID[c];
				}
			}
		}
		else
		{
			// find the first instance 
			for (int c =0; c < N->Cnt; c++)
			{
				if (c >= NODE_DEPTH) break;

				u128* MAC = (u128*)(N->Pkt[c]+1);
				if ((swap128(MAC[0]) & s_MACMask) != s_MACDiff[0]) continue;

				if (N->TS[c] < TS0)
				{
					TS0 	= N->TS[c];
					FID0 	= N->FID[0];
				}
			}

			// find next instance 

			for (int c =0; c < N->Cnt; c++)
			{
				if (c >= NODE_DEPTH) break;

				u128* MAC = (u128*)(N->Pkt[c]+1);
				if ((swap128(MAC[0]) & s_MACMask) != s_MACDiff[1]) continue;
				if ((N->TS[c] != TS0) && (N->TS[c] < TS1))
				{
					TS1 	= N->TS[c];
					FID1 	= N->FID[c];
				}
			}

		}
		DoSample = true;	
	}

	if (DoSample)
	{
		// sample time delta
		if ((FID0 != -1) && (FID1 != -1) )
		{
			s64 dT 		= (TS1 - TS0);

			// online mean/stde calc 

			s_FileDiffSum0 += 1;
			s_FileDiffSum1 += dT;
			s_FileDiffSum2 += dT*dT;

			// center / align and slice dT for histogram 
			s64 dTH 	= dT;
			dTH 		= (dTH > s_LatencyHistoMax) ? s_LatencyHistoMax : dTH;
			dTH 		= (dTH < s_LatencyHistoMin) ? s_LatencyHistoMin : dTH;
			dTH			+= -s_LatencyHistoMin;

			// convert to histo buckets

			s32 Index 	= dTH / s_LatencyHistoUnit;
			Index 		= (Index < 0) ? 0 : Index;
			Index 		= (Index >= s_LatencyHistoCnt) ? s_LatencyHistoCnt -1 : Index;

			s_LatencyHisto[Index]++;

			if (labs(dT) > s_FileDiffLatencyTraceMin)
			{
				TracePacket(N);
			}
			//printf("%lli ns %016llx %016llx : %i %i\n", dT, TS0, TS1, FID0, FID1); 
		}
	}
	// packet was dropped for some reason 
	else
	{
		// update number of packets not seen in each file 
		bool MissingA = false;
		bool MissingB = false;
		for (int i=0; i < N->Cnt; i++)
		{
			switch (N->FID[i])
			{
			case 0: 
				s_FileDiffMissingA++; 
				MissingA = true;
				break;
			case 1: 
				s_FileDiffMissingB++; 
				MissingB = true;
				break;
			default:
					break;
			}
		}
		if (MissingA && s_FileDiffMissingTraceA) TracePacket(N);
		if (MissingB && s_FileDiffMissingTraceB) TracePacket(N);
		s_DroppedPkts += N->Cnt;
	}

	// count packets with hash overflow 
	if (N->Cnt >= NODE_DEPTH)
	{
		s_HashOverflow++;
		if (s_EnableTraceOverflow) TracePacket(N);
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

	// remove entry from the list

	if (N->Prev == 0)
	{
		s_IndexLevel0[ N->Hash & 0x00ffffff] = N->Next;
	}
	else
	{
		HashNode_t* NP = s_HashList + N->Prev;
		NP->Next = N->Next;
	}

	if (N->Next != 0)
	{
		HashNode_t* NP 	= s_HashList + N->Next;
		NP->Prev 		= N->Prev;
	}

	// remove from LRU list 
	NodeLRUUnlink(N);	

	memset(N, 0, sizeof(HashNode_t));
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
static void HashPacket(u32 FID, PCAPPacket_t* Pkt, u32 Type, u128 Hash, u32 Length)
{
	HashNode_t* N 	= NULL;

	u64 TS 		= PCAPTimeStamp(FID, Pkt); 
	u128* MAC 	= (u128*)(Pkt+1);

	// search for hash
	bool NodeHit = false;	
	u32 NIndex = s_IndexLevel0[ Hash & 0x00ffffff];
	if (NIndex != 0)
	{
		HashNode_t* NS = &s_HashList[NIndex];
		{
			u32 Count = 1e6;
			while (NS)
			{
				if ((NS->Hash == Hash) && 
					(NS->Type == Type) &&
					((!s_HashMatchMAC) | (NS->MAC == MAC[0]))
				){
					// can delete previous entries 
					s64 dT = TS - NS->TS[0];
					if (abs(dT) > s_TimeDeltaMaxNS)
					{
						// kick sample
						NodeOutput(NS);

						NS->Cnt = 0;

						NS->Pkt[0] 	= Pkt; 
						NS->TS [0] 	= TS; 
						NS->FID[0] 	= FID; 

						NodeHit 	= true;
						N 			= NS;

						NodeLRUUnlink(N);
					}
					else
					{
						NS->Cnt++;

						for (int i=NODE_DEPTH-1; i >= 1; i--)
						{
							NS->Pkt[i]	= NS->Pkt[i-1];
							NS->TS [i]	= NS->TS [i-1]; 
							NS->FID[i]	= NS->FID[i-1];
						}
						NS->Pkt[0] = Pkt; 
						NS->TS [0] = TS; 
						NS->FID[0] = FID; 

						NodeHit = true;
						N = NS;

						NodeLRUUnlink(N);
					}
					break;
				}
				if (NS->Next == 0)
				{
					break;
				}
				NS = s_HashList + NS->Next;
				assert(--Count != 0);
			}
		}
	}

	// allocate Node
	if (!NodeHit)
	{
		N = NodeAllocate(); 
		N->Hash 	= Hash;
		N->Pkt[0]	= Pkt;
		N->TS[0] 	= TS; 
		N->FID[0]	= FID;
		N->Cnt		= 1;
		N->Length	= Length;
		N->Type		= Type;
		N->MAC		= MAC[0];

		HashNode_t* OldN = &s_HashList[ s_IndexLevel0[ Hash & 0x00ffffff] ];
		N->Next = OldN - s_HashList;	

		OldN->Prev	= N - s_HashList;
		N->Prev = 0; 

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

	if (TCPLength > 16*1024)
	{
		fprintf(stderr, "bogus tcp packet: %i %i %i %i\n", TCPLength, swap16(IP4->Len), TCPOffset, IPOffset);
		return;
	}

	if ((TCPLength >= s_TCPLengthMin)  && (TCPLength <= s_TCPLengthMax))
	{
		if (TCPLength > s_TCPPayloadMax) TCPLength = s_TCPPayloadMax;

		// generate payload hash  
		u128 Hash = PayloadHash(TCPPayload, TCPLength); 
		HashPacket(FID, Pkt, PKTTYPE_TCP, Hash, TCPLength);

		// add to mac histogram 
		s_LengthHisto[Pkt->Length]++;
	}
	//printf("tcp %i %i %x %x %x : %08x\n", swap16(TCP->PortSrc), swap16(TCP->PortDst), TCPOffset, sizeof(TCPHeader_t)/4, TCP->Flags, TCPPayload[0]); 
}

//---------------------------------------------------------------------------------------------

static void UDPProcess(u32 FID, PCAPPacket_t* Pkt, fEther_t* E, IP4Header_t* IP4, u32 IPOffset)
{
	if (!s_UDPEnable) return;

	UDPHeader_t* UDP 	= (UDPHeader_t*)( ((u8*)IP4) + IPOffset);
	u8* Payload			= (u8*)(UDP + 1); 
	u32 Length 			= swap16(UDP->Length) + s_UDPLengthChomp;

	if (Length > 16*1024)
	{
		fprintf(stderr, "UDP length bogus %i\n", Length);
		return;
	}
	if ((Length >= s_UDPLengthMin) && (Length <= s_UDPLengthMax))
	{
		// generate payload hash  
		u128 Hash = PayloadHash(Payload, Length); 
		HashPacket(FID, Pkt, PKTTYPE_UDP, Hash, Length);

		s_LengthHisto[Length]++;
	}
}

//---------------------------------------------------------------------------------------------
// has the entire packet, mac/ip/headers/everything
static inline void ProcessHashFull(u32 FID, PCAPFile_t* PCAP, PCAPPacket_t* Pkt, u64 TS)
{
	fEther_t* E = PCAPETHHeader(Pkt);
	bool HashIt = false;
	switch (swap16(E->Proto))
	{
	case ETHER_PROTO_IPV4:
	{
		IP4Header_t* IP4 = PCAPIP4Header(Pkt); 
		u32 IPOffset = (IP4->Version & 0x0f)*4; 
		switch (IP4->Proto)
		{
		case IPv4_PROTO_TCP:
			if (s_EnableFullHashTCP)
			{
				TCPHeader_t* TCP = (TCPHeader_t*)( ((u8*)IP4) + IPOffset);

				// filter by length TCP packets to be fully hashed 

				u32 TCPOffset 	= ((TCP->Flags&0xf0)>>4)*4;
				u8* TCPPayload 	= (u8*)TCP + TCPOffset;
				u32 TCPLength 	= swap16(IP4->Len) - TCPOffset - IPOffset;
				if ((TCPLength >= s_TCPLengthMin)  && (TCPLength <= s_TCPLengthMax))
				{
					HashIt 		= true; 
					if (TCPLength < 16*1024)
					{
						s_LengthHisto[TCPLength]++;
					}
				}
			}
			break;

		case IPv4_PROTO_UDP: 
			HashIt = s_EnableFullHashUDP; 
			break;
		}
	}
	break;
	}

	// ignore protocol 
	if (s_EnableFullHashAll)
	{
		if (Pkt->Length >= s_FullHashLengthMin)
		{
			HashIt 		= true;
		}
	}

	// compensate for diffing between FCS and noFCS capture files
	if (HashIt)
	{
		u32 HashLength 	= Pkt->Length; 

		if (s_FileDiffNoFCS && (FID == 0) && s_FileDiffNoFCSFileB) HashLength -= 4;
		if (s_FileDiffNoFCS && (FID == 1) && s_FileDiffNoFCSFileA) HashLength -= 4;

		u128 Hash = PayloadHash((u8*)E, HashLength); 
		HashPacket(FID, Pkt, PKTTYPE_FULL, Hash, HashLength);
	}
}

//---------------------------------------------------------------------------------------------
// extract only the packload tcp/udp and hash with that
static inline void ProcessHashPayload(u32 FID, PCAPFile_t* PCAP, PCAPPacket_t* Pkt, u64 TS)
{
	fEther_t* E = PCAPETHHeader(Pkt);

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

	case ETHER_PROTO_MPLS:
	{
		MPLS_t* MPLS 		= (MPLS_t*)(E + 1);

		// strip all the tags
		for (int i=0; i < 8; i++)
		{
			u32 d 		= swap32(*((u32*)MPLS));
			u32 Label 	= (d >> 12)  & 0xfffff;
			u32 EOS 	= (d >> 8)  & 0x1;
			//printf("MPLS %i Label:%i %08x\n", EOS, Label, d);	

			if (EOS) break;
			MPLS += 1;
		}

		IP4Header_t* IP4 	= (IP4Header_t*)(MPLS + 1); 
		u32 IPOffset 		= (IP4->Version & 0x0f)*4; 

		switch (IP4->Proto)
		{
		case IPv4_PROTO_TCP: TCPProcess(FID, Pkt, E, IP4, IPOffset); break;
		case IPv4_PROTO_UDP: UDPProcess(FID, Pkt, E, IP4, IPOffset); break;
		}

	}
	break;
	}
}

//---------------------------------------------------------------------------------------------

static void PrintLatencyHisto(u32 PCAPCnt, PCAPFile_t* PCAPFile[])
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
	printf("  Min     : %10lli ns\n", s_LatencyHistoMin);
	printf("  Max     : %10lli ns\n", s_LatencyHistoMax);
	printf("  Unit    : %10lli ns\n", s_LatencyHistoUnit);
	printf("\n");

	// output histogram
	u32 HMin 	= s_LatencyHistoCnt-1;
	u32 HMax 	= 0;
	u64 Max		= 0; 
	u64 Total	= 0;
	for (int i=0; i < s_LatencyHistoCnt; i++)
	{
		if (s_LatencyHisto[i] == 0) continue; 

		HMin = (HMin > i) ? i : HMin;
		HMax = (HMax < i) ? i : HMax;
		Max = (s_LatencyHisto[i] > Max) ? s_LatencyHisto[i] : Max;
		Total += s_LatencyHisto[i];
	}
	u64 Sum = 0;
	for (int i=HMin; i <= HMax; i++)
	{
		Sum += s_LatencyHisto[i]; 
		s64 dT = s_LatencyHistoMin + i * s_LatencyHistoUnit;
		double Pct = (double)s_LatencyHisto[i] / (double)Max;
		printf("%8lli ns : %12lli %.4f (%.4f) : ", dT, s_LatencyHisto[i], Pct, Sum / (double)Total);

		int StarCnt = 50*Pct;
		if ((s_LatencyHisto[i] > 0) && StarCnt == 0) StarCnt = 1;

		for (int s=0; s < StarCnt; s++) printf("*");

		printf("\n");
	}
	printf("\n");

	if (PCAPCnt > 2)
	{
		printf("Missing Packets:\n");
		printf("  [%s] packets not in [%s] : %lli Pkts\n", PCAPFile[0]->Path, PCAPFile[1]->Path, s_FileDiffMissingA);  
		printf("  [%s] packets not in [%s] : %lli Pkts\n", PCAPFile[1]->Path, PCAPFile[0]->Path, s_FileDiffMissingB);  
	}
}

//---------------------------------------------------------------------------------------------

static void PrintLengthHisto(void)
{
	u64 MaxCnt = 0;
	u64 TotalSample = 0;
	for (int i=0; i < 16*1024; i += s_LengthHistoUnit)
	{
		u64 Cnt = 0;
		for (int j=0; j < s_LengthHistoUnit; j++)
		{
			Cnt += s_LengthHisto[i];
		}

		MaxCnt = Cnt > MaxCnt ?  Cnt : MaxCnt;
		TotalSample += Cnt; 
	}

	u64 Sum = 0;
	for (int i=0; i < 1500; i+= s_LengthHistoUnit)
	{
		u64 Cnt = 0;
		for (int j=0; j < s_LengthHistoUnit; j++)
		{
			Cnt += s_LengthHisto[i];
		}
		Sum += Cnt;
		printf("%4i B : %12lli (%.4f) : ", i, Cnt, Sum / (double)TotalSample);

		double Pct = (double)Cnt / (double)MaxCnt;
		int StarCnt = 100.0*Pct;
		if ((Cnt > 0) && StarCnt == 0) StarCnt = 1;
		for (int s=0; s < StarCnt; s++) printf("*");

		printf("\n");
	}
}

//---------------------------------------------------------------------------------------------

static void print_usage(void)
{
	printf("pcap_latency_analyzer: <pcap A> <pcap B>\n");
	printf("\n");
	printf("Version: %s %s\n", __DATE__, __TIME__);
	printf("Contact: support at fmad.io\n"); 
	printf("\n");
	printf("Options:\n");
	printf(" --packet-trace                  | write each packet events to stdout\n");
	printf(" --length-histo                  | print packet length histogram\n");
	printf(" --latency-histo                 | print latency histogram \n");
	printf(" --hash-memory                   | (int MB) amount of memory to use for hashing. default 128MB\n");
	printf(" --disable-mmap                  | use fread not mmap of the pcap files\n"); 
	printf(" --packet-time-delta-max         | reset time between new and old packets with the same hash.\n"); 
	printf(" --packet-max <number>           | maximum number of packets to process\n");
	printf("\n");
	printf(" --tcp-length <number>           | filter tcp packets to include only payload length of <number>\n");
	printf(" --tcp-length-chomp <number>     | set max tcp payload hash to be of length <number>. for packet slicing\n");
	printf(" --tcp-only                      | only match tcp packets\n"); 
	printf(" --udp-only                      | only match udp packets\n"); 
	printf(" --udp-length <number>           | specifiy udp packets of only length <number>\n"); 
	printf(" --udp-length-chomp <number>     | remove <number> bytes from the end of the UDP packet\n"); 
	printf("\n");
	printf("Hash the entire packet\n");
	printf(" --full-packet                   | use entire packet contents for hash (.e.g no protocol)\n"); 
	printf(" --full-packet-tcp-only          | use entire packet contents for hash but only for tcp packets\n"); 
	printf(" --full-packet-udp-only          | use entire packet contents for hash but only for udp packets\n"); 
	printf("\n");
	printf("Diff 2 PCAP files:");
	printf(" --file-diff                     | special mode of comparing packets between 2 files (instead of within the same file)\n");
	printf(" --file-diff                     | special mode of comparing packets between 2 files (instead of within the same file)\n");
	printf(" --file-diff-no-timesync         | do not attempt to time sync the two files. reads 1MB chunks at a time\n");
	printf(" --file-diff-strict              | only matches with two entries in a hash node will be sampled\n"); 
	printf(" --file-diff-nofcs-a             | file A has no FCS (ethernet crc) value\n"); 
	printf(" --file-diff-nofcs-b             | file B has no FCS (ethernet crc) value\n"); 
	printf(" --file-diff-missing-trace       | trace all packets that are missing\n"); 
	printf(" --file-diff-latency-trace <number in ns> | trace packets that have latency greather than <number>\n"); 
	printf("\n");
	printf("Diff 2 MAC address:\n");
	printf(" --mac-diff                      | compare packets from 2 mac address in a single PCAP\n");
	printf(" --mac-diff-a 00:11:22:33:44:55  | specify MAC address A\n"); 
	printf(" --mac-diff-b 66:77:88:99:aa:bb  | specify MAC address B\n"); 
	printf("\n");
	printf("Latency histogram shaping\n");
	printf(" --latency-histo-min             | minimum time delta for histogram. default -1e6 ns\n"); 
	printf(" --latency-histo-max             | maximum time delta for histogram. default 1e6 ns\n"); 
	printf(" --latency-histo-unit            | duration of a single histogram slot. default 100ns\n"); 

	printf("\n");
	printf(" --ts-last-byte-a                | adjust timestamp of first file A from last byte to first byte (assumes 10G)\n"); 
	printf(" --ts-last-byte-b                | adjust timestamp of first file B from last byte to first byte (assumes 10G)\n"); 
	printf("\n");
}

static u64 ParseMAC(char* sMAC)
{
	u64 MAC = 0;	
	u64 iMAC[6];
	for (int j=0; j < 6; j++) 
	{
		char c = sMAC[j*3 + 0];
		u8 m0 = 0;
		if ((c >= '0') && (c <= '9')) m0 = c - '0';
		if ((c >= 'a') && (c <= 'f')) m0 = 10 + c - 'a';
		if ((c >= 'A') && (c <= 'F')) m0 = 10 + c - 'A';

		c = sMAC[j*3 + 1];
		u8 m1 = 0;
		if ((c >= '0') && (c <= '9')) m1 = c - '0';
		if ((c >= 'a') && (c <= 'f')) m1 = 10 + c - 'a';
		if ((c >= 'A') && (c <= 'F')) m1 = 10 + c - 'A';

		iMAC[j] = (m0<<4) | m1;
		fprintf(stderr, "%02llx ", iMAC[j]); 
	}
	fprintf(stderr, " ass\n");

	MAC = 	(iMAC[0]<<(8*5ULL)) | 
		(iMAC[1]<<(8*4ULL)) | 
		(iMAC[2]<<(8*3ULL)) | 
		(iMAC[3]<<(8*2ULL)) | 
		(iMAC[4]<<(8*1ULL)) | 
		(iMAC[5]<<(8*0ULL));

	return MAC;
}

//---------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	int 	FileNameListPos = 0;
	char 	FileNameList[16][256];

	memset(s_FileDiffTimeOffset, 0, sizeof(s_FileDiffTimeOffset));

	for (int i=1; i < argc; i++)
	{
		if (argv[i][0] != '-')
		{
			strcpy(FileNameList[FileNameListPos], argv[i]);
			FileNameListPos++;
		}
		else
		{
			if (strcmp(argv[i], "--packet-trace") == 0)
			{
				s_EnablePacketTrace = true;
			}
			// specifiy an exact tcp length to use 
			else if (strcmp(argv[i], "--tcp-length") == 0)
			{
				s_TCPLengthMin = atoi(argv[i+1]);	
				s_TCPLengthMax = atoi(argv[i+1]);	

				fprintf(stderr, "TCP Length == %i\n", s_TCPLengthMin);
				i += 1;
			}
			// specifiy an exact udp length to use 
			else if (strcmp(argv[i], "--udp-length") == 0)
			{
				s_UDPLengthMin = atoi(argv[i+1]);	
				s_UDPLengthMax = atoi(argv[i+1]);	

				fprintf(stderr, "UDP Length == %i\n", s_UDPLengthMin);
				i += 1;
			}
			// chomp tcp length 
			else if (strcmp(argv[i], "--tcp-length-chomp") == 0)
			{
				s_TCPPayloadMax = atoi(argv[i+1]);	
				fprintf(stderr, "TCP Length Chomp == %i\n", s_TCPPayloadMax);
				i += 1;
			}
			// chomp the udp length 
			else if (strcmp(argv[i], "--udp-length-chomp") == 0)
			{
				s_UDPLengthChomp = -atoi(argv[i+1]);	
				fprintf(stderr, "UDP Length Chomp == %i\n", s_UDPLengthChomp);
				i += 1;
			}
			// only check tcp packets
			else if (strcmp(argv[i], "--tcp-only") == 0)
			{
				s_TCPEnable = true;
				s_UDPEnable = false;
			}
			// only check UDP packets
			else if (strcmp(argv[i], "--udp-only") == 0)
			{
				s_TCPEnable = false;
				s_UDPEnable = true;
			}

			// full packet hash 
			else if (strcmp(argv[i], "--full-packet") == 0)
			{
				s_TCPEnable 		= false;
				s_UDPEnable 		= false;
				s_EnableFullHash 	= true;
				s_EnableFullHashAll = true;
				s_EnableFullHashTCP = true;
				s_EnableFullHashUDP = true;
				s_HashMatchMAC		= true;
			}
			else if (strcmp(argv[i], "--full-packet-tcp-only") == 0)
			{
				s_EnableFullHash 	= true;
				s_EnableFullHashTCP = true;
				s_EnableFullHashUDP = false;
				s_HashMatchMAC		= true;
			}
			else if (strcmp(argv[i], "--full-packet-udp-only") == 0)
			{
				s_EnableFullHash 	= true;
				s_EnableFullHashTCP = false;
				s_EnableFullHashUDP = true;
				s_HashMatchMAC		= true;
			}
			// specal case of 2 pcap diff. compare first hash entrys between files
			else if (strcmp(argv[i], "--file-diff") == 0)
			{
				s_EnableFileDiff 	= true;
			}
			// output latency histo 
			else if (strcmp(argv[i], "--latency-histo") == 0)
			{
				fprintf(stderr, "outputing latency histogram\n");
				s_LatencyHistoEnable = true;
			}
			// min file diff position 
			else if (strcmp(argv[i], "--latency-histo-min") == 0)
			{
				s_LatencyHistoMin	= atoi(argv[i+1]); 
				i+= 1;
			}
			// max file diff position 
			else if (strcmp(argv[i], "--latency-histo-max") == 0)
			{
				s_LatencyHistoMax	= atoi(argv[i+1]);
				i+= 1;
			}
			// unit size of each sample 
			else if (strcmp(argv[i], "--latency-histo-unit") == 0)
			{
				s_LatencyHistoUnit= atoi(argv[i+1]);
				i+= 1;
			}
			// use pure byte based file synching 
			else if (strcmp(argv[i], "--file-diff-no-timesync") == 0)
			{
				s_EnableFileDiffTimeSync = false;	
			}
			// dont do strict file diff 
			else if (strcmp(argv[i], "--file-diff-strict") == 0)
			{
				s_EnableFileDiffStrict = true;	
			}
			// indicate file A has no FCS 
			else if (strcmp(argv[i], "--file-diff-nofcs-a") == 0)
			{
				s_FileDiffNoFCSFileA 	= true;
				s_FileDiffNoFCS			= true;
			}
			// indicate file B has no FCS 
			else if (strcmp(argv[i], "--file-diff-nofcs-b") == 0)
			{
				s_FileDiffNoFCSFileB 	= true;
				s_FileDiffNoFCS			= true;
			}
			// trace packets missing from file A 
			else if (strcmp(argv[i], "--file-diff-missing-trace-a") == 0)
			{
				s_FileDiffMissingTraceA	= true;
			}
			// trace packets missing from file B 
			else if (strcmp(argv[i], "--file-diff-missing-trace-b") == 0)
			{
				s_FileDiffMissingTraceB	= true;
			}
			// trace packets with latency above the specified threshold 
			else if (strcmp(argv[i], "--file-diff-latency-trace") == 0)
			{
				s_FileDiffLatencyTraceMin = atol(argv[i+1]); 
				i++;

				fprintf(stderr, "enabling file diff latency trace with threshold of %lli ns\n", s_FileDiffLatencyTraceMin);
			}
			else if (strcmp(argv[i], "--mac-diff") == 0)
			{
				fprintf(stderr, "comparing MACs\n");
				s_MACDiffEnable = true;

				s_MACMask 	= 0xffffffffffffULL;
				s_MACMask	= (s_MACMask << (8ULL*4));
			}
			else if (strcmp(argv[i], "--mac-diff-a") == 0)
			{
				u64 MAC = ParseMAC(argv[i+1]);	
		
				fprintf(stderr, "diff A MACs %016llx\n", MAC);
				s_MACDiff[0] = (u128)MAC<<(4*8ULL); 
				i++;
			}
			else if (strcmp(argv[i], "--mac-diff-b") == 0)
			{
				u64 MAC = ParseMAC(argv[i+1]);	
		
				fprintf(stderr, "diff B MACs %016llx\n", MAC);
				s_MACDiff[1] = (u128)MAC<<(4*8ULL); 
				i++;
			}


			// adjust file A timestamp to start of packet (from end of packet) 
			else if (strcmp(argv[i], "--ts-last-byte-a") == 0)
			{
				fprintf(stderr, "Adjusting file A timestamp to start of packet (from end of packet)\n");
				s_FileDiffTimeOffset[0] = -(1e9 / 10e9) * 8.0;
			}
			// adjust file B timestamp to start of packet (from end of packet) 
			else if (strcmp(argv[i], "--ts-last-byte-b") == 0)
			{
				fprintf(stderr, "Adjusting file B timestamp to start of packet (from end of packet)\n");
				s_FileDiffTimeOffset[1] = -(1e9 / 10e9) * 8.0;
			}
			// amount of memory to allocate for hash nodes 
			else if (strcmp(argv[i], "--hash-memory") == 0)
			{
				s_HashMemory = atoi(argv[i+1])*1024*1024;
				i+= 1;
			}
			// use fread of the data
			else if (strcmp(argv[i], "--disable-mmap") == 0)
			{
				fprintf(stderr, "data using fread\n");
				s_EnableMMAP = false; 
			}
			// max packet time deltea between new & old packet
			// before reseting a node
			else if (strcmp(argv[i], "--packet-time-delta-max") == 0)
			{
				fprintf(stderr, "setting max time delta\n");
				s_TimeDeltaMaxNS = atoi(argv[i+1]); 
				i+= 1;
			}
			else if (strcmp(argv[i], "--wtf") == 0)
			{
				fprintf(stderr, "wtf mode\n");
				s_EnableWTF = true;	
			}
			else if (strcmp(argv[i], "--length-histo") == 0)
			{
				fprintf(stderr, "packet length histogram\n");
				s_EnableLengthHisto = true;	
			}
			else if (strcmp(argv[i], "--packet-max") == 0)
			{
				s_MaxPackets = atoll(argv[i+1]); 
				fprintf(stderr, "setting maximum number of packets to %lli\n", s_MaxPackets);
				i+= 1;
			}
			else
			{
				fprintf(stderr, "unknown option [%s]\n", argv[i]);
				return 0;
			}
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

	// calcuate tsc frequency
	CycleCalibration();

	// get timezone offset

  	time_t t = time(NULL);
	struct tm lt = {0};

	localtime_r(&t, &lt);
	s_TimeZoneOffset = lt.tm_gmtoff * 1e9;
	
	// open pcap diff files

	PCAPFile_t* PCAPFile[16];
	memset(PCAPFile, 0, sizeof(PCAPFile));
	for (int i=0; i < FileNameListPos; i++)
	{
		PCAPFile[i] = OpenPCAP(FileNameList[i]);	
		if (!PCAPFile[i]) return 0;

		// get starting time 
		PCAPPacket_t* Pkt = ReadPCAP(PCAPFile[i]); 
		u64 TS = PCAPTimeStamp(i, Pkt);

		printf("[%30s] FileSize: %lliGB %s\n", PCAPFile[i]->Path, PCAPFile[i]->Length / kGB(1), FormatTS(TS)); 
	}

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

	s_LatencyHistoCnt 	= (s_LatencyHistoMax  - s_LatencyHistoMin) /  s_LatencyHistoUnit;
	s_LatencyHisto 	= (u64*)malloc(sizeof(u64) *  s_LatencyHistoCnt);
	memset(s_LatencyHisto, 0, sizeof(u64) * s_LatencyHistoCnt);

	// packet length histogram
	memset(s_LengthHisto, 0, sizeof(s_LengthHisto));

	u64 TotalLength = 0;
	for (int FID=0; FID < FileNameListPos; FID++)
	{
		TotalLength += PCAPFile[FID]->Length;	
	}

	u64 SyncTS  		= 0; 
	u64 TotalByte 		= 0;
	u64 TotalPkt 		= 0;
	u64 NextPrintTSC 	= 0;
	u64 StartTSC		= rdtsc();	
	while (true)
	{
		bool Done = true;
		for (int FID=0; FID < FileNameListPos; FID++)
		{
			if (!PCAPFile[FID]->Finished) Done = false;
		}
		if (Done) break;

		for (int FID=0; FID < FileNameListPos; FID++)
		{
			PCAPFile_t* PCAP = PCAPFile[FID];
			u64 StartPos = PCAP->ReadPos;

			// read next 1MB

			while (true)
			{
				PCAPPacket_t* Pkt = ReadPCAP(PCAP); 
				if (!Pkt)
				{
					PCAP->Finished = true;
					break;
				}

				PCAP->TS = PCAPTimeStamp(FID, Pkt);
				// want to increment file 0 by 128KB each time, but want 
				// the other file to attempt time sync with file0. this maximizes
				// the hash cache
				if (s_EnableFileDiffTimeSync)
				{
					if (FID == 0)
					{
						if (PCAP->ReadPos > StartPos + kMB(1)) break;

						// include fudge window
						SyncTS  = PCAP->TS;
					}
					else
					{
						if (PCAP->TS > SyncTS)
						{
							// when File0`s last timestamp is less thean FileA 
							if (!PCAPFile[0]->Finished)
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

				if (s_EnableFullHash) 	ProcessHashFull(FID, PCAP, Pkt, PCAP->TS);
				else					ProcessHashPayload(FID, PCAP, Pkt, PCAP->TS);

				PCAP->ReadPos += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
				PCAP->PktCnt++;

				TotalPkt++;
				TotalByte += sizeof(PCAPPacket_t) + Pkt->LengthCapture;
			}
		}

		if (rdtsc() > NextPrintTSC)
		{
			u64 TSC = rdtsc();
			NextPrintTSC = TSC + 3e9;

			static u64 LastTSC = 0;
			double dT = tsc2ns(TSC - LastTSC) / 1e9;
			LastTSC = TSC;

			static u64 LastByte = 0;
			double Bps = (TotalByte - LastByte) / dT;
			LastByte = TotalByte;

			double TotalTime = tsc2ns(TSC - StartTSC);
			double ETA = TotalLength * (TotalTime / (double)TotalByte);
			double Min = (ETA - TotalTime) / 60e9;

			fprintf(stderr, "[");
			for (int f=0; f < FileNameListPos; f++)
			{
				u64 TSf = PCAPFile[f]->TS; 
				fprintf(stderr, "%.2f%% %s  ", PCAPFile[f]->ReadPos / (double)PCAPFile[f]->Length, FormatTS(TSf)); 
			}

			u64 Depth = 0; //NodeLRUValidate();
			fprintf(stderr, "] %.2fM Pkts %.3fGbps : %.2fGB UPkt:%lli Hit:%.f Over:%lli ETA %.2fMin\n", 
					TotalPkt / 1e6, 
					(8.0*Bps) / 1e9,
					TotalByte / 1e9, 
					s_HashCnt,
					s_FileDiffSum0,
					s_HashOverflow,
					Min
			);
		}
		if (TotalPkt > s_MaxPackets) break;
	}

	//fProfile_Dump(15);
	printf("Reading Done\n");

	printf("Validating...\n");
	NodeLRUValidate();

	// dump out remaining nodes
	printf("Flushing..\n");
	HashFlush();		

	printf("Done\n");

	printf("Hash Overflow:  %lli\n", s_HashOverflow);
	printf("Dropped      : %lli\n", s_DroppedPkts);
	printf("Process Time : %.2fMin\n", tsc2ns(rdtsc() - StartTSC) / 60e9);

	printf("FileStats:\n");
	for (int i=0; i < FileNameListPos; i++)
	{
		printf("  %12lli Pkts [%-30s]\n", PCAPFile[i]->PktCnt, PCAPFile[i]->Path);
	}
	printf("\n");

	if (s_EnableLengthHisto) PrintLengthHisto();
	if (s_LatencyHistoEnable) PrintLatencyHisto(FileNameListPos, PCAPFile);

	printf("Total : %lli\n", s_HashOverflow + s_DroppedPkts + (u64)s_FileDiffSum0);

}

/* vim: set ts=4 sts=4 */
