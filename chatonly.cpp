#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
typedef unsigned char uchar;
#define HUFFMAN_LUTBITS		(10)
#define HUFFMAN_LUTSIZE 	(1<<HUFFMAN_LUTBITS)
enum { NETSENDFLAG_VITAL = 1, NETSENDFLAG_CONNLESS = 2, NETSENDFLAG_FLUSH = 4 };
enum { STATE_CONNECTING = 1, STATE_LOADING, STATE_ONLINE };
static int new_tick = -1;
#if defined(WIN64) || defined(_WIN64) || defined(WIN32) || defined(_WIN32) || defined(__CYGWIN32__) || defined(__MINGW32__)
	#define CONF_FAMILY_WINDOWS 1
	#define WIN32_LEAN_AND_MEAN
	#undef _WIN32_WINNT
	#define _WIN32_WINNT 0x0501 /* required for mingw to get getaddrinfo to work */
	#include <windows.h>
	#include <winsock2.h>
	#include <ws2tcpip.h>
	#include <direct.h>
	#include <process.h>
	#include <shellapi.h>
	#include <wincrypt.h>
long long time_freq() {
	long long t;
	QueryPerformanceFrequency((PLARGE_INTEGER)&t);
	return t;
}
long long time_get() {
	static long long last = 0;
	if(new_tick == 0)	return last;
	if(new_tick != -1)	new_tick = 0;
	long long t;
	QueryPerformanceCounter((PLARGE_INTEGER)&t);
	if(t<last) /* for some reason, QPC can return values in the past */
		return last;
	last = t;
	return t;
}
#endif
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__LINUX__) || defined(__linux__) || defined(__GNU__) || defined(__gnu__) || defined(__sun) || defined(MACOSX) || defined(__APPLE__) || defined(__DARWIN__)
	#include <sys/time.h>
	#include <unistd.h>
	#include <sys/socket.h>
	#include <sys/ioctl.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <dirent.h>
#if defined(MACOSX) || defined(__APPLE__) || defined(__DARWIN__)
	#include <mach/mach_time.h>
long long time_freq() { return 1000000000; }
long long time_get() {
	static long long last = 0;
	if(new_tick == 0)	return last;
	if(new_tick != -1)	new_tick = 0;
	static int got_timebase = 0;
	mach_timebase_info_data_t tb;
	if(!got_timebase)
		mach_timebase_info(&tb);
	uint64_t time = mach_absolute_time();
	last = (time / tb.denom) * tb.numer + (time % tb.denom) * tb.numer / tb.denom;
	return last;
}
#else
long long time_freq() { return 1000000; }
long long time_get() {
	static long long last = 0;
	if(new_tick == 0)	return last;
	if(new_tick != -1)	new_tick = 0;
	struct timespec spec;
	clock_gettime(CLOCK_MONOTONIC, &spec);
	last = (long long)spec.tv_sec*(long long)1000000+(long long)spec.tv_nsec/1000;
	return last;
}
#endif
#endif
// Format: ESDDDDDD EDDDDDDD EDD... Extended, Data, Sign
static uchar *cviPack(uchar *pDst, int i) {
	*pDst = (i>>25)&0x40; // set sign bit if i<0
	i = i^(i>>31); // if(i<0) i = ~i
	*pDst |= i&0x3F; // pack 6bit into dst
	i >>= 6; // discard 6 bits
	if(i) {
		*pDst |= 0x80; // set extend bit
		do {
			pDst++;
			*pDst = i&(0x7F); // pack 7bit
			i >>= 7; // discard 7 bits
			*pDst |= (i!=0)<<7; // set extend bit (may branch)
		} while (i);
	}
	pDst++;
	return pDst;
}
static const uchar *cviUnpack(const uchar *pSrc, int *pInOut) {
	int Sign = (*pSrc>>6)&1;
	*pInOut = *pSrc&0x3F;
	for (int i = 6; i <= 27 && *pSrc&0x80; i+=7) 
		*pInOut |= (*++pSrc&(0x7F))<<(i);
	*pInOut ^= -Sign; // if(sign) *i = ~(*i)
	return pSrc + 1;
}
struct CMsgPacker {
	uchar m_aBuffer[(1024*2)], *mpc, *m_pEnd;
	int Size() const { return (int)(mpc-m_aBuffer); }
	void AddInt(int i) { mpc = cviPack(mpc, i); }
	void AddString(const char *pStr, int Limit) {
		for(; *pStr && Limit != 0; Limit--)
			*mpc++ = *pStr++;
		*mpc++ = 0;
	}
	CMsgPacker(int Type) {
		mpc = m_aBuffer;
		AddInt(Type);
	}
};
struct ss_item {
	int m_TypeAndID;
	int *Data() { return (int *)(this+1); }
	int Type() { return m_TypeAndID>>16; }
	int ID() { return m_TypeAndID&0xffff; }
	int Key() { return m_TypeAndID; }
};
struct CSnapshot {
	int d_size, numitems;
	int *Offsets() const { return (int *)(this+1); }
	char *DataStart() const { return (char*)(Offsets()+numitems); }
};
uchar r_cdata[(1400-6)], c_cdata[(1400-6)];
static const uchar magic[] = {'T', 'K', 'E', 'N'};
unsigned short m_seq, m_Ack, m_PeerAck;
long long last_stime;
bool r_Valid;
struct sockaddr_in sa;
struct CClientData {
	char m_aName[16];
	int m_Team;
} m_aClients[64];
char m_bData[65536];
int d_size, offs[1024], numitems, nnodes, r_cchunk, m_ddsent, r_flags, r_ack, r_numc, r_dsize;
int c_flags, c_numc, c_dsize, m_Socket, mstate, astate, ss_parts, s_token, crecv_tick, m_ReceivedSnapshots;
void *NewItem(int Type, int ID, int Size) {
	if (d_size+sizeof(ss_item)+Size >= 65536 || numitems+1 >= 1024 || Type >= (1<<16))
		return 0;
	ss_item *pObj = (ss_item *)(m_bData + d_size);
	memset(pObj, 0, sizeof(ss_item) + Size);
	pObj->m_TypeAndID = (Type<<16)|ID;
	offs[numitems++] = d_size;
	d_size += sizeof(ss_item) + Size;
	return pObj->Data();
}
struct CHolder {
	CHolder *m_pPrev, *m_pNext;
	long long m_Tagtime;
	int m_Tick, m_SnapSize;
	CSnapshot *m_pSnap, *m_pAltSnap;
} *m_pFirst, *m_pLast, *m_ss[2]; /* 0 = current, 1 = previous */
struct CNode {
	unsigned m_Bits, m_NumBits;
	unsigned short m_aLeafs[2];
	uchar m_Symbol;
} m_aNodes[(257*2-1)], *m_apDecodeLut[HUFFMAN_LUTSIZE], *m_pStartNode;
void Setbits_r(CNode *pNode, int Bits, unsigned Depth) {
	if(pNode->m_aLeafs[1] != 0xffff)
		Setbits_r(&m_aNodes[pNode->m_aLeafs[1]], Bits|(1<<Depth), Depth+1);
	if(pNode->m_aLeafs[0] != 0xffff)
		Setbits_r(&m_aNodes[pNode->m_aLeafs[0]], Bits, Depth+1);
	if(pNode->m_NumBits) {
		pNode->m_Bits = Bits;
		pNode->m_NumBits = Depth;
	}
}
uchar *Unpack(uchar *pData, int *flag, int *size, int *seq) {
	*flag = (pData[0]>>6)&3;
	*size = ((pData[0]&0x3f)<<4) | (pData[1]&0xf);
	*seq = -1;
	if((*flag)&NETSENDFLAG_VITAL) {
		*seq = ((pData[1]&0xf0)<<2) | pData[2];
		return pData + 3;
	}
	return pData + 2;
}
void SendPacket(int Socket, int flags, int ack, int numc, int datasize, uchar *data, int SecurityToken) {
	uchar aBuffer[1400]; /* max packet size */
	if (SecurityToken != 0) { /* supported, append security token */
		// if SecurityToken is -1 (unknown) we will still append it hoping to negotiate it
		memcpy(&data[datasize], &SecurityToken, sizeof(SecurityToken));
		datasize += sizeof(SecurityToken);
	}
	memcpy(&aBuffer[3], data, datasize);
	flags &= ~8; /* compression flag */
	aBuffer[0] = ((flags<<4)&0xf0)|((ack>>8)&0xf);
	aBuffer[1] = ack&0xff;
	aBuffer[2] = numc;
	sendto((int)Socket, (const char*)aBuffer, datasize + 3, 0, (struct sockaddr *)&sa, sizeof(sa));
}
void Flush() {
	if(!c_numc && !c_flags)
		return;
	SendPacket(m_Socket, c_flags, m_Ack, c_numc, c_dsize, c_cdata, s_token);
	last_stime = time_get();
	c_flags = c_dsize = c_numc = 0;
	memset(c_cdata, 0, sizeof(c_cdata));
}
void SendControl(int ControlMsg, const void *pExtra, int ExtraSize) {
	last_stime = time_get();
	uchar buf[(1400-6)];
	buf[0] = ControlMsg;
	memcpy(&buf[1], pExtra, ExtraSize);
	SendPacket(m_Socket, 1, m_Ack, 0, 1+ExtraSize, buf, s_token);
}
int cRecv(int *flags, int *datasize, void **data) {
	while(1) {
		int hflags, hsize, hseq, Bytes;
		uchar *pEnd = r_cdata + r_dsize;
		while(1) {
			uchar *pData = r_cdata;
			if(!r_Valid || r_cchunk >= r_numc) {
				r_Valid = false;
				break;
			}
			for(int i = 0; i < r_cchunk; i++) {
				pData = Unpack(pData, &hflags, &hsize, &hseq);
				pData += hsize;
			}
			pData = Unpack(pData, &hflags, &hsize, &hseq);
			r_cchunk++;
			if(pData+hsize > pEnd) {
				r_Valid = false;
				break;
			}
			if((hflags&NETSENDFLAG_VITAL)) { // anti spoof
				if(hseq == (m_Ack+1)%(1<<10)) { /* max sequence */
					m_Ack = hseq;
				} else { //IsSeqInBackroom (old packet that we already got)
					int Bottom = (m_Ack-(1<<10)/2);
					if(Bottom < 0) {
						if((hseq <= m_Ack)||(hseq >= (Bottom + (1<<10))))
							continue;
					} else {
						if(hseq <= m_Ack && hseq >= Bottom)
							continue;
					}
					c_flags |= 4; /* resend flag */
					continue; // take the next chunk in the packet
				}
			}
			*flags = hflags;
			*datasize = hsize;
			*data = *(void **)&pData;
			return 1;
		}
		uchar sbuf[128] = { 0 }, rbuf[1400]; /* max packet size */
		socklen_t fromlen = sizeof(sockaddr_in);
		if((Bytes = recvfrom(m_Socket, (char*)rbuf, 1400, 0, (struct sockaddr *)&sbuf, &fromlen)) <= 0)
			break;
		if(Bytes < 3 || Bytes > 1400) /* packet header size */
			continue;
		r_flags = rbuf[0]>>4;
		r_ack = ((rbuf[0]&0xf)<<8) | rbuf[1];
		r_numc = rbuf[2];
		r_dsize = Bytes - 3; /* packet header size */
		if ((r_flags&2)) /* connless flag */
			continue;
		if(r_flags&8) { /* compression flag */
			if(r_flags&1) /* control flag, don't allow compression */
				return -1;
			uchar *pDst = (uchar *)r_cdata, *pSrc = (uchar *)&rbuf[3];
			uchar *pDstEnd = pDst+sizeof(r_cdata), *pSrcEnd = pSrc+r_dsize;
			unsigned Bits = 0, Bitcount = 0;
			CNode *pNode = 0, *pEof = &m_aNodes[256];
			while(1) {
				pNode = 0; // {A} try to load a node now
				if(Bitcount >= HUFFMAN_LUTBITS)
					pNode = m_apDecodeLut[Bits&(HUFFMAN_LUTSIZE-1)];
				while(Bitcount < 24 && pSrc != pSrcEnd) { // {B} fill with new bits
					Bits |= (*pSrc++) << Bitcount;
					Bitcount += 8;
				}
				if(!pNode) // {C} load symbol now if we didn't at location {A}
					pNode = m_apDecodeLut[Bits&(HUFFMAN_LUTSIZE-1)];
				if(!pNode) {
					r_dsize = -1;
					break;
				} // {D} check if we hit a symbol already
				if(pNode->m_NumBits) { // remove the bits for that symbol
					Bits >>= pNode->m_NumBits;
					Bitcount -= pNode->m_NumBits;
				} else { // remove the bits that the lut checked up for us
					Bits >>= HUFFMAN_LUTBITS;
					Bitcount -= HUFFMAN_LUTBITS;
					while(1) { /* traverse tree */
						pNode = &m_aNodes[pNode->m_aLeafs[Bits&1]];
						Bitcount--; /* remove bit */
						Bits >>= 1;
						if(pNode->m_NumBits) /* check if hit symbol */
							break;
						if(Bitcount == 0) { /* no more bits, decode error */
							r_dsize = -1;
							break;
						}
					}
				}
				if(pNode == pEof) /* check for eof */
					break;
				if(pDst == pDstEnd) { /* output character */
					r_dsize = -1;
					break;
				}
				*pDst++ = pNode->m_Symbol;
			}
			r_dsize = (int)(pDst - (const uchar *)r_cdata);		
		} else {
			memcpy(r_cdata, &rbuf[3], r_dsize);
		}
		if (r_dsize < 0)
			continue;
		if (s_token != -1 && s_token != 0) { /* check security token */
			if (r_dsize < (int)sizeof(s_token))
				continue;
			r_dsize -= sizeof(s_token);
		}
		// check if actual ack value is valid(own sequence..latest peer ack)
		if (((m_seq >= m_PeerAck) && (r_ack < m_PeerAck || r_ack > m_seq)) ||
		    ((m_seq < m_PeerAck) && (r_ack < m_PeerAck && r_ack > m_seq)))
			continue;
		m_PeerAck = r_ack; /* control message, connectaccept */
		if ((r_flags&1) && (astate == STATE_CONNECTING) && r_cdata[0] == 2) {
			if (s_token == -1 && r_dsize >= (int)(1 + sizeof(magic) + sizeof(s_token)) &&
			    !memcmp(&r_cdata[1], magic, sizeof(magic))) {
				int *pd = (int *)&r_cdata[1 + sizeof(magic)];
				s_token = (int)pd[0]|(pd[1]<<8)|(pd[2]<<16)|(pd[3]<<24);
				printf("got connect+accept (token %d)\n", s_token);
			} else {
				s_token = 0;
				printf("got connect+accept (token unsupported)\n");
			}
			SendControl(3, 0, 0); /* accept control msg */
			astate = STATE_ONLINE;
		}
		r_cchunk = 0;
		r_Valid = true;
	}
	return 0;
}
int SendMsgEx(CMsgPacker *pMsg, int Flags, bool sys) {
	uchar *pcd, *mpd = (uchar *)pMsg->m_aBuffer;
	*mpd = (*mpd << 1) | sys; /* store system flag in msg id */
	if(Flags&NETSENDFLAG_VITAL)
		m_seq = (m_seq+1)%(1<<10); /* max sequence */
	if ((pMsg->Size() >= (1400-6))) /* max payload */
		return -1;
	if(c_dsize + pMsg->Size() + 5 > (int)sizeof(c_cdata) - (int)sizeof(int))
		Flush(); /* if not enough space (chunk header size = 5) */
	pcd = &c_cdata[c_dsize];
	pcd[0] = ((Flags&3)<<6)|((pMsg->Size()>>4)&0x3f);
	pcd[1] = (pMsg->Size()&0xf);
	if(Flags&NETSENDFLAG_VITAL) {
		pcd[1] |= (m_seq>>2)&0xf0;
		pcd[2] = m_seq&0xff;
		pcd += 3;
	} else {
		pcd += 2;
	}
	memcpy(pcd, mpd, pMsg->Size());
	pcd += pMsg->Size();
	c_numc++;
	c_dsize = (int)(pcd-c_cdata);
	if(Flags&NETSENDFLAG_FLUSH)
		Flush();
	return 0;
}
void handle_snapshot (int parts, int Part, int psize, int GameTick, int DeltaTick, char *pData) {
	char incomingdata[65536];
	if (psize > (65536 - Part*900))
		psize = (65536 - Part*900);
	memcpy((char*)incomingdata + Part*900, pData, psize); /* max snapshot packsize */
	ss_parts |= 1<<Part;
	if(ss_parts != (unsigned)((1<<parts)-1))
		return;
	static CSnapshot Emptysnap;
	CSnapshot *deltas = &Emptysnap;
	uchar buf2[65536], buf3[65536];
	ss_parts = 0; // find snapshot that we should use as delta
	Emptysnap.numitems = Emptysnap.d_size = 0;
	CHolder *eHolder = m_pFirst; 
	for (; eHolder; eHolder = eHolder->m_pNext)
		if(eHolder->m_Tick == DeltaTick) {
			deltas = eHolder->m_pSnap;
			break;
		}
	if (DeltaTick >= 0 && !eHolder) {
		printf("error, couldn't find the delta snapshot\n");
		return;
	}
	const uchar *pSrc = (uchar *)incomingdata, *eEnd = pSrc+((parts-1)*900+psize);
	int d, dsz, isize, *pDst = (int *)buf2;
	while(pSrc < eEnd)
		pSrc = cviUnpack(pSrc, pDst++);
	if ((dsz = (long)((uchar *)pDst-(uchar *)buf2)) < 0)
		return; /* failure during decompression, bail */
	int *mData = (int *)buf2;
	int num_deleted = *mData++;
	int num_update = *mData++;
	int *pEnd = (int *)(((char *)buf2 + dsz));
	short isz[64] = { 0, 40, 24, 20, 16, 12, 32, 16, 60, 88, 20, 68, 12, 
				8, 8, 8, 8, 12, 12, 12, 12, 0 };
	d_size = numitems = 0;
	mData += num_deleted + 1; /* unpack deleted stuff */
	if(mData > pEnd)
		return;
	for(int i = 0; i < deltas->numitems; i++) { /* copy non-deleted stuff */
		ss_item *ifrom = (ss_item *)(deltas->DataStart() + deltas->Offsets()[i]);
		isize = (i == deltas->numitems-1) ? deltas->d_size : deltas->Offsets()[i+1];
		isize -= (deltas->Offsets()[i] + sizeof(ss_item));
		for (d = 0; d < num_deleted; d++)
			if(mData[d] == ifrom->Key())
				break;
		if(d >= num_deleted)
			memcpy(NewItem(ifrom->Type(), ifrom->ID(), isize), ifrom->Data(), isize);
	}
	for(int i = 0; i < num_update; i++) { /* unpack updated stuff */
		if(mData+2 > pEnd)
			return;
		int Type = *mData++;
		int ID = *mData++;
		if ((unsigned int)Type < sizeof(isz) / sizeof(isz[0]) && isz[Type])
			isize = isz[Type];
		else {
			if(mData+1 > pEnd)
				return;
			isize = (*mData++) * 4;
		}
		if(Type < 0 || Type > 0xFFFF || isize < 0 || (((char *)mData + isize) > (char *)pEnd))
			return;
		int *dnew = 0, Key = (Type<<16)|ID;
		for(int k = 0; k < numitems; k++)
			if(((ss_item *)&(m_bData[offs[k]]))->Key() == Key) {
				dnew = (int *)((ss_item *)&(m_bData[offs[k]]))->Data();
				break;
			}
		if(!dnew)
			dnew = (int *)NewItem(Key>>16, Key&0xffff, isize);
		for(int i = 0; i < deltas->numitems; i++) { /* get item index */
			ss_item *t = (ss_item *)(deltas->DataStart() + deltas->Offsets()[i]);
			if(t->Key() == Key) {
				int *pPast = (int *)t->Data(), *pDiff = mData, *pOut = dnew;
				for (int Size = isize/4; Size; ) {
					*pOut = *pPast+*pDiff;
					if(*pDiff != 0) {
						uchar aBuf[16];
						uchar *pEnd = cviPack(aBuf, *pDiff);
					}
					pOut++, pPast++, pDiff++, Size--;
				}
				break;
			}
		}
		if (i >= deltas->numitems) /* no previous, just copy the mData */
			memcpy(dnew, mData, isize);
		mData += isize/4;
	}
	CSnapshot *pSnap = (CSnapshot *)buf3;
	pSnap->d_size = d_size;
	pSnap->numitems = numitems;
	memcpy(pSnap->Offsets(), offs, (sizeof(int)*numitems));
	memcpy(pSnap->DataStart(), m_bData, d_size);
	if(m_ss[1] && m_ss[1]->m_Tick < DeltaTick)
		DeltaTick = m_ss[1]->m_Tick;
	if(m_ss[0] && m_ss[0]->m_Tick < DeltaTick)
		DeltaTick = m_ss[0]->m_Tick;
	for (CHolder *hld = m_pFirst; hld && hld->m_Tick < DeltaTick; ) {
		CHolder *pNext = hld->m_pNext; /* purge old snapshots */
		free(hld);
		if (!pNext) {
			m_pFirst = m_pLast = 0;
			break;
		}
		hld = m_pFirst = pNext;
		pNext->m_pPrev = 0x0;
	}
	int DataSize = (sizeof(CSnapshot) + (sizeof(int)*numitems) + d_size);
	CHolder *hld = (CHolder *)calloc(sizeof(CHolder)+DataSize+DataSize, 1);
	hld->m_Tick = GameTick;
	hld->m_Tagtime = time_get();
	hld->m_SnapSize = DataSize;
	hld->m_pSnap = (CSnapshot*)(hld+1);
	memcpy(hld->m_pSnap, (void *)buf3, DataSize);
	hld->m_pAltSnap = (CSnapshot*)(((char *)hld->m_pSnap) + DataSize);
	memcpy(hld->m_pAltSnap, (void *)buf3, DataSize);
	hld->m_pNext = 0;
	hld->m_pPrev = m_pLast;
	if(m_pLast)
		m_pLast->m_pNext = hld;
	else
		m_pFirst = hld;
	m_pLast = hld;
	if (++m_ReceivedSnapshots == 2) { /* wait for 2 ss before seeing self as connected */
		m_ss[1] = m_pFirst;
		m_ss[0] = m_pLast;
		mstate = STATE_ONLINE;
	}
	crecv_tick = GameTick;
}
int main(int argc, const char **argv) {
	int i, port = 0, iptos = 0x10, broadcast = 1, recvsize = 65536, sockid = 0;
	if (argc < 4)		return -1;
#if defined(CONF_FAMILY_WINDOWS)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(1, 1), &wsaData);
#endif
	struct CHuffmanConstructNode {
		unsigned short m_NodeId;
	} nodestorage[257], *nodes[257];
	for(int i = 0; i < 257; i++) { /* add the symbols */
		m_aNodes[i].m_NumBits = 0xFFFFFFFF;
		m_aNodes[i].m_Symbol = i;
		m_aNodes[i].m_aLeafs[0] = m_aNodes[i].m_aLeafs[1] = 0xffff;
		nodestorage[i].m_NodeId = i;
		nodes[i] = &nodestorage[i];
	}
	nnodes = 257;
	for (int nnl = 257; nnl > 1; nnl--) { /* construct the table */
		m_aNodes[nnodes].m_NumBits = 0;
		m_aNodes[nnodes].m_aLeafs[0] = nodes[nnl-1]->m_NodeId;
		m_aNodes[nnodes].m_aLeafs[1] = nodes[nnl-2]->m_NodeId;
		nodes[nnl-2]->m_NodeId = nnodes;
		nnodes++;
	}
	m_pStartNode = &m_aNodes[nnodes-1];
	Setbits_r(m_pStartNode, 0, 0);
	for(int i = 0; i < HUFFMAN_LUTSIZE; i++) { /* build decode LUT */
		unsigned Bits = i;
		int k;
		CNode *pNode = m_pStartNode;
		for(k = 0; k < HUFFMAN_LUTBITS; k++) {
			pNode = &m_aNodes[pNode->m_aLeafs[Bits&1]];
			Bits >>= 1;
			if(!pNode)
				break;
			if(pNode->m_NumBits) {
				m_apDecodeLut[i] = pNode;
				break;
			}
		}
		if(k == HUFFMAN_LUTBITS)
			m_apDecodeLut[i] = pNode;
	}
	struct timeval tv = { 0, 0 };
	fd_set fds, readfds;
	srand(time(NULL));
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((rand() % 64511) + 1024);
	if ((m_Socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ||
	    bind(m_Socket, (struct sockaddr *)&addr, (int)sizeof(addr)) != 0) {
		printf("failed to create + bind socket\n");
		return -1;
	}
	setsockopt(m_Socket, SOL_SOCKET, SO_BROADCAST, (const char*)&broadcast, sizeof(broadcast));
	setsockopt(m_Socket, SOL_SOCKET, SO_RCVBUF, (char*)&recvsize, sizeof(recvsize));
	setsockopt(m_Socket, IPPROTO_IP, IP_TOS, (char*)&iptos, sizeof(iptos)); /* lowdelay */
	unsigned long mode = 1;
#if defined(CONF_FAMILY_WINDOWS)
	ioctlsocket(m_Socket, FIONBIO, (unsigned long *)&mode);
#else
	ioctl(m_Socket, FIONBIO, (unsigned long *)&mode);
#endif
	long long LastTime = time_get();
	long long tickscount = 0;
	struct addrinfo hints, *result = NULL;
	char host[256] = { 0 };
	for(i = 0; i < sizeof(host)-1 && argv[1][i] && argv[1][i] != ':'; i++)
		host[i] = argv[1][i];
	if (argv[1][i] == ':')
		port = atol(argv[1]+i+1);
	printf("connecting to host='%s' port=%d\n", host, port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	if (getaddrinfo(host, NULL, &hints, &result) != 0 || !result)
		return -1;
	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_port = htons(port);
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, &((struct sockaddr_in*)(result->ai_addr))->sin_addr.s_addr, 4);
	freeaddrinfo(result);
	astate = mstate = STATE_CONNECTING;
	s_token = -1;
	SendControl(1, magic, sizeof(magic)); /* connect control message */
	while (1) {	/* run loop */
		new_tick = 1;
		if(mstate == STATE_ONLINE && m_ReceivedSnapshots >= 3) {
			CHolder *pNext;
			while ((pNext = m_ss[0]->m_pNext) != NULL) {
				m_ss[1] = m_ss[0];
				m_ss[0] = pNext;
				if (!m_ss[0] || !m_ss[1])
					continue;
				for(int i = 0; i < 64; ++i)
					m_aClients[i].m_Team = -2;	
				int Num = m_ss[0]->m_pSnap->numitems;
				for(int i = 0; i < Num; i++) { /* read snapshot */
					CSnapshot *p = m_ss[0]->m_pAltSnap;
					ss_item *d = (ss_item *)(p->DataStart() + p->Offsets()[i]);
					int *pInfo = (int *)d->Data();
					if(d->Type() == 11) { /* client info */
						char *ptr = m_aClients[d->ID()].m_aName;
						for (int i = 0; i < 4; i++, pInfo++) {
							ptr[0] = (((*pInfo)>>24)&0xff)-128;
							ptr[1] = (((*pInfo)>>16)&0xff)-128;
							ptr[2] = (((*pInfo)>>8)&0xff)-128;
							ptr[3] = ((*pInfo)&0xff)-128;
							ptr += 4;
						}
						ptr[-1] = 0;
					} else if(d->Type() == 10) { /* player info */
						m_aClients[pInfo[1]].m_Team = pInfo[2];
						if (pInfo[0] && !m_ddsent) { /* local */
							CMsgPacker Msg(26); /* isddnet */
							Msg.AddInt((int)strtol(argv[3], NULL, 10));
							SendMsgEx(&Msg, NETSENDFLAG_VITAL, false);
							m_ddsent = true;
						}
					}
				}
			}
		}
		long long Now = time_get(), dif = (Now-last_stime);
		if (astate == STATE_ONLINE) {
			if (dif > time_freq()/2) /* flush after 500ms */
				Flush();
			if (dif > time_freq())
				SendControl(0, 0, 0); /* keepalive */
		} else if (astate == STATE_CONNECTING) {
			if (dif > time_freq()/2) /* send new connect every 500ms */
				SendControl(1, magic, sizeof(magic)); /* connect control msg */
		} else {
			if (dif > time_freq()/2) /* send a new connect/accept every 500ms */
				SendControl(2, magic, sizeof(magic));
		}
		if(mstate == STATE_CONNECTING && astate == STATE_ONLINE) {
			mstate = STATE_LOADING;
			CMsgPacker Msg(1); /* info */
			Msg.AddString("0.6 626fce9a778df4d4", 128); /* version */
		//	Msg.AddString("0.6 1afa644a8d227cbd", 128); /* version */
			Msg.AddString("", 128);
			SendMsgEx(&Msg, NETSENDFLAG_VITAL|NETSENDFLAG_FLUSH, true);
		}
		void *data;
		int flags, datasize, MsgID, mtype, team, id;
		while (m_Socket >= 0 && cRecv(&flags, &datasize, &data)) {
			const uchar *mpc = (uchar *)data;
			uchar *m_pEnd = (uchar *)data + datasize;
			mpc = cviUnpack(mpc, &MsgID);
			mtype = MsgID >> 1;
			if (!(MsgID & 1) && ((flags&NETSENDFLAG_VITAL) != 0)) {
				if (mtype == 8) { /* ready to enter */
					CMsgPacker Msg(15); /* entergame */
					SendMsgEx(&Msg, NETSENDFLAG_VITAL|NETSENDFLAG_FLUSH, true);
					m_ss[0] = m_ss[1] = 0;
					CHolder *pNext, *pHolder = m_pFirst;
					while(pHolder) {
						pNext = pHolder->m_pNext;
						free(pHolder);
						pHolder = pNext;
					}
					m_pFirst = m_pLast = 0;
					m_ReceivedSnapshots = ss_parts = crecv_tick = 0;
				} else if (mtype == 3) { /* chat */
					mpc = cviUnpack(mpc, &team);
					mpc = cviUnpack(mpc, &id);
					if (mpc < m_pEnd)
						printf("%2d %16s: %s\n", id, (id >= 0 && id < 64) ? 
							m_aClients[id].m_aName : "***", (char *)mpc);
				}
				continue;
			} /* system message */
			if ((flags&NETSENDFLAG_VITAL) != 0 && mtype == 2) { /* map change */
				mstate = STATE_LOADING;
				CMsgPacker Msg(14); /* ready */
				SendMsgEx(&Msg, NETSENDFLAG_VITAL|NETSENDFLAG_FLUSH, true);
			} else if ((flags&NETSENDFLAG_VITAL) != 0 && mtype == 4) { /* conn ready */
				CMsgPacker Packer(20); /* startinfo */
				Packer.AddString(argv[2], 16); /* name */
				Packer.AddString("", 12); /* clan */
				Packer.AddInt(-1); /* country */
				Packer.AddString("pinky", 16); /* skin */
				Packer.AddInt(1); /* use custom color */
				Packer.AddInt(7667531); /* color body */
				Packer.AddInt(11468598); /* color feet */
				SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);	
			} else if (mtype == 22) { /* ping */
				CMsgPacker Msg(23); /* ping reply */
				SendMsgEx(&Msg, 0, true);
			} else if (mstate >= STATE_LOADING && (mtype == 5 || mtype == 7 || mtype == 6)) { /* snapshot */
				int np = 1, pt = 0, ps = 0, gt, dt;
				mpc = cviUnpack(mpc, &gt);
				mpc = cviUnpack(mpc, &dt);
				dt = gt - dt;
				if (mtype == 5) { /* snap */
					mpc = cviUnpack(mpc, &np);
					mpc = cviUnpack(mpc, &pt);
				}
				if (mtype != 6) { /* empty snap */
					mpc = cviUnpack(mpc, &ps);
					mpc = cviUnpack(mpc, &ps);
				}
				char *pData = (char *)mpc;
				mpc += ps;
				if (np >= 1 && pt >= 0 && ps >= 0 && gt >= crecv_tick) {
					if(gt != crecv_tick) {
						ss_parts = 0;
						crecv_tick = gt;
					}
					handle_snapshot(np, pt, ps, gt, dt, pData);
				}	
			} else {
				printf("msg %d\n", mtype);
			}
		}
		long long tm = (1000000 * (LastTime + time_freq() / 120 - Now) / time_freq());
		tm = (tm >= 0) ? tm : 0;
		tv.tv_sec = tm / 1000000;
		tv.tv_usec = tm % 1000000;
		FD_ZERO(&readfds);
		if(m_Socket >= 0) {
			FD_SET(m_Socket, &readfds);
			sockid = m_Socket;
		} 
		select(sockid+1, &readfds, NULL, NULL, (tm < 0) ? NULL : &tv);
		LastTime = Now;
		/*
		if (++tickscount > 1000) {
			CMsgPacker Packer(17); 
			Packer.AddInt(0); 
			Packer.AddString("test", 512);
			SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);
			tickscount = 0;
		}
		*/
		char input[512] = { 0 };
#if !defined(CONF_FAMILY_WINDOWS)
		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO, &fds);
		select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
		if (!FD_ISSET(0, &fds)) 
			continue;	
		fgets(input, 512, stdin);
#else
		INPUT_RECORD inp[200];
		DWORD i, num;
		HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
		if (!PeekConsoleInput(h, inp, 200, &num)) 
			continue;
		for (i = 0; i < num; i++)
			if (inp[i].EventType == KEY_EVENT &&
			    inp[i].Event.KeyEvent.wVirtualKeyCode == VK_RETURN)
				break;
		if (i == num || !ReadConsole(h, input, sizeof(input), &num, NULL) || (int)num <= 0)
			continue;
#endif
		if (!strncmp(";team", input, 5)) {
			CMsgPacker Packer(18); /* cl_setteam */
			Packer.AddInt((int)strtol(input + 6, NULL, 10));
			SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);
		} else if (!strncmp(";list", input, 5)) {
			for (int i = 0; i < 64; i++) {
				if (m_aClients[i].m_Team < -1)
					continue;
				printf("* %3d (%2d) %s\n", i, m_aClients[i].m_Team, m_aClients[i].m_aName);
			}
		} else if (!strncmp(";quit", input, 5)) {
			break;
		} else {
			CMsgPacker Packer(17); /* cl_say */
			Packer.AddInt(0); /* team */
			Packer.AddString(input, 512);
			SendMsgEx(&Packer, NETSENDFLAG_VITAL, false);
		}
	}
	SendControl(4, 0, 0); /* close control msg */
	return 0;
}
