#ifndef STRUCT
#define STRUCT
/* IP header */
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include "mstcpip.h"


#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8
struct ip_pkt
{
	unsigned char vhl;		/* version << 4 | header length >> 2 */
	unsigned char tos;		/* type of service */
	unsigned short len;		/* total length */
	unsigned short id;		/* identification */
	unsigned short offset;	/* fragment offset field */
	unsigned char ttl;		/* time to live */
	unsigned char pro;		/* protocol */
	unsigned short cksum;	/* checksum */
	in_addr src, dst;		/* source and dest address */
};
#define IP_V(ip)		(((ip)->vhl) >> 4)
#define IP_HL(ip)		(((ip)->vhl) & 0x0f)

struct et_header
{
	unsigned char   eh_dst[6];
	unsigned char   eh_src[6];
	unsigned short  eh_type;
};
struct psd_header{
	ULONG  sourceip;    //源IP地址
	ULONG  destip;      //目的IP地址
	BYTE mbz;           //置空(0)
	BYTE ptcl;          //协议类型
	USHORT plen;        //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)
};

struct tcp_Header {
	USHORT srcport;   // 源端口
	USHORT dstport;   // 目的端口
	UINT seqnum;      // 顺序号
	UINT acknum;      // 确认号
	BYTE dataoff;     // TCP头长
	BYTE flags;       // 标志（URG、ACK等）
	USHORT window;    // 窗口大小
	USHORT chksum;    // 校验和
	USHORT urgptr;    // 紧急指针
};
//Necessary Structs
typedef struct
{
	char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;

typedef struct _IP_ADDR_STRING
{
	struct _IP_ADDR_STRING* Next;
	IP_ADDRESS_STRING IpAddress;
	IP_MASK_STRING IpMask;
	DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

typedef struct _IP_ADAPTER_INFO
{
	struct _IP_ADAPTER_INFO* Next;
	DWORD           ComboIndex;
	char            AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
	char            Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
	UINT            AddressLength;
	BYTE            Address[MAX_ADAPTER_ADDRESS_LENGTH];
	DWORD           Index;
	UINT            Type;
	UINT            DhcpEnabled;
	PIP_ADDR_STRING CurrentIpAddress;
	IP_ADDR_STRING  IpAddressList;
	IP_ADDR_STRING  GatewayList;
	IP_ADDR_STRING  DhcpServer;
	BOOL            HaveWins;
	IP_ADDR_STRING  PrimaryWinsServer;
	IP_ADDR_STRING  SecondaryWinsServer;
	time_t          LeaseObtained;
	time_t          LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;



struct icmp_hdr
{
	unsigned char icmp_type;   //类型
	unsigned char code;        //代码
	unsigned short chk_sum;    //16位检验和
};

#endif