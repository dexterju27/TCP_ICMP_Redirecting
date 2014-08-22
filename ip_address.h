#ifndef IP_ADDRESS_H
#define IP_ADDRESS_H


#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <pcap.h>
#include <conio.h>
#include <packet32.h>
#include <ntddndis.h>
#include "struct.h"

#include <string>


typedef DWORD(WINAPI* psendarp)(in_addr DestIP, in_addr SrcIP, PULONG pMacAddr, PULONG PhyAddrLen);
typedef DWORD(WINAPI* pgetadaptersinfo)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);



#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Packet.lib")
#define ETH_HEADER 14
#define IP_PROTO    0x0800 
#define IP_HEADER 20

void loadiphlpapi();
void ifprint(pcap_if_t *d, int i);
void icmp_cksum(u_char * buff, int length);//计算icmp校验和
char *iptos(u_long in);
bool fliter_ip(in_addr addr,std::string target);
bool fliter_ip(u_long addr, u_int taget);
bool fliter_mac(u_char* mac_addr_1, u_char * mac_addr_2);
void get_gateway(struct in_addr ip, char *sgatewayip);
void get_gateway_mac_address(unsigned char *mac, u_int ip);
void tcp_cksum(unsigned char packet[]//包的头部地址，包含以太网
	);
u_int cal_gateway_ip(u_int ip, u_int subnet);


u_short in_cksum(u_short * const addr, int len);
int get_mac_address(pcap_if_t *d, u_char * mac_address);
#endif