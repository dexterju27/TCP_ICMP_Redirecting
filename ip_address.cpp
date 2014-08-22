/* 将数字类型的IP地址转换成字符串类型的 */
#include "stdafx.h"
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif // !_CRT_SECURE_NO_WARNINGS


#define IPTOSBUFFERS    12
#include "ip_address.h"
#define LoadLibrary  LoadLibraryA

psendarp SendArp;
pgetadaptersinfo GetAdaptersInfo;

void loadiphlpapi() {
	HINSTANCE hDll = LoadLibrary("iphlpapi.dll");

	GetAdaptersInfo = (pgetadaptersinfo)GetProcAddress(hDll, "GetAdaptersInfo");
	if (GetAdaptersInfo == NULL)
		printf("Error in iphlpapi.dll%d", GetLastError());
	SendArp = (psendarp)GetProcAddress(hDll, "SendARP");
	if (SendArp == NULL)
		printf("Error in iphlpapi.dll%d", GetLastError());
}
void get_gateway_mac_address(unsigned char *mac, u_int ip)
{
	in_addr destip;
	DWORD ret;
	in_addr srcip;
	ULONG MacAddr[2];
	ULONG PhyAddrLen = 6;  /* default to length of six bytes */
	destip.s_addr = ip;
	srcip.s_addr = 0;

	//Now print the Mac address also
	ret = SendArp(destip, srcip, MacAddr, &PhyAddrLen);
	if (PhyAddrLen) {
		BYTE *bMacAddr = (BYTE *)& MacAddr;
		for (int i = 0; i < (int)PhyAddrLen; i++)
			mac[i] = (char)bMacAddr[i];
	}
}

void get_gateway(struct in_addr ip, char *sgatewayip) {
	char pAdapterInfo[5000];
	PIP_ADAPTER_INFO  AdapterInfo;
	ULONG OutBufLen = sizeof(pAdapterInfo);

	GetAdaptersInfo((PIP_ADAPTER_INFO)pAdapterInfo, &OutBufLen);
	for (AdapterInfo = (PIP_ADAPTER_INFO)pAdapterInfo; AdapterInfo; AdapterInfo = AdapterInfo->Next) {
		if (ip.s_addr == inet_addr(AdapterInfo->IpAddressList.IpAddress.String))
			strcpy(sgatewayip, AdapterInfo->GatewayList.IpAddress.String);
	}
	
}
u_int cal_gateway_ip(u_int ip,u_int subnet){//用IP和子网掩码计算默认网关地址

	in_addr gateway;
	gateway.s_addr = ip&subnet;
	u_int temp;
	temp = gateway.s_addr;
	temp = ntohl(temp);
	temp = temp + 1;
	gateway.s_addr = htonl(temp);
	printf("将使用默认网关，网关地址为：%s\n", inet_ntoa(gateway));
	return gateway.s_addr;

}
bool fliter_ip(in_addr addr,std::string target ){
	{
		char c[15] = { NULL };
		memcpy(c, inet_ntoa(addr), target.length());
		char d[15] = { NULL };
		memcpy(d, target.c_str(), target.length());

		if (memcmp(c, d, target.length()) == 0)
			return TRUE;
		else
		{
			return FALSE;
		}
	}
}
bool fliter_ip(u_long addr, u_int taget){
		if (addr == taget)
		{
			return true;
		}
		else
		{
			return false;
		}
}
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

int get_mac_address(pcap_if_t *d,u_char * mac_address){

	LPADAPTER	lpAdapter = 0;
	int			i;
	DWORD		dwErrorCode;
	char		AdapterName[8192];
	char		*temp, *temp1;
	int			AdapterNum = 0, Open;
	ULONG		AdapterLength;
	PPACKET_OID_DATA  OidData;
	BOOLEAN		Status;
	lpAdapter = PacketOpenAdapter(d->name);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		dwErrorCode = GetLastError();
		printf("Unable to open the adapter, Error Code : %lx\n", dwErrorCode);

		return -1;
	}

	// 
	// Allocate a buffer to get the MAC adress
	//

	OidData = (PPACKET_OID_DATA) malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		printf("error allocating memory!\n");
		PacketCloseAdapter(lpAdapter);
		return -1;
	}

	// 
	// Retrieve the adapter MAC querying the NIC driver
	//

	OidData->Oid = OID_802_3_CURRENT_ADDRESS;

	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	Status = PacketRequest(lpAdapter, FALSE, OidData);
	if (Status)
	{
		printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			(OidData->Data)[0],
			(OidData->Data)[1],
			(OidData->Data)[2],
			(OidData->Data)[3],
			(OidData->Data)[4],
			(OidData->Data)[5]);
		memcpy(mac_address, OidData->Data, 6);
	}
	
	else
	{
		printf("error retrieving the MAC address of the adapter!\n");
	}

	free(OidData);
	PacketCloseAdapter(lpAdapter);
	return (0);
}



void ifprint(pcap_if_t *d, int i)
{
	pcap_addr_t *a;
	char ip6str[128];
	printf("%d", i + 1);

	/* 设备名(Name) */
	printf("%s\n", d->name);

	/* 设备描述(Description) */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}
u_short in_cksum(u_short * const addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	while (nleft>1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		u_short u = 0;
		*(u_char*)(&u) = *(u_char*)w;
		sum += u;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);           //add carry 加进位
	answer = ~sum;              //truncate to 16 bits 截断到16位
	return(answer);
}
void icmp_cksum(u_char * buff,int length){
	u_short * data;
	data = (u_short *)(buff+IP_HEADER+ETH_HEADER);
	icmp_hdr * icmp_header = (icmp_hdr *)data;
	icmp_header->chk_sum = 0;
	icmp_header->chk_sum = in_cksum(data, length - ETH_HEADER - IP_HEADER);
}


int get_mac_address(char* source, char* mac_buf)
{
	LPADAPTER lpAdapter;
	PPACKET_OID_DATA  OidData;
	BOOLEAN status;

	lpAdapter = PacketOpenAdapter(source);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		return -1;
	}

	OidData = (PPACKET_OID_DATA) malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		return 0;
	}

	OidData->Oid = OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	status = PacketRequest(lpAdapter, FALSE, OidData);
	if (status == NULL)
	{
		return -1;
	}

	memcpy((void *)mac_buf, (void *)OidData->Data, 6);

	free(OidData->Data);

	return 0;
}

//-------------------------------------------------------------------------
// PacketCheckSum
// 计算数据包的校验和
// 参数:packet-待处理数据(将封装好的数据包的指针)
//-------------------------------------------------------------------------
void tcp_cksum(unsigned char packet[])//包的头部地址，包含以太网
	
{
	ip_pkt  *pip_header = NULL;  //IP头指针
	unsigned short attachsize = 0; //传输层协议头以及附加数据的总长度
	//判断ethertype,如果不是IP包则不予处理
	pip_header = (ip_pkt  *)(packet + 14);
	//TCP包
		tcp_Header *ptcp_header = NULL; //TCP头指针
		psd_header *ptcp_psd_header = NULL;
		ptcp_header = (tcp_Header *)(packet + 14 + ((pip_header->vhl) & 15) * 4);
		attachsize = ntohs(pip_header->len) - ((pip_header->vhl) & 15) * 4;
		ptcp_psd_header = (psd_header *)malloc(attachsize + sizeof(psd_header));//开辟临时空间用于计算加盐和
		ptcp_header->chksum = 0;
		if (!ptcp_psd_header) return;
		memset(ptcp_psd_header, 0, attachsize + sizeof(psd_header));
		//填充伪TCP头
		ptcp_psd_header->destip = pip_header->dst.s_addr;
		ptcp_psd_header->sourceip = pip_header->src.s_addr;
		ptcp_psd_header->mbz = 0;
		ptcp_psd_header->ptcl = 0x06;//TCP
		ptcp_psd_header->plen = htons(attachsize);
		//计算TCP校验和
		ptcp_header->chksum = 0;
		memcpy((unsigned char *)ptcp_psd_header + sizeof(psd_header),
			(unsigned char *)ptcp_header, attachsize);
		ptcp_header->chksum = in_cksum((unsigned short *)ptcp_psd_header,
			attachsize + sizeof(psd_header));
		return;
}

bool fliter_mac(u_char* mac_addr_1, u_char * mac_addr_2){
	char a[6] = { NULL };
	char b[6] = { NULL };
	memcpy(a,mac_addr_1, 6);
	memcpy(b, mac_addr_2, 6);
	if (memcmp(a, b, 6) == 0)
		return true;
	return false;

}