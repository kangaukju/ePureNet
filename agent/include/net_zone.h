#define ETH_HW_ADDR_LEN 6  
#define IP_ADDR_LEN 4    
#define ARP_FRAME_TYPE 0x0806  
#define ETHER_HW_TYPE 1         
#define IP_PROTO_TYPE 0x0800
#define OP_ARP_REQUEST 1


struct arp_packet {
   u_char 	dst_hw[ETH_HW_ADDR_LEN];
   u_char 	src_hw[ETH_HW_ADDR_LEN];
   u_short 	frame_type;
   u_short 	hw_type;

   u_short 	prot_type;
   u_char 	hw_addr_size;
   u_char 	prot_addr_size;
   u_short 	op;
   u_char 	send_hw[ETH_HW_ADDR_LEN];
   u_int 		send_ip;
   u_char 	recv_hw[ETH_HW_ADDR_LEN];
   u_int 		recv_ip;
   u_char 	padding[8];
};



char net_zone[255];



void *arp_packet_thread_func( void *data )
{

	struct arp_packet pkt;
	struct ether_addr * ether;
	u_char broad_mac[ETH_HW_ADDR_LEN] = {0xfF, 0xfF, 0xfF, 0xfF, 0xfF, 0xfF};
	u_char nul_mac[ETH_HW_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned long mask, loop_ip;
	struct sockaddr sa, da;	
	int sock;
	
	pcap_t *pd;
	char	ebuf[PCAP_ERRBUF_SIZE];
	struct in_addr	netmask, network;
	struct bpf_program  fcode;
	int status;
	struct pcap_pkthdr h;
	char *dev = answer[1];
	const u_char *packet; // 패킷 시작 위치 포인터
	unsigned int *target_addr;
	unsigned char host_index;
	char filter[24];
	
	
	u_char *recv_ipp;
	struct in_addr add;



	// raw 소켓 생성
	sock=socket(AF_INET,SOCK_PACKET, IPPROTO_RAW);
	if(sock<0){
		perror("socket");		
	}

	// 디바이스 열기
	sprintf(filter, " arp and dst host %s ", ifcg.ip);  
	pd = pcap_open_live(dev, SNAPSIZE, PROMISCUOUS, 0, ebuf); 
	if(pd == NULL) {
  		fprintf(stderr, "pcap_open_live fail: %s", ebuf);    
	}

	// device localnet과, netmask
	pcap_lookupnet(dev, &network.s_addr, &netmask.s_addr, ebuf);

	// 필터링 규칙 컴파일
	pcap_compile(pd, &fcode, filter, 0, netmask.s_addr);
	pcap_setfilter(pd, &fcode); // 디스크립터에 필터링 규칙적용

	printf("[NET_ZONE] CAPUTRE START Dev='%s'[net=%s]\n", dev, inet_ntoa(network), inet_ntoa(netmask));

	// net_zone 초기화
	memset(net_zone, '*', sizeof(net_zone));
	net_zone[sizeof(net_zone)-1] = 0;


	//옵션 설정
	pkt.frame_type		= htons(ARP_FRAME_TYPE);
	pkt.hw_type			= htons(ETHER_HW_TYPE);
	pkt.prot_type		= htons(IP_PROTO_TYPE);
	pkt.hw_addr_size	= ETH_HW_ADDR_LEN;
	pkt.prot_addr_size	= IP_ADDR_LEN;
	pkt.op				= htons(OP_ARP_REQUEST);


	// 출발지 맥주소 
	ether = ether_aton(ifcg.mac);
	memcpy( &pkt.src_hw  , ether->ether_addr_octet, sizeof(u_char)* ETH_HW_ADDR_LEN );
	memcpy( &pkt.send_hw , ether->ether_addr_octet, sizeof(u_char)* ETH_HW_ADDR_LEN );
	
	// 목적지 맥주소
	memcpy( &pkt.dst_hw , &broad_mac, sizeof(u_char)* ETH_HW_ADDR_LEN );
	memcpy( &pkt.recv_hw ,&nul_mac,		sizeof(u_char)* ETH_HW_ADDR_LEN );

	// 출발지 ip
	pkt.send_ip = inet_addr(ifcg.ip);
	add.s_addr = pkt.send_ip;
	puts(inet_ntoa(add));

	// 넷마스크
	mask = inet_addr(ifcg.netmask);

	//목적지 ip
	loop_ip = pkt.send_ip & mask;
	
	recv_ipp = (u_char *)&pkt.send_ip;

	//padding
	bzero(pkt.padding,8);
	strcpy(sa.sa_data,dev);

	int i;
	
	for(i =0; i<254*2; i++){

		loop_ip		= ntohl(loop_ip);
		loop_ip++;
		loop_ip   = htonl(loop_ip);
		
		*((u_int *)recv_ipp) = loop_ip;
		

		if(sendto(sock, &pkt, sizeof(pkt), 0, &sa, sizeof(sa)) < 0){
			perror("sendto");
			close(sock);			
		}
		//usleep(1);
		
		/*

		if( (packet = (u_char *)pcap_next(pd, &h)) != NULL){
			target_addr = (unsigned int *)(packet + sizeof(struct ethhdr) + sizeof(char) * 14);
			host_index = *((unsigned char*)target_addr + 3);
			if(host_index < 255){
				net_zone[host_index] = '1';
			}
		}	
		*/
	}
	pcap_close(pd);
}















