
/* fake paaket for access deny
 * date : 2008 . 8. 4
 * id   : kinow
 * doc  : 1. 3 way-handshake 세션 단계
 *        2. HOST는 "GET" 메소드의 페이지를 요청하는 PSH와 ACK 플래그가 포함된 패킷을 웹서버로 보낼 것이다. (브라우저를 통해...)
 *        3. 이 때 AGENT는 웹서버를 대신해 GET 요청에 대한 ACK 패킷을 HOST에게 보낸 후, 곧 바로
 *        4. 웹서버를 대신한 차단 페이지를 보낸다.
 *        5. 뒤 늦게 도착한 실제 웹서버의 페이지는 유효 하지 않게 된다.

 */

#include "hash.h"
#include "http_filter.h"
#include "pipe.h"

#define snapsize 1024          // Snap Length
#define http_header_size snapsize-40          // Snap Length
#define fake_rule		" ! arp "
#define TOTAL_NETWORK	"0.0.0.0"

int ssock;	// raw socket 전역 변수

char URL[] 					= "policy/url";
char KEYWORD[] 			= "policy/keyword";
char IP[] 					= "policy/ip";

char URL_OBJ[] 			= "policy/url_obj";
char KEYWORD_OBJ[] 	= "policy/keyword_obj";
char IP_OBJ[] 			= "policy/ip_obj";

char URL_BASE[] 					= "policy/url_base";
char KEYWORD_BASE[] 			= "policy/keyword_base";
char IP_BASE[] 						= "policy/ip_base";

enum {O_START, O_STOP} OPERATION;



struct packet_data{
	char check;
	int type;
	char data[http_header_size];
	
	u_int32_t saddr;
	u_int32_t daddr;
	
	u_int16_t source;
	u_int16_t dest;
	
	u_int32_t ack_seq;
	u_int32_t seq;
	
	u_int32_t packet_len;
};


static struct packet_data 	ip_data;	//ip 차단 구조체
static struct packet_data  keyword_data;	//keyword 차단 구조체
static struct packet_data  capure_data;	//url 차단 구조체



void f_callback(  u_char *user, const struct pcap_pkthdr *h, const u_char *packet);
unsigned short ip_sum (u_short *addr, int len);
void send_tcp_segment(struct iphdr *ih, struct tcphdr *th, char *data, int dlen);
void assemble_port(u_int32_t my_ip, u_int32_t their_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size);
void assemble_ack(u_int32_t my_ip, u_int32_t their_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size);
void assemble_psh(u_int32_t my_ip, u_int32_t their_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size);
void assemble_rst(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size);
int get_webpage(char *buf, char *path);
int policy_load(void);
int get_policy(int agent_num);
void *apply_thread_func(void *data);
void *fake_page_process(char *path);
char http_header[http_header_size];




typedef struct pseudo_header{  /* rfc 793 tcp pseudo-header */
	unsigned long saddr, daddr;
	char mbz;
	char ptcl;
	unsigned short tcpl;
} ph_t;

ph_t ph;


static char html[2048];







void *ip_filter_thread_func(void *data)
{
	
	struct packet_data send_data;
	unsigned long no;
	
	while(OPERATION == O_START){
		if(ip_data.check == 1){
			ip_data.check = 0;
			memcpy(&send_data, &ip_data, sizeof(ip_data));
			
			if( no = find_ip( send_data.daddr ,ip_table) ){
				
				if( find_ip_base(no, ip_baseobj) == 0 || find_ip_obj(send_data.saddr, no, ip_netobj) == 0){
					if(find_ip_base(no, ip_baseobj) == 0){
						printf("ip base no: %d\n", no);
					}
					if(find_ip_obj(send_data.saddr, no, ip_netobj) == 0){
						printf("ip obj no: %d\n", no);
					}
					/*
					////////////////////////////////////////////////////////////////////////////
					// DEBUG or LOG
					////////////////////////////////////////////////////////////////////////////
					struct in_addr addr;
					addr.s_addr = send_data.saddr;
					printf("[IP]src:%s   ---->   ", inet_ntoa(addr));
					addr.s_addr = send_data.daddr;
					printf("dst:%s\n", inet_ntoa(addr));
					*/
					assemble_ack(send_data.daddr, send_data.saddr, send_data.dest, send_data.source, send_data.ack_seq, ntohl(send_data.seq) + send_data.packet_len-(40+14), 0);
    			assemble_psh(send_data.daddr, send_data.saddr, send_data.dest, send_data.source, send_data.ack_seq, ntohl(send_data.seq) + send_data.packet_len-(40+14), send_data.packet_len-40);
    		}
			}			
		}		
		else{
			usleep(1);			
		}		
	}	
}



void *keyword_filter_thread_func(void *data)
{
	
	struct packet_data send_data;
	int i;	
	
	
	while(OPERATION == O_START){
		if(keyword_data.check == 1 ){
			
			memcpy(&send_data, &keyword_data, sizeof(keyword_data));
			
			
			switch(send_data.type){
			
			
			case IS_GET :
				
				for(i=0; i<MAXKEYWORD; i++){					
					if( _strnstr(send_data.data, keyword_table[i].keyword, 100)){
						
						if(find_keyword_base(keyword_table[i].no, keyword_baseobj) == 0 || find_keyword_obj(send_data.saddr, keyword_table[i].no, keyword_netobj) == 0){
							if(find_keyword_base(keyword_table[i].no, keyword_baseobj) == 0){
								printf("keyword base no: %d\n", keyword_table[i].no);
							}
							if(find_keyword_obj(send_data.saddr, keyword_table[i].no, keyword_netobj) == 0){
								printf("keyword obj no: %d\n", keyword_table[i].no);
							}
							/*
							////////////////////////////////////////////////////////////////////////////
								// DEBUG or LOG
							////////////////////////////////////////////////////////////////////////////
							struct in_addr addr;
							addr.s_addr = send_data.saddr;
							printf("[KEYWORD]src:%s   ---->   ", inet_ntoa(addr));
							addr.s_addr = send_data.daddr;
							printf("dst:%s\n", inet_ntoa(addr));
							*/

							assemble_ack(send_data.daddr, send_data.saddr, send_data.dest, send_data.source, send_data.ack_seq, ntohl(send_data.seq) + send_data.packet_len-(40+14), 0);
  	  				assemble_psh(send_data.daddr, send_data.saddr, send_data.dest, send_data.source, send_data.ack_seq, ntohl(send_data.seq) + send_data.packet_len-(40+14), send_data.packet_len-40);
    					assemble_rst(send_data.saddr, send_data.daddr, send_data.source, send_data.dest, send_data.seq+1, send_data.ack_seq, 0);
    				}
					}
				}
				break;
				
			case IS_POST :
				break;
				
			default: break;
				
			}
			keyword_data.check = 0;
		}
				
		else{
			usleep(1);			
		}		
	}	
}










/*
 * Check Sum 
 */
 
unsigned short ip_sum (u_short *addr, int len){
	register int nleft = len;
	register u_short *w = addr;
	register int sum = 0;
	u_short answer = 0;
	
	while (nleft > 1){
		  sum += *w++;
		  nleft -= 2;
	}

	if (nleft == 1){
		  *(u_char *) (&answer) = *(u_char *) w;
		  sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
	sum += (sum >> 16);           /* add carry */
	answer = ~sum;                /* truncate to 16 bits */
	return (answer);
}



/* 
 * packet assembly 
 */
 
void send_tcp_segment(struct iphdr *ih, struct tcphdr *th, char *data, int dlen) {
	
	
	char buf[1580];
	
	struct sockaddr_in sin;

	ssock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if(ssock<0) {
		perror("socket (raw)");
//		exit(1);
  }
	
	ph.saddr=ih->saddr;
	ph.daddr=ih->daddr;
	ph.mbz=0;
	ph.ptcl=IPPROTO_TCP;
	ph.tcpl=htons(sizeof(*th)+dlen);
	
	memcpy(buf, &ph, sizeof(ph));
	memcpy(buf+sizeof(ph), th, sizeof(*th));
	memcpy(buf+sizeof(ph)+sizeof(*th), data, dlen);
	memset(buf+sizeof(ph)+sizeof(*th)+dlen, 0, 4);
	th->check=ip_sum((u_short *)buf, (sizeof(ph)+sizeof(*th)+dlen+1)&~1);
	
	memcpy(buf, ih, 4*ih->ihl);
	memcpy(buf+4*ih->ihl, th, sizeof(*th));
	memcpy(buf+4*ih->ihl+sizeof(*th), data, dlen);
	memset(buf+4*ih->ihl+sizeof(*th)+dlen, 0, 4);
	
	ih->check=ip_sum((u_short *)buf, (4*ih->ihl + sizeof(*th)+ dlen + 1) & ~1);
	memcpy(buf, ih, 4*ih->ihl);


	/* make socket information */
	sin.sin_family=AF_INET;
	sin.sin_port=th->dest;
	sin.sin_addr.s_addr=ih->daddr;

	/* messege send  */
	if(sendto(ssock, buf, 4*ih->ihl + sizeof(*th)+ dlen, 0, (struct sockaddr *)&sin, sizeof(sin))<0) {
		printf("Error sending syn packet.\n"); perror("");
		exit(1);
	}
	close(ssock);
	
}




/* 
 * reassembling ack
 */

void assemble_ack
(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size){

	struct iphdr ih;
	struct tcphdr th;
	


	/* ip header */
	ih.version=4;
	ih.ihl=5;
	ih.tos=0;			/* XXX is this normal? */
	ih.tot_len=sizeof(ih)+sizeof(th)+size;	/* total length, from ip header to data */
	ih.id=htons(random());
	ih.frag_off=0;
	ih.ttl=30;
	ih.protocol=IPPROTO_TCP;
	ih.check=0;
	ih.saddr=s_ip;
	ih.daddr=d_ip;
	
	/* tcp header */
	th.source=sport;
	th.dest=dport;
	th.seq=seq;
	th.doff=sizeof(th)/4;
	th.ack_seq=htonl(ack);
	th.res1=0;
	th.fin=0;
	th.syn=0;
	th.rst=0;
	th.psh=0;
	th.ack=1;
	th.urg=0;
	th.res2=0;
	th.window=htons(65253);
	th.check=0;
	th.urg_ptr=0;

	send_tcp_segment(&ih, &th, "", 0); 
}




/* 
 * reassembling psh
 */

void assemble_psh
(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size){

	struct iphdr ih;
	struct tcphdr th;
	

	/* ip header */
	ih.version=4;
	ih.ihl=5;
	ih.tos=0;			/* XXX is this normal? */
	ih.tot_len=sizeof(ih)+sizeof(th)+size;
	ih.id=htons(random());
	ih.frag_off=0;
	ih.ttl=30;
	ih.protocol=IPPROTO_TCP;
	ih.check=0;
	ih.saddr=s_ip;
	ih.daddr=d_ip;
	
	/* tcp header */
	th.source=sport;
	th.dest=dport;
	th.seq=seq;
	th.doff=sizeof(th)/4;
	th.ack_seq=htonl(ack);
	th.res1=0;
	th.fin=1;
	th.syn=0;
	th.rst=0;
	th.psh=1;	//PUSH
	th.ack=1;	//ACK
	th.urg=0;
	th.res2=0;
	th.window=htons(65253);
	th.check=0;
	th.urg_ptr=0;

	send_tcp_segment(&ih, &th, (char *)html, strlen(html)+1); 
}


/* 
 * reassembling port
 */

void assemble_port
(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size){

	struct iphdr ih;
	struct tcphdr th;
	

	/* ip header */
	ih.version=4;
	ih.ihl=5;
	ih.tos=0;			/* XXX is this normal? */
	ih.tot_len=sizeof(ih)+sizeof(th)+size;
	ih.id=htons(random());
	ih.frag_off=0;
	ih.ttl=30;
	ih.protocol=IPPROTO_TCP;
	ih.check=0;
	ih.saddr=s_ip;
	ih.daddr=d_ip;
	
	/* tcp header */
	th.source=sport;
	th.dest=dport;
	th.seq=seq;
	th.doff=sizeof(th)/4;
	th.ack_seq=htonl(ack);
	th.res1=0;
	th.fin=0;
	th.syn=0;
	th.rst=0;
	th.psh=1;	//PUSH
	th.ack=1;	//ACK
	th.urg=0;
	th.res2=0;
	th.window=htons(65253);
	th.check=0;
	th.urg_ptr=0;

	send_tcp_segment(&ih, &th, (char *)html, strlen(html)+1); 
}

/* 
 * reassembling fin
 */

void assemble_rst
(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport, u_int16_t dport, u_int32_t seq, u_int32_t ack, u_int32_t size){

	struct iphdr ih;
	struct tcphdr th;
	

	/* ip header */
	ih.version=4;
	ih.ihl=5;
	ih.tos=0;			/* XXX is this normal? */
	ih.tot_len=sizeof(ih)+sizeof(th)+size;
	ih.id=htons(random());
	ih.frag_off=0;
	ih.ttl=30;
	ih.protocol=IPPROTO_TCP;
	ih.check=0;
	ih.saddr=s_ip;
	ih.daddr=d_ip;
	
	/* tcp header */
	th.source=sport;
	th.dest=dport;
	th.seq=seq;
	th.doff=sizeof(th)/4;
	th.ack_seq=htonl(ack);
	th.res1=0;
	th.fin=0;
	th.syn=0;
	th.rst=1;
	th.psh=0;
	th.ack=0;
	th.urg=0;
	th.res2=0;
	th.window=htons(65253);
	th.check=0;
	th.urg_ptr=0;
		
	send_tcp_segment(&ih, &th, "", 0); 
}







/* 
 * pcap callback
 */
 
 
void f_callback(  u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {	
			
    struct tcphdr *tcph;
    struct ip  *iph;
    struct iphdr *iphiph;
    struct ethhdr *eh = (struct ethhdr *) packet;
    u_char * http;
    char *cat;
    
    char *p1, *p2;
    char buf_url[http_header_size];    
    int type;
    

    int packet_len =h->caplen;
    int ethhdr_len = sizeof(struct ethhdr);
    int iphlen;
    
    
    if(OPERATION == O_START){
    	
    	iphiph = (struct iphdr *) (packet + ethhdr_len);
	
    	iph =  (struct ip *) (packet + sizeof(struct ethhdr));
    
    	// IP 헤더의 길이
    	iphlen = iph->ip_hl*4;

    	// 이더넷 프레임 헤더+ IP 헤더의 다음이 TCP 헤더임
    	tcph = (struct tcphdr *) (packet + sizeof(struct ethhdr) + iphlen) ;
    
    	http = (u_char *)packet + ethhdr_len + iphlen + sizeof(struct tcphdr);
    
    	type = type_request((char *)http);
    	
    

			if( tcph->psh == 1 && tcph->ack ==1 ){

			capure_data.check = 1;		
			capure_data.saddr = iphiph->saddr;
			capure_data.daddr = iphiph->daddr;
			capure_data.source = tcph->source;
			capure_data.dest = tcph->dest;
			capure_data.ack_seq = tcph->ack_seq;
			capure_data.seq = tcph->seq;
			capure_data.packet_len = packet_len;
			capure_data.type = type;
			memcpy(&ip_data, &capure_data, sizeof(capure_data));
			
		
			strncpy(capure_data.data, http, http_header_size);
				
			memcpy(&keyword_data, &capure_data, sizeof(capure_data));
			/*
			///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			// PORT 차단
			///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
			if(tcph->dest == htons(1033)){
				puts("11");
				assemble_ack(iphiph->daddr, iphiph->saddr, tcph->dest, tcph->source, tcph->ack_seq, ntohl(tcph->seq) + packet_len-(40+14), 0);
  	  	assemble_port(iphiph->daddr, iphiph->saddr, tcph->dest, tcph->source, tcph->ack_seq, ntohl(tcph->seq) + packet_len-(40+14), packet_len-40);
  	  	assemble_rst(iphiph->saddr, iphiph->daddr, tcph->source, tcph->dest, tcph->seq+1, tcph->ack_seq, 0);
			}			
			*/
			
			switch(type){
			
				case IS_GET :
				
					if((p2 = strstr(http+150, "Host: ")) != NULL){
						unsigned long no;
						register int i=0;						
						p2 += 6;
					
						while(*p2 != '\r' && *p2 != 0){
							buf_url[i++] = *p2++;
						}
				
						buf_url[i] = 0;
						
						if( no = find_url(buf_url, url_table)){					
							
							if(find_url_base(no, url_baseobj) == 0 || find_url_obj(capure_data.saddr, no, url_netobj) == 0){
								if(find_url_base(no, url_baseobj) == 0){
									printf("url base no: %d\n", no);
								}
								if(find_url_obj(capure_data.saddr, no, url_netobj) == 0){
									printf("url obj no: %d\n", no);
								}
								
							
								/*
								////////////////////////////////////////////////////////////////////////////
								// DEBUG or LOG
								////////////////////////////////////////////////////////////////////////////
								struct in_addr addr;
								addr.s_addr = capure_data.saddr;
								printf("[URL]src:%s   ---->   ", inet_ntoa(addr));
								addr.s_addr = capure_data.daddr;
								printf("dst:%s\n", inet_ntoa(addr));
								*/
								assemble_ack(iphiph->daddr, iphiph->saddr, tcph->dest, tcph->source, tcph->ack_seq, ntohl(tcph->seq) + packet_len-(40+14), 0);
  	  					assemble_psh(iphiph->daddr, iphiph->saddr, tcph->dest, tcph->source, tcph->ack_seq, ntohl(tcph->seq) + packet_len-(40+14), packet_len-40);
    					}
    				}
					}			
				
					break;
				
				case IS_POST :
					break;
					
				default: break;
				
			
			}
		}
  }
}




void *fake_page_process(char *path)
{
	
		char cmd[128];
	
    pcap_t  *pd;                     // pcap  디스크립터
    char     ebuf[PCAP_ERRBUF_SIZE], // error buffer
            *dev;                    // device name
    
    struct in_addr      netmask,     // 넷마스크
                        network;     // 네트워크 주소
    struct bpf_program  fcode;       // 패킷필터링 프로그램
    
    pthread_t ip_filter_thread;
    pthread_t keyword_filter_thread;
    pthread_t apply_thread;
    
    int status;
    
    
    sprintf(cmd,"touch %s",URL);    			system(cmd);
    sprintf(cmd,"touch %s",KEYWORD);    	system(cmd);
    sprintf(cmd,"touch %s",IP);			    system(cmd);
    
    sprintf(cmd,"touch %s",URL_OBJ);    	system(cmd);
    sprintf(cmd,"touch %s",KEYWORD_OBJ); system(cmd);
    sprintf(cmd,"touch %s",IP_OBJ);	    system(cmd);
    
    sprintf(cmd,"touch %s",URL_BASE);    system(cmd);
    sprintf(cmd,"touch %s",KEYWORD_BASE); system(cmd);
    sprintf(cmd,"touch %s",IP_BASE);    system(cmd);
    
    
    // block page 불러오기
    get_webpage(html, path);
    
    if( policy_load() != 0 ){
    	puts("[FAKE] hashtable unload");
    	exit(1);
    }
    
    
    OPERATION = O_START;
    
    // 정책 반영 쓰레드
    if(( status = pthread_create( &apply_thread, NULL, &apply_thread_func, NULL)) != 0 ) {
			printf("Thread error : %s\n", strerror(status));
			exit(-1);
		}
		
		// 키워드 차단 쓰레드
		if(( status = pthread_create( &keyword_filter_thread, NULL, &keyword_filter_thread_func, NULL)) != 0 ) {
			printf("Thread error : %s\n", strerror(status));
			exit(-1);
		}
		
		// ip 차단 쓰레드
		if(( status = pthread_create( &ip_filter_thread, NULL, &ip_filter_thread_func, NULL)) != 0 ) {
			printf("Thread error : %s\n", strerror(status));
			exit(-1);
		}
		
		
		
    // 타임아웃  2초
    pd=pcap_open_live(answer[1],snapsize,1,1000,ebuf); // 디바이스 열기
    if(pd == NULL) {
        fprintf(stderr, "pcap_open_live fail: %s", ebuf);
        exit(1);
    }
    

    // 디바이스에 해당하는 localnet과 netmask를 얻음
    pcap_lookupnet(answer[1], &network.s_addr, &netmask.s_addr, ebuf);

    // 필터링 규칙 컴파일    
    pcap_compile(pd, &fcode, fake_rule,0, netmask.s_addr);

    pcap_setfilter(pd, &fcode); // 디스크립터에 필터링 규칙적용
    
//    printf("[FAKE] CAPUTRE START Dev='%s'[net=%s]\n", answer[1], inet_ntoa(network), inet_ntoa(netmask));
    printf("[FAKE] CAPUTRE START Dev='%s'[net=%s]\n", answer[1], inet_ntoa(network));

    // f_callback : url 차단 루틴
    if(pcap_loop(pd, -1, f_callback, NULL)<0) {
        fprintf(stderr, "pcap_loop fail: %s\n", pcap_geterr(pd));
        exit(1);
    }
        
    
    pthread_join(keyword_filter_thread, NULL);	
		pthread_join(ip_filter_thread, NULL);	
		pcap_close(pd);
   return ; 
}



void *apply_thread_func(void *data)
{
	
	while(1){
		
		// pipeline[1] : fake가 받는 파이프
		// pipeline[0] : fake가 보내는 파이프
		if( read(pipeline[0], &ipc_buf, sizeof(ipc_buf)) != -1){			
			if(ipc_buf == PLY_CHN){
				
				puts("[PIPE] SEND : LOG -> RECV : FAKE [PLY_CHN]");
				
				// 작동 중지 해쉬 테이블 다시 로드
				OPERATION = O_STOP;
				
				// 정책 다운로드				
				if (get_policy(agent_num) == -1){
					puts("[POLICY] download policy error");
				}
				puts("[POLICY] download policy");
				
				
				// 네트워크 객체 다운로드
				if(get_netobj(agent_num) == -1){
					puts("[POLICY] download network object error");
				}
				puts("[POLICY] download network object");
				
				// 해쉬 테이블 재 등록
				if( policy_load() != 0 ){
		    	puts("[FAKE] hashtable Reload error");
    			exit(1);
    		}
    		puts("[FAKE] hashtable Reload");
    		
    		// 작동 재시작
    		OPERATION = O_START;
    		
    		// 정책 적용 완료
    		ipc_buf = PLY_APP;
    		//printf("%d\n",ipc_buf);
    		write(pipeline2[1], &ipc_buf, sizeof(ipc_buf));
    		
    		
			}
			else{
				puts("[PIPE] Not found COMMAND Define");				
			}
		}		
	}	
}




int get_webpage(char *buf, char *path)
{
        int fd;
        int cnt;
        
        int i=0;
        fd = open(path, O_RDONLY);

        if(fd == -1){
                printf("FILE open() error : %s\n",path);
                return -1;
        }

        while(cnt = read(fd, &html[i++], 1));
        html[i] = 0;
        close(fd);
        return 0;
}




int policy_load()
{
	
	// 정책 파일열고 해쉬 테이블 생성
	create_url_hash_table(URL);
	puts("create_url_hash_table(URL)");
	
  create_ip_hash_table(IP);
  puts("create_ip_hash_table(IP)");
  
  create_keyword_table(KEYWORD);  
  puts("create_keyword_table(KEYWORD)");
  
  create_url_obj_table(URL_OBJ);  
  puts("create_url_obj_table(URL_OBJ)");
  
  create_ip_obj_table(IP_OBJ);  
  puts("create_ip_obj_table(IP_OBJ)");
  
  create_keyword_obj_table(KEYWORD_OBJ);  
  puts("create_keyword_obj_table(KEYWORD_OBJ)");
  
  create_base_obj(URL_BASE, IP_BASE, KEYWORD_BASE);
  puts("create_base_obj(URL_BASE, IP_BASE, KEYWORD_BASE)");
  
  return 0;
	
}




int get_policy(int agent_num)
{
	
	MYSQL       *ply_connection=NULL, ply_conn;
	int query_stat;	
	char query[600];
	char buf[300];
		
	MYSQL_RES   *sql_result;
	MYSQL_ROW   sql_row;
	
	FILE * url_fp, * keyword_fp, * ip_fp;
	
	unlink(URL);
	unlink(IP);
	unlink(KEYWORD);
	
	if( !(url_fp = fopen(URL, "w+")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(keyword_fp = fopen(KEYWORD, "w+")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(ip_fp = fopen(IP, "w+")) ){
		puts(" fopen error");
		return -1;
	}	
	
	///////////////////////////////////////////////////
	// 접속
	///////////////////////////////////////////////////
	mysql_init(&ply_conn);
	
	
	ply_connection = mysql_real_connect(&ply_conn, answer[2], USER, answer[3], NULL, 0, (char *)NULL, 0);
	if (ply_connection == NULL){
			printf("%s\n", mysql_error(&ply_conn));
			return -1;
	}	
	
	
	query_stat = mysql_select_db( ply_connection, "policy" );
	
	// SELECT distinct url.no, url.content FROM agent1_policy, url
	// where agent1_policy.type=1 and agent1_policy.catagory = url.catagory
	// and agent1_policy.no = url.no order by no
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// URL 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(query,"SELECT distinct url.no, url.content FROM agent%d_policy, url WHERE agent%d_policy.type=1 and agent%d_policy.catagory = url.catagory and agent%d_policy.no = url.no" , 
	agent_num, agent_num, agent_num, agent_num);
	
	query_stat = mysql_real_query( ply_connection, query, strlen(query) );
	
	sql_result = mysql_store_result( ply_connection );
	if( query_invalied( ply_conn, query_stat ) ){
		puts("URL POLICY DOWNLOAD FAIL");
		return -1;
	}
	puts("URL POLICY DOWNLOAD OK");
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);		
		fputs(buf, url_fp);
	}
	fclose(url_fp);	
	mysql_free_result(sql_result);
	
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// IP 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(query,"SELECT distinct %s.no, %s.content FROM agent%d_policy, %s  \
	WHERE agent%d_policy.type=3 and agent%d_policy.catagory = %s.catagory \
	and agent%d_policy.no = %s.no" , 
	POLICY_ip, POLICY_ip, agent_num, POLICY_ip, agent_num, agent_num, POLICY_ip, agent_num, POLICY_ip);
	
	query_stat = mysql_real_query( ply_connection, query, strlen(query) );
	
	sql_result = mysql_store_result( ply_connection );
	if( query_invalied( ply_conn, query_stat ) ){
		return -1;
		puts("IP POLICY DOWNLOAD FAIL");
	}
	puts("IP POLICY DOWNLOAD OK");
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);
		
		fputs(buf, ip_fp);
	}
	fclose(ip_fp);	
	mysql_free_result(sql_result);
	
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// KEYWORD 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	sprintf(query,"SELECT distinct %s.no, %s.content FROM agent%d_policy, %s  \
	WHERE agent%d_policy.type=2 and agent%d_policy.catagory = %s.catagory \
	and agent%d_policy.no = %s.no" , 
	POLICY_keyword, POLICY_keyword, agent_num, POLICY_keyword, agent_num, agent_num, POLICY_keyword, agent_num, POLICY_keyword);
	
	query_stat = mysql_real_query( ply_connection, query, strlen(query) );
	
	sql_result = mysql_store_result( ply_connection );
	if( query_invalied( ply_conn, query_stat ) ){
		puts("KEYWORD POLICY DOWNLOAD FAIL");
		return -1;
	}
	puts("KEYWORD POLICY DOWNLOAD OK");
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);
		
		fputs(buf, keyword_fp);
	}
	fclose(keyword_fp);
	mysql_free_result(sql_result);
		
	mysql_close(ply_connection);

	return 0;	
	
}



int get_netobj(int agent_num)
{
	
	MYSQL       *obj_connection=NULL, obj_conn;
	int query_stat;	
	char query[600];
	char buf[300];
	
		
	MYSQL_RES   *sql_result;
	MYSQL_ROW   sql_row;
	
	
	FILE * url_fp, * keyword_fp, * ip_fp;
	FILE	*base_url,* base_ip, * base_keyword;
	
	unlink(URL_OBJ);
	unlink(IP_OBJ);
	unlink(KEYWORD_OBJ);
	
	unlink(URL_BASE);
	unlink(IP_BASE);
	unlink(KEYWORD_BASE);	
	
	
	if( !(url_fp = fopen(URL_OBJ, "w")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(keyword_fp = fopen(KEYWORD_OBJ, "w")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(ip_fp = fopen(IP_OBJ, "w")) ){
		puts(" fopen error");
		return -1;
	}
	
	if( !(base_url = fopen(URL_BASE, "w")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(base_keyword = fopen(KEYWORD_BASE, "w")) )
	{
		puts(" fopen error");
		return -1;
	}
	if( !(base_ip = fopen(IP_BASE, "w")) ){
		puts(" fopen error");
		return -1;
	}
	
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	// DB 접속
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	mysql_init(&obj_conn);
	
	obj_connection = mysql_real_connect(&obj_conn, answer[2], USER, answer[3], NULL, 0, (char *)NULL, 0);
	if (obj_connection == NULL){
			printf("%s\n", mysql_error(&obj_conn));
			return -1;
	}
	
	query_stat = mysql_select_db( obj_connection, "policy" );
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// URL 네트워크 객체 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	
	//	select agent1_policy.no, agent1_policy.type, agent1_group.host from agent1_policy, agent1_group
	//	where agent1_policy.netobj = agent1_group.netobj and agent1_policy.type =1 order by no
	
	sprintf(query,"SELECT agent%d_policy.no, agent%d_group.host FROM agent%d_policy, agent%d_group \
	WHERE agent%d_policy.netobj = agent%d_group.netobj and agent%d_policy.type=1",
	agent_num, agent_num, agent_num, agent_num, agent_num, agent_num, agent_num);
	
	query_stat = mysql_real_query( obj_connection, query, strlen(query) );
		
	sql_result = mysql_store_result( obj_connection );
	if( query_invalied( obj_conn, query_stat ) ){
		puts("URL OBJECT DOWNLOAD FAIL");
		puts("URL BASE OBJECT DOWNLOAD FAIL");
		return -1;
	}
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		////////////////////////////////////////////////////////////////////////
		// 네트워크 전체 선택(0.0.0.0) 이면 base 파일에 네트워크 객체 저장 -? 메모리 사용 효율
		////////////////////////////////////////////////////////////////////////
		if(!strcmp(sql_row[1],TOTAL_NETWORK)){
			sprintf(buf, "%s\n", sql_row[0]);
			fputs(buf, base_url);				
		}
		else{
			sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);
			fputs(buf, url_fp);
		}		
	}
	puts("URL OBJECT DOWNLOAD OK");
	puts("URL BASE OBJECT DOWNLOAD OK");
	fclose(url_fp);
	fclose(base_url);
	mysql_free_result(sql_result);
	
	
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// IP 네트워크 객체 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	
	//	select agent1_policy.no, agent1_policy.type, agent1_group.host from agent1_policy, agent1_group
	//	where agent1_policy.netobj = agent1_group.netobj and agent1_policy.type =2 order by no
	
	sprintf(query,"SELECT agent%d_policy.no, agent%d_group.host FROM agent%d_policy, agent%d_group \
	WHERE agent%d_policy.netobj = agent%d_group.netobj and agent%d_policy.type=3",
	agent_num, agent_num, agent_num, agent_num, agent_num, agent_num, agent_num);
	
	query_stat = mysql_real_query( obj_connection, query, strlen(query) );
	
	sql_result = mysql_store_result( obj_connection );
	if( query_invalied( obj_conn, query_stat ) ){
		puts("IP OBJECT DOWNLOAD FAIL");
		puts("IP BASE OBJECT DOWNLOAD FAIL");
		return -1;
	}
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		////////////////////////////////////////////////////////////////////////
		// 네트워크 전체 선택(0.0.0.0) 이면 base 파일에 네트워크 객체 저장 -? 메모리 사용 효율
		////////////////////////////////////////////////////////////////////////
		if(!strcmp(sql_row[1],TOTAL_NETWORK)){
			sprintf(buf, "%s\n", sql_row[0]);
			fputs(buf, base_ip);				
		}
		else{		
			sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);		
			fputs(buf, ip_fp);
		}
	}
	puts("IP OBJECT DOWNLOAD OK");
	puts("IP BASE OBJECT DOWNLOAD OK");
	fclose(ip_fp);
	fclose(base_ip);
	mysql_free_result(sql_result);
	
	
	
	////////////////////////////////////////////////////////////////////////////////////////////////
	// KEYWORD 네트워크 객체 가져오기
	////////////////////////////////////////////////////////////////////////////////////////////////
	
	//	select agent1_policy.no, agent1_policy.type, agent1_group.host from agent1_policy, agent1_group
	//	where agent1_policy.netobj = agent1_group.netobj and agent1_policy.type =2 order by no
	
	sprintf(query,"SELECT agent%d_policy.no, agent%d_group.host FROM agent%d_policy, agent%d_group \
	WHERE agent%d_policy.netobj = agent%d_group.netobj and agent%d_policy.type=2",
	agent_num, agent_num, agent_num, agent_num, agent_num, agent_num, agent_num);
	
	query_stat = mysql_real_query( obj_connection, query, strlen(query) );
	
	sql_result = mysql_store_result( obj_connection );
	if( query_invalied( obj_conn, query_stat ) ){
		puts("KEYWORD OBJECT DOWNLOAD FAIL");
		puts("KEYWORD BASE OBJECT DOWNLOAD FAIL");
		return -1;
	}
	
	while( sql_row = mysql_fetch_row(sql_result) ){
		
		////////////////////////////////////////////////////////////////////////
		// 네트워크 전체 선택(0.0.0.0) 이면 base 파일에 네트워크 객체 저장 -? 메모리 사용 효율
		////////////////////////////////////////////////////////////////////////		
		if(!strcmp(sql_row[1],TOTAL_NETWORK)){
			sprintf(buf, "%s\n", sql_row[0]);
			fputs(buf, base_keyword);				
		}
		else{	
			sprintf(buf, "%s	%s\n", sql_row[0], sql_row[1]);		
			fputs(buf, keyword_fp);
		}
	}
	puts("KEYWORD OBJECT DOWNLOAD OK");
	puts("KEYWORD BASE OBJECT DOWNLOAD OK");
	fclose(keyword_fp);
	fclose(base_keyword);
	mysql_free_result(sql_result);
	
	mysql_close(obj_connection);	
	return 0;
}






