#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <fcntl.h>
#include <time.h>

#include "../include/pcap.h"









char* itoa(unsigned int val);
char * _strcat(char * src, char * dst);
char * _strnstr(char *big, char *little, int len);
void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) ;
void Log_write(char *pbuf, char *url);
void cal_traffic();
void create_new_file();



SIZE traffic;

/* Network hader include */
struct ether_header *ep;	// ethernet
struct ip  *iph;					// ip
unsigned short ether_type;
struct tcphdr *tcph;			// tcp


char buf_header[128];			// packet_data
int fd = 0;								// LOG file discriptor
char url_host[128];				// url 문자열
char *Host;								// "Host : " 찾는 포인터
char save_file[24];
char log_dir[10];
start = 1;								// 파일을 한 순간에 하나만 생성



uint32_t pre_ip_dst;
uint32_t pre_ip_src;

struct tm *tm;
time_t t;


void cal_traffic(){
	
	while(traffic.Byte >= 1024){
		traffic.Byte -= 1024;
		traffic.KByte++;
	}
	
	if(traffic.KByte >= 1024){
		traffic.KByte -= 1024;
		traffic.MByte++;		
	}
	if(traffic.MByte >= 1024){
		traffic.MByte -= 1024;
		traffic.GByte++;		
	}
	return;	
}




void pcap_capture(char *dev, char *filter, char *dir)
{
	
	pcap_t *pd;
	char	ebuf[PCAP_ERRBUF_SIZE]; 	// error buffer
  struct in_addr      netmask, 		// 넷마스크
                      network;		// 네트워크 주소
  struct bpf_program  fcode;  	 	// 패킷필터링 프로그램  
  int status;	
	
	strcpy(log_dir, dir);

	time(&t);
	tm=localtime(&t);

  pd = pcap_open_live(dev, SNAPSIZE, PROMISCUOUS, 10000, ebuf); // 디바이스 열기
  if(pd == NULL) {
  	fprintf(stderr, "pcap_open_live fail: %s", ebuf);
    exit(0);
  }

  // device localnet과, netmask
  pcap_lookupnet(dev, &network.s_addr, &netmask.s_addr, ebuf);

		
	// 필터링 규칙 컴파일
	pcap_compile(pd, &fcode, filter, 0, netmask.s_addr);
  pcap_setfilter(pd, &fcode); // 디스크립터에 필터링 규칙적용

  printf("Device='%s'(network=%s, netmask=%s)\n", dev, inet_ntoa(network), inet_ntoa(netmask));

	
	
	
	// LOG 파일 열기
	sprintf(save_file, "%s/AG%02d%02d",log_dir, tm->tm_mday, tm->tm_hour);	
	fd = open(save_file, O_RDWR | O_CREAT);		// 백업 파일 open
	
	
	if(pcap_loop(pd, -1, pcap_callback, NULL)<0) {
		fprintf(stderr, "pcap_loop fail: %s\n", pcap_geterr(pd));
        exit(-1);
  }
    
  pcap_close(pd);	// close the packet capture discriptor
}




/*
 * @ pcap_capture's  callback
 */

void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) 
{	
	
	char * pbuf = buf_header;	//헤더 정보	
	register int i = 0;	
	
	//usleep(0.1);
	
	// 시간 체크
	time(&t);
	tm=localtime(&t);
	
	if(tm->tm_sec == 0 && tm->tm_min == 0 && start == 1){
		create_new_file();
		start = 0;
	}
	
	if(tm->tm_sec == 1 && tm->tm_min == 0){		
		start = 1;
	}
	
	
	// 트래픽 계산
	traffic.Byte += h->len;	
	cal_traffic();
	
	//s += h->len;
	
	// 이더넷 헤더
	ep = (struct ether_header *)packet;
	
	// IP헤더 가져오기 위해 이더넷 헤더 만큼 offset
	packet += sizeof(struct ether_header);
	
	// 이더넷 헤더 타입
  ether_type = ntohs(ep->ether_type);
  
	
	// @ IP protocol
	iph = (struct ip *)packet;
	uint32_t d = (iph->ip_dst).s_addr;
	uint32_t s = (iph->ip_src).s_addr;
  if (ether_type == ETHERTYPE_IP && d != pre_ip_dst && s != pre_ip_src){
  	
  	pre_ip_dst = (iph->ip_dst).s_addr;
  	pre_ip_src = (iph->ip_src).s_addr;
  	
  	
  	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // @ TCP protocol
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////  	
    
    tcph = (struct tcphdr *)(packet + iph->ip_hl * 4);
    
    int x = tcph->psh;        
		if (iph->ip_p == IPPROTO_TCP  && (x == 1)){
			
			
    	// @point : http header 
      packet += sizeof(struct tcphdr) + 20; // 20 tcp header
      
    	
    	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    	// @ HTTP protocol
    	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    	if(tcph->dest == htons(80)){
    		
    		
    		if((Host = strstr(packet+300, "Host: ")) != NULL){    			
    			
    			int i = 0;
    			Host += 6;
    			while( *Host != '\r' && *Host != 0 )
    				url_host[i++] = *Host++;    				
    			
    			url_host[i] = 0;
    			puts(url_host);
    			
    			Log_write(pbuf, url_host);
    			
    			
    			write(fd, buf_header, strlen(buf_header));
    			
    			
    		}
    		
    	}    	
    	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    	// @ NOT HTTP protocol
    	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
    	else{
    		
    		Log_write(pbuf, "TCP");
    			
    		write(fd, buf_header, strlen(buf_header));
    		
 //   		printf("%s", buf_header);
   	
    	}   	
    }
    
  
  	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
		// @ UDP protocol
  	///////////////////////////////////////////////////////////////////////////////////////////////////////////////
  	else if(iph->ip_p == IPPROTO_UDP){  		
  		
  		Log_write(pbuf, "UDP");
  		
    	write(fd, buf_header, strlen(buf_header));  	
    }
    
    
    
  }  
  
  
  
  printf("%s", buf_header);
 // printf("%d %d %d %d	%d	%d\n",traffic.GByte,traffic.MByte,traffic.KByte,traffic.Byte, h->len, s);
}



void Log_write(char *pbuf, char *url)
{
	memset(buf_header, 0, sizeof(buf_header));
	pbuf = (char *)_strcat(pbuf, (char *)inet_ntoa(iph->ip_src));
	pbuf = (char *)_strcat(pbuf, "\t");
	pbuf = (char *)_strcat(pbuf, itoa(ntohs(tcph->source)));
	pbuf = (char *)_strcat(pbuf, "\t");
	pbuf = (char *)_strcat(pbuf, (char *)inet_ntoa(iph->ip_dst));
	pbuf = (char *)_strcat(pbuf, "\t");
	pbuf = (char *)_strcat(pbuf, itoa(ntohs(tcph->dest)));
	pbuf = (char *)_strcat(pbuf, "\t");
	pbuf = (char *)_strcat(pbuf, url);
	pbuf = (char *)_strcat(pbuf, "\t");
				
	*pbuf++ = (tm->tm_year+1900) / 1000 + '0';
	*pbuf++ = ((tm->tm_year+1900) % 1000) / 100 + '0';
	*pbuf++ = ((tm->tm_year+1900) % 100) / 10 + '0';
	*pbuf++ = (tm->tm_year+1900) % 10 + '0';
	*pbuf++ = '-';
	*pbuf++ = (tm->tm_mon) / 10 + '0';
	*pbuf++ = (tm->tm_mon) % 10 + '0';
	*pbuf++ = '-';
	*pbuf++ = (tm->tm_mday) / 10 + '0';
	*pbuf++ = (tm->tm_mday) % 10 + '0';
	*pbuf++ = '\t';
	*pbuf++ = (tm->tm_hour) / 10 + '0';
	*pbuf++ = (tm->tm_hour) % 10 + '0';
	*pbuf++ = '-';
	*pbuf++ = (tm->tm_min) / 10 + '0';
	*pbuf++ = (tm->tm_min) % 10 + '0';
	*pbuf++ = '-';
	*pbuf++ = (tm->tm_sec) / 10 + '0';
	*pbuf++ = (tm->tm_sec) % 10 + '0';
	*pbuf++ = '\n';
	
}




char* itoa(unsigned int val)
{
	static char buf[32] = {0};
	int i = 30;
	for( ; val && i ; --i, val /= 10)
		buf[i] = "0123456789"[val % 10];
	return &buf[i+1];
}




char * _strcat(char * src, char * dst)
{
	while(*src++); src--;
	while(*src++ = *dst++);	src--;
	return src;
}




/*  strstr 함수에 검색 길이 조건 추가  */
char * _strnstr(char *big, char *little, int len)
{
	char *p1, *p2;
	while(len){
		while(len > 0 && *big++ != *little) len--;
		if(len <= 0) break;
		p1 = big-1;
		p2 = little;
		while(*p2 && *p1 == *p2) { p1++; p2++; }
		if(!*p2) return big-1;
		len--;
	}
	return NULL;
}



/*
 * 매 시간 마다 새로운 파일을 만들어 주고 sorting..
 * 해당 에이전트 로그 전송시간에 sorting된 로그파일을 전송
 */
void create_new_file()
{
	
	if(fd){
		close(fd);
		puts("[pcap] New Log file");
	}
	
	sprintf(save_file, "%s/AG%02d%02d",log_dir, tm->tm_mday, tm->tm_hour);	
	fd = open(save_file, O_RDWR | O_CREAT);		// 백업 파일 open
	
	
}


