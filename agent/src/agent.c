/*
*	@ file  : agent.c
* @ brief : 
* @ include : ../include
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <pthread.h>
#include <mysql.h>

/*
* include 순서 지켜 줄것
*/
#include "../include/ifconfig.h"
#include "../include/common.h"	//일반 설정 해데
#include "../include/db.h"
#include "../include/command.h"
#include "../include/config.h"
#include "../include/time.h"
#include "../include/system.h"
#include "../include/pcap.h"
#include "../include/port.h"
#include "../include/facke_page.h"
#include "../include/net_zone.h"





extern struct system_monitor System;
void *pcap_thread_func( void *data );
void *alive_thread_func( void *data );
void *timer_thread_func( void *data );
void *log_thread_func( void *data );
void sort_func();
void create_new_file();
void *live_log_thread_func( void *sock );


int main(int argc, char **argv){
		
	int connect_cnt=0;		
	struct sockaddr_in master_addr;		
	
	pthread_t alive_thread;	
	pthread_t pcap_thread;	
	pthread_t timer_thread;	
	pthread_t live_log_thread;
	pthread_t arp_packet_thread;
	
	
	int optval=1;
	int status;
	
	int delaytime=0;
	int refresh = 0;
	
	int pid;


	get_localtime();
	
	if( pipe(pipeline) == -1)
	{
		puts("pipe() error");
		exit(1);
	}
	if( pipe(pipeline2) == -1)
	{
		puts("pipe() error");
		exit(1);
	}
	
	
	STATUS = STOP;
	FAKE = F_STOP;
	
	// @ 설정 파일 불러오기
	get_conf();
	
	// ifconfig 의 ip, mac, broadcast, netmask, mtu 가져오기
	get_ifconfig(&ifcg, answer[1]);
	
	// @ LOG 디렉토리 생성
	if(access(log_dir,0) != 0){
		mkdir(log_dir);
	}	
	
	// 에이전트 번호 확인
	if(strlen(answer[0]) != 0){
		agent_num = atoi(answer[0]);
		trans_time = agent_num % moduler;	// 해당 에이전트가 LOG 파일을 보내야 할 시간
		
		  puts("┌───────────────────┐");		
		printf("│I am AGENT[%d]                         │\n", agent_num);
		printf("│I will send LOG file %dmin             │\n", trans_time);
		  puts("└───────────────────┘");		
	}
	else{
		agent_num = 0;
		printf("I yet haven't agent ID\n");
	}
	
	/////////////////////////////////////////////////////////////
	// command rutine
	/////////////////////////////////////////////////////////////
	
RESTART:
	
	command_sock = socket(PF_INET, SOCK_STREAM, 0);
	if(command_sock == -1){
		puts("agnet sock error");
		exit(-1);
	}
	
	
	
	memset(&master_addr, 0, sizeof(master_addr));
	master_addr.sin_family = AF_INET;
	master_addr.sin_addr.s_addr = inet_addr(answer[2]);
	master_addr.sin_port = htons(MASTER_PORT);	
	
	
	
	// TIME_WAIT 시 IP 재사용 하기위한 set sock
	//ling.l_onoff = 1;
	//ling.l_linger = 0;
	//setsockopt(command_sock, SOL_SOCKET, SO_LINGER, (char *)&optval, (int)sizeof(optval));
	setsockopt(command_sock, SOL_SOCKET, SO_REUSEADDR, &optval, (int)sizeof(optval));
	
	
	
	
	printf("┌────< Master connection information  >─────┐\n");
	printf("│ MASTER IP     %s                       │\n",answer[2]);
	printf("│ MASTER PORT   %d                                 │\n",MASTER_PORT);
	  puts("└──────────────────────────┘");
	
	

	while( connect(command_sock, (struct sockaddr*) &master_addr, sizeof(master_addr)) == -1 ){
		sleep(5);
		printf("[CONNECT] master connection attemptedcount\n");
	}
	
		
	memset(&send_cmd, 0, sizeof(send_cmd));
	memset(&recv_cmd, 0, sizeof(recv_cmd));
	
	// 전송 타입 
	// 1. ID 있는 경우
	// 2. ID 없는 경우
	if(agent_num != 0){	// ID 값이 있다면
		send_cmd.signal = HELLO_WITH_ID;
		send_cmd.data = agent_num;
		puts("[COMMAND] SEND : AGENT ----> RECV : MASTER [HELLO_WITH_ID]");
	}
	else{
		send_cmd.signal = HELLO_NO_ID;
		puts("[COMMAND] SEND : AGENT ----> RECV : MASTER [HELLO_NO_ID]");
	}
	
	
	// @ SEND
	write(command_sock, &send_cmd, sizeof(send_cmd));
	
	
	
	while(1){
		
		// MASTER 가 접속이 끊어 졌을 경우 모든 쓰레드를 종료 한다.
		if(tz.sec == delaytime){
			refresh++;
			if(refresh >= REFRESH_TIME){
				refresh = 0;
				STATUS = STOP;
				
				close(command_sock);				
				goto RESTART;
			}
		}
	
		
		//if(rz.sec)
		
		
		memset(&send_cmd, 0, sizeof(send_cmd));
		memset(&recv_cmd, 0, sizeof(recv_cmd));
		fflush(NULL);
	 
		// @ RECV
		puts("┌───────────────────┐");
		puts("│[COMMAND] Waiting for COMMAND...      │");
		puts("└───────────────────┘");
		
		if ( read(command_sock, &recv_cmd, sizeof(recv_cmd)) != 0 ){		
			
	
			//printf("cnt:%d	sig:%d	data:%d	 sock:%d\n",cnt++, recv_cmd.signal, recv_cmd.data,command_sock);
			switch(recv_cmd.signal){

////////////////////////////////////////////////////
// ACK_WITH_ID - 에이전트 번호 할당 받음
////////////////////////////////////////////////////			
				case ACK_WITH_ID:
				
					puts("[COMMAND] SEND : MASTER -> RECV : AGENT [ACK_WITH_ID]");
							
					////////////////////////////////////////////////////////////
					// MAX_AGENT error : 최대 30대 까지 연결 가능
					///////////////////////////////////////////////////////////
					if(recv_cmd.data > MAX_AGENT){
						printf("[MAX_AGENT] MAX_AGENT is %d\n",MAX_AGENT);
						exit(1);								
					}
							
					FILE *fp = fopen(CONF_FILE, "w");
		
					if(fp == NULL){
						puts("agernt.conf file can not open()");
						exit(1);			
					}
		
					// 설정 파일 다시 쓰기 - 할당 받은 번호를 추가하기 위해서..//
					char buffer[CONFIG_BUFSIZE];
		
					sprintf(buffer,"ID = %d\n", recv_cmd.data);
					fputs(buffer, fp);
					sprintf(buffer,"DEV=%s\n",answer[1]);
					fputs(buffer, fp);					
					sprintf(buffer,"MASTER=%s\n",answer[2]);
					fputs(buffer, fp);
					sprintf(buffer,"PASSWORD=%s\n",answer[3]);
					fputs(buffer, fp);
					sprintf(buffer,"IP=%s\n",answer[4]);
					fputs(buffer, fp);
					sprintf(buffer,"URL_PATH=%s\n",answer[5]);	
					fputs(buffer, fp);
					fclose(fp);
		
					// @ 설정 다시 파일 불러오기
					get_conf();
		
					// @ agent ID 재 부여
					agent_num = atoi(answer[0]);
					trans_time = agent_num % moduler;
				  	puts("┌───────────────────┐");		
					printf("│[ALRAM] I am AGENT[%d]                 │\n", agent_num);
					printf("│[ALRAM] I will send LOG file %dmin│\n", trans_time);
					  puts("└───────────────────┘");		
				
					// 쓰레드 시작 상태 돌입
					STATUS = START;
				
					// @ alive_thread
					if(( status = pthread_create( &alive_thread, NULL, &alive_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));
						//shutdown(command_sock, 0);
						//close(command_sock);
					}				
						
					// @ pcap_thread
					if(( status = pthread_create( &pcap_thread, NULL, &pcap_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));
					}
						
					// @ timer_thread
					if(( status = pthread_create( &timer_thread, NULL, &timer_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));
					}				
					
					
					// send start_ok							
					//send_cmd.signal = START_OK;
					//send_cmd.data = agent_num;
				
					//write(close(command_sock), &send_cmd.signal, sizeof(send_cmd));
					break;
				
					
////////////////////////////////////////////////////
// ACK_OK - 에이전트가 시작해도 좋다는 시그널
////////////////////////////////////////////////////		
				case ACK_OK :
					
					puts("[COMMAND] SEND : MASTER -> RECV : AGENT [ACK_OK]");
					
					// 쓰레드 시작 상태 돌입 				
					STATUS = START;
				
					// @ alive_thread
					if(( status = pthread_create( &alive_thread, NULL, &alive_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));					
					}
						
					// @ pcap_thread
					if(( status = pthread_create( &pcap_thread, NULL, &pcap_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));
					}
						
					// @ timer_thread
					if(( status = pthread_create( &timer_thread, NULL, &timer_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));					
					}
					
				
					// send start_ok
					//send_cmd.data = agent_num;
					//send_cmd.signal = START_OK;
					//write(close(command_sock), &send_cmd.signal, sizeof(send_cmd));
				
					break;
////////////////////////////////////////////////////
// ACK_INVALID - 잘못된 연결 / 에이전트 프로그램 종료 시킨다.
////////////////////////////////////////////////////
				case ACK_INVALID:
				
					puts("[COMMAND] SEND : MASTER -> RECV : AGENT [ACK_INVALID]");
					puts("[ERROR] ./conf/config file syntax error or program error");					
					close(command_sock);
						
					exit(1);
////////////////////////////////////////////////////
// REQPOLY - 정책이 변경되어 다시 다운로드 하라는 시그널
///////////////////////////////////////////////////					
			
				case REQ_POLY:
					
					puts("[COMMAND] SEND : MASTER -> RECV : AGENT [REQ_POLY]");
					
					ipc_buf = PLY_CHN;					
					puts("[PIPE] SEND : LOG -> RECV : FAKE [PLY_CHN]");
					write(pipeline[1], &ipc_buf, sizeof(ipc_buf));
					
					
					if( read(pipeline2[0], &ipc_buf, sizeof(ipc_buf)) != -1){
						
						if(ipc_buf == PLY_APP){
							puts("[PIPE] SEND : FAKE -> RECV : LOG [PLY_APP]");
							
							
							send_cmd.signal = RPL_POLY;							
							send_cmd.data = 0;
							
							write(command_sock, &send_cmd, sizeof(send_cmd));
							puts("[COMMAND] SEND : AGENT -> RECV : MASTER [PLY_POLY]");
							
						}
						else{
							puts("[PIPE] Not found Define");
						}
						
					}
					
				
					break;

///////////////////////////////////////////////////
// REQLIVE - 실시간 LOG를 원한다
///////////////////////////////////////////////////
				case REQ_LIVE:
				
					puts("[COMMAND] SEND : MASTER -> RECV : AGENT [REQ_LIVE]");
				
				
					if(( status = pthread_create( &live_log_thread, NULL, &live_log_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));					
					}
				
								
					//pthread_join(alive_thread, NULL);
				
					break;


///////////////////////////////////////////////////
// REQ_NET_ZONE - 네트워크 호스트 질의
///////////////////////////////////////////////////					
					
				case REQ_NET:
					
					puts("[COMMAND] SEND : AGENT -> RECV : MASTER [REQ_NET]");
					// @ arp_packet_thread
					if(( status = pthread_create( &arp_packet_thread, NULL, &arp_packet_thread_func, (void*)NULL)) != 0 ) {
						printf("Thread error : %s\n", strerror(status));
					}
					
					pthread_join(arp_packet_thread, NULL);
					
					send_cmd.signal = RPL_NET;
					send_cmd.data = 0;
							
					write(command_sock, &send_cmd, sizeof(send_cmd));
					puts("[COMMAND] SEND : AGENT -> RECV : MASTER [PLY_NET]");
					
					
				
				default:
					break;
					
					
				
			}
		}
	
		delaytime = tz.sec;
		
		////////////////////////////////////////////////////////////////////////
		// FORK
		////////////////////////////////////////////////////////////////////////
		if( FAKE == F_STOP ){
			
			FAKE = F_START;
			
			pid = fork();
			
			// fake page process 생성
			if(pid == 0){
				puts("[FAKE] Fack page PROCESS START");
				fake_page_process(answer[5]);
				
			}
			else if(pid == -1){
				exit(0);
			}
		}
	}		
	
	
	pthread_join(alive_thread, NULL);
	pthread_join(pcap_thread, NULL);
	pthread_join(timer_thread, NULL);
							
	
}





void *live_log_thread_func( void *sock )
{
	if(STATUS == START){
		live_pcap_capture(answer[1], pcap_filter, agent_num, answer[2], USER, answer[3], command_sock);
	}else{
		pthread_exit(0);
	}
}




// pcap 루틴
void *pcap_thread_func( void *data )
{
	
	printf("[PCAP START]\n");
	
	
	pcap_capture(answer[1], pcap_filter);
	
}



// alive 루틴
void *alive_thread_func( void *data )
{
	/*
	struct system{	
	char disk_used[2][3];
	char disk_mount[3][8];	
	char mem_stat;	
	char cpu_stat;	
};
struct system System;

*/
	
	char query[400];
	int query_stat;	
	char cpu, mem;
	
	int alive_value=1;
	
	printf("[ALIVE START]\n");
	
	
	
	// alive MYSQL 세션 연결
	if((mysql_alive_connection(answer[2], USER, answer[3])) != 0)
	{
		puts("[DBMS] alive_master DBMS connected fialed!");
	}
	
	
	while(STATUS == START){		
		alive_value *= -1;
		
		system_moniter(alive_interval);
		
		if(!System.disk_mount[0]){
			strcpy(System.disk_mount[0], "null");
		}
		if(!System.disk_mount[1]){
			strcpy(System.disk_mount[1], "null");
		}
		if(!System.disk_used[0]){
			strcpy(System.disk_used[0], "0");
		}
		if(!System.disk_used[1]){
			strcpy(System.disk_used[1], "0");
		}
		
		// @ query send system_moniter
		sprintf(query, "UPDATE %s SET save_time=%d, cpu=%d, mem=%d, disk1_name='%s', disk1=%s, disk2_name='%s', disk2=%s where id=%d",		AGENT_INFORMATION_STATUS, alive_value, System.cpu_stat, System.mem_stat, System.disk_mount[0], System.disk_used[0],System.disk_mount[1], System.disk_used[1], agent_num);
		//puts(query);
		fflush(0);
		query_stat = mysql_real_query(alive_connection, query, strlen(query));
		
		
		
		if( query_invalied(alive_conn, query_stat) ){
	//		mysql_close(alive_connection);
			//exit(-1);
		}
		
		//puts("send system information to master DBMS");
		
	}
	mysql_close(alive_connection);
	pthread_exit(0);
	
}


// timer 루틴
void *timer_thread_func( void *data )
{
	
	pthread_t log_thread;
	int status;	
	int start = 1;								// 파일을 한 순간에 하나만 생성
	
	
	printf("[TIMER START]\n");
	
	
	while(STATUS == START){
		
		sleep(1);
		get_localtime();
		
		
		// LOG 파일을 보낸다. 보내야 할 분에 log_send_sec 초가 되면....
		if(trans_time == tz.min && tz.sec == log_send_sec){
			
			if(( status = pthread_create( &log_thread, NULL, &log_thread_func, NULL)) != 0 ) {
				printf("Thread error : %s\n", strerror(status));
				exit(-1);
			}
			
		}
		
		// 정시 
		if(tz.sec == 0 && tz.min == 0 && start == 1){
			FILE *traffic_fd;
			char buf[64];
			//새로운 파일 생성
			create_new_file();
			
			if( (traffic_fd = fopen(TRAFFIC_FILE, "w")) == NULL ){
				puts("[TRAFFIC]TRAFFIC_FILE cant not create file");
			}
			sprintf(buf, "%d-%d-%d\t%d\t%d\t%d\t%d\t%d\t%d", tz.pre_year, tz.pre_mon+1, tz.pre_mday,   tz.pre_hour, traffic.TByte, traffic.GByte, traffic.MByte, traffic.KByte, traffic.Byte);			
//			fputs(buf, traffic_fd);
			memset(&traffic, 0, sizeof(traffic));
			sprintf(buf, "%d-%d-%d\t%d\t%d\t%d\t%d\t%d\t%d", tz.pre_year, tz.pre_mon+1, tz.pre_mday,   tz.pre_hour, traffic.TByte, traffic.GByte, traffic.MByte, traffic.KByte, traffic.Byte);			
//			puts(buf);
			fclose(traffic_fd);
			
			printf("[SAVE] %s\n",buf);
			
			start = 0;
		}
	
		if(tz.sec == 1 && tz.min == 0){		
			start = 1;
		}
		
		/*
		
		// 1시간 동안 저장된 LOG 파일 닫고, 새로운 시간대 LOG파일 열기
		if(tz.min == 0 && tz.sec == 0){			
			
			//sleep(1);//usleep(900000); // = usleep(1000000);			
			chang_file();
			
		}
			
		*/
		
	}
	pthread_exit(0);
	
}


// log 전송 루틴
void *log_thread_func( void *data )
{
	char query[356];
	int query_stat;
	puts("");
	printf("┌───[ log start  ]────┐\n");
	printf("└──────────────┘\n");
	
	puts("[SORT] LOG FILE sorting start........");
	sort_func();
	puts("[SORT] LOG FILE sorting end..........");
	
	
	// log MYSQL 세션 연결
	if ((mysql_log_connection(answer[2], USER, answer[3])) != 0){
		puts("[DBMS] log_master DBMS connected success!");
	}
	
	sprintf(query, "./%s/AG%02d%02d",  log_dir, tz.pre_mday, tz.pre_hour);
	//////////////////////////////////////////////////////////////////////////////////////////////////
	if( access(query, 0) ==0 && agent_num != 0){
	
		//LOAD DATA local INFILE './packet/AG0100' into table agent1.AG0100;
		sprintf(query, 
			"LOAD DATA local INFILE './%s/%s' into table %s%d.AG%02d%02d"
	 		, log_dir, LOGFILE, AGENT,agent_num, tz.pre_mday, tz.pre_hour);
	 
	 
		query_stat = mysql_real_query(log_connection, query, strlen(query));
	 
	 
		if( query_invalied(log_conn, query_stat) ){
			return;
		}
		
		/*
		typedef struct size{
		int Byte;
		int KByte;
		int MByte;
		int GByte;
		int TByte;
		}SIZE;	
		*/
		// 트래픽 전송 --> statics.agent + 번호
		sprintf(query, 
			"LOAD DATA local INFILE './%s' into table %s%d", TRAFFIC_FILE, STATICS_AGENT, agent_num);
		/*
		sprintf(query, 
			"INSERT INTO %s%d (date, time, tbyte, gbyte, mbyte, kbyte, byte) VALUES('%d-%d-%d','%d', %d,%d,%d,%d,%d) "
	 		, STATICS_AGENT, agent_num, tz.pre_year, tz.pre_mon+1, tz.pre_mday,   tz.pre_hour, traffic.TByte, traffic.GByte, traffic.MByte, traffic.KByte, traffic.Byte);
		*/
//		puts(query);
		query_stat = mysql_real_query(log_connection, query, strlen(query));
		
		if( query_invalied(log_conn, query_stat) ){
			return;
		}
					
		printf("[LOG] Send file : %s\n", query);
		
		
		puts("[LOG] PRE LOG FILE delete");
		
		sprintf(query, "%s/AG%02d%02d", log_dir, tz.pre_mday, tz.pre_hour);
		unlink(query);
		sprintf(query, "%s/AG%02d%02d", log_dir, tz.pre_mday, tz.pre_hour);
		unlink(query);
//		puts(query);
		system(query);
		
	}
	else{
		printf("[LOG] No file : %s\n", query);
	}
	
	mysql_close(log_connection);

	
}


void sort_func()
{
	char system_sort[64];
	
	sprintf(system_sort,"sort -u %s/AG%02d%02d | sort -k 7 > %s/%s", log_dir, tz.pre_mday, tz.pre_hour, log_dir,LOGFILE);
		
	system(system_sort);
	
	return;
}




/*	
void apply_thread_func( void *sock )
{
	//get_policy();
	
}	
*/
//update policy.game set agent1='N', agent2='N',agent3='N',agent4='N',agent5='N',agent6='N',agent7='N',agent8='N',agent9='N',agent10='N',agent11='N',agent12='N',agent13='N',agent14='N',agent15='N',agent16='N',agent17='N',agent18='N',agent19='N',agent20='N',agent21='N',agent22='N',agent23='N',agent24='N',agent25='N',agent26='N',agent27='N',agent28='N',agent29='N',agent30='N';




void create_new_file()
{
	
	
	
	if(fd){
		close(fd);
		puts("[pcap] New Log file");
	}
	
	sprintf(save_file, "%s/AG%02d%02d",log_dir, tz.mday, tz.hour);	
	fd = open(save_file, O_RDWR | O_CREAT);		// 백업 파일 open
	return;

}
