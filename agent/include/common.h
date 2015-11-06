
/*
* @ file : common.h
*	brief : 
*/

#define MAX_AGENT	30
#define LISTENSIZE 10
#define moduler 31	// trans_time 계산시 moduler 값
#define LOGFILE	"LOG_FILE"
#define REFRESH_TIME 7

int alive_interval = 2; // alive 주기적인 인터벌 시간
int log_send_sec = 10;	// LOG 파일을 보내는 초 시간
enum {START, STOP} STATUS;
enum {F_START, F_STOP} FAKE;


int trans_time;		//전송 할 시간(sec) : 계산법 = agent 번호 % 60
int agent_num=0;	//에이전트 ID


int command_sock;
