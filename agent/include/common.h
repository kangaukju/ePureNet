
/*
* @ file : common.h
*	brief : 
*/

#define MAX_AGENT	30
#define LISTENSIZE 10
#define moduler 31	// trans_time ���� moduler ��
#define LOGFILE	"LOG_FILE"
#define REFRESH_TIME 7

int alive_interval = 2; // alive �ֱ����� ���͹� �ð�
int log_send_sec = 10;	// LOG ������ ������ �� �ð�
enum {START, STOP} STATUS;
enum {F_START, F_STOP} FAKE;


int trans_time;		//���� �� �ð�(sec) : ���� = agent ��ȣ % 60
int agent_num=0;	//������Ʈ ID


int command_sock;
