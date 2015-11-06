
/*
* @ file : db.c
*	brief : 
*/

#define HELLO_WITH_ID	1
#define HELLO_NO_ID		2

#define ACK_WITH_ID		3
#define ACK_OK				4
#define ACK_INVALID		5

#define REQ_LIVE			6
#define REQ_POLY			7

#define RPL_LIVE			8
#define RPL_POLY			9

#define START_OK			10


#define	REQ_NET				11
#define RPL_NET				12


// web에서는 struct.. int 자료형이 없기 때문에...
#define WEB_REQ_LIVE	"LIVE"
#define WEB_REQ_POLY	"POLY"
#define WEB_REQ_NET		"NET"

#define WEB_PRL_LIVE	"RPLY_LIVE"
#define WEB_PRL_POLY	"RPLY_POLY"
#define WEB_PRL_NET		"RPLY_NET"



typedef struct command{	
	unsigned char signal;	
	unsigned int data;	
}COMMAND;

//command
COMMAND recv_cmd, send_cmd;	// 커맨드 구조체


char WEB_COMMAND[8];
