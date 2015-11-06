// 해쉬 테이블 구조체
// 인자: URL 명
//     : 다음 구조체 포인터


#define LEN					1000000
#define OBJ_SIZE		256
#define HASH	5432
#define NON_VALUE	-1
#define MAXKEYWORD 5000
#define MAXWORD 	24


////////////////////////////////////////////////
// 차단 정책 해쉬 테이블
////////////////////////////////////////////////
struct deny_link{
	char *target;
	unsigned long no;
	struct deny_link *next;
};

struct ip_link{
	unsigned long target;
	unsigned long no;
	struct ip_link *next;
};

struct keyword_link{
	char keyword[MAXWORD];
	unsigned long no;
};



////////////////////////////////////////////////
// 네트워크 객체 해쉬 테이블
////////////////////////////////////////////////
struct url_obj{
	unsigned long no;
	struct url_obj *next;
};

struct keyword_obj{
	unsigned long no;
	struct keyword_obj *next;
};

struct ip_obj{
	unsigned long no;
	struct ip_obj *next;
};

////////////////////////////////////////////////
// 네트워크 객체 해쉬 테이블
////////////////////////////////////////////////
struct url_base{
	unsigned long 	no;
	struct url_base *next;
};

struct keyword_base{
	unsigned long 			no;
	struct keyword_base *next;
};

struct ip_base{
	unsigned long no;
	struct ip_base *next;
};





struct deny_link 			url_table[LEN];
struct keyword_link 	keyword_table[MAXKEYWORD];
struct ip_link 				ip_table[LEN];


struct url_obj 			url_netobj[OBJ_SIZE];
struct ip_obj 			ip_netobj[OBJ_SIZE];
struct keyword_obj 	keyword_netobj[OBJ_SIZE];


struct url_base				url_baseobj[LEN];
struct ip_base				ip_baseobj[LEN];
struct keyword_base		keyword_baseobj[LEN];

