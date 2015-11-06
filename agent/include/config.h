/*
*	@ file : config.h
*/

#define CONFIG_BUFSIZE		64
#define LIST_CNT		6
#define CONF_FILE "conf/config"
#define BLOCK_PAGE "html/block_page.html"

// 설정 파일 항목
char *keyword[]={
	"ID=",
	"DEV=",
	"MASTER=",
	"PASSWORD=",
	"URL_PATH=",
};


// 설정 파일 목록
char answer[LIST_CNT][CONFIG_BUFSIZE];

void get_conf();
void _strim(char * p);



// 설정 파일에서 내용을 가져와 전역 변수(answer)에 저장
void get_conf(){
	FILE *fp;
	char buf[CONFIG_BUFSIZE];
	char *p;
	int i=0;
	
	fp = fopen(CONF_FILE, "r");
	if(!fp){
		exit(1);
	}
	
	// 주의!! 설정 항목들은 keyword 순서대로 설정파일에 적혀져 있어야 한다.
	while( fgets(buf, sizeof(buf), fp) ){
		
		_strim(buf);		
		
		
		if(*buf == '#'){
			continue;
		}
		
		else if( p = strstr(buf, keyword[i])){
			
			strcpy(answer[i], p+strlen(keyword[i]));
			
			answer[i][strlen(answer[i])-1] = '\0';
			
			
			i++;
			
		}
	}
			
	if(strlen(answer[LIST_CNT-1]) == 0)
	{
		strcpy(answer[LIST_CNT-1], BLOCK_PAGE);				
	}	
	
}

// str_trim
void _strim(char * p){
	
	char *buf, *prev;
	int i=0;
	
	buf = (char *)malloc(strlen(p)+1);
	prev = p;
	
	while(*p){
		if(*p != ' ' && *p != '\t'){
			buf[i++] = *p;			
		}		
		
		p++;
		
	}
	
	buf[i]=0;	
	strcpy(prev, buf);
	free(buf);

}


