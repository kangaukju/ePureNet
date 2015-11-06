/*
*	@file : make policy program
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <mysql.h>

#define PATH "new_db"

#define CREATE_POLICY	"CREATE DATABASE policy"

#define CREATE_CATAGORY	"CREATE TABLE `policy`.`catagory` ( \
  `no` INTEGER UNSIGNED NOT NULL AUTO_INCREMENT, \
  `name` VARCHAR(45) NOT NULL, \
  `korean` VARCHAR(45) NOT NULL, \
  PRIMARY KEY (`no`) \
)ENGINE=MyISAM"


#define shop 					"insert into policy.catagory values ('','shop','쇼핑')"
#define adult					"insert into policy.catagory values ('','adult','성인')"
#define education			"insert into policy.catagory values ('','education','교육')"
#define society				"insert into policy.catagory values ('','society','사회')"
#define computer			"insert into policy.catagory values ('','computer','컴퓨터')"
#define entertain			"insert into policy.catagory values ('','entertain','연예')"
#define media					"insert into policy.catagory values ('','media','미디어')"
#define living				"insert into policy.catagory values ('','living','생활/건강')"
#define culture				"insert into policy.catagory values ('','culture','문화')"
#define tour					"insert into policy.catagory values ('','tour','여행')"
#define religion			"insert into policy.catagory values ('','religion','종교')"
#define game					"insert into policy.catagory values ('','game','게임')"
#define sports				"insert into policy.catagory values ('','sports','스포츠')"
#define economy				"insert into policy.catagory values ('','economy','경제')"
#define p2p						"insert into policy.catagory values ('','p2p','p2p')"
#define organization	"insert into policy.catagory values ('','organization','기관/조직')"
#define internet			"insert into policy.catagory values ('','internet','인터넷')"
#define international	"insert into policy.catagory values ('','international','국제')"
#define politics			"insert into policy.catagory values ('','politics','정치')"
#define etc						"insert into policy.catagory values ('','etc','기타')"

#define drop_db				"drop database policy"


#define CREATE_IP	"CREATE TABLE `policy`.`ip` ( \
  `no` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, \
  `type` TINYINT(3) UNSIGNED NOT NULL, \
  `catagory` TINYINT(3) UNSIGNED NOT NULL, \
  `content` CHAR(15) NOT NULL, \
  PRIMARY KEY (`no`) \
)ENGINE=MyISAM"

#define CREATE_KEYWORD	"CREATE TABLE `policy`.`keyword` ( \
  `no` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, \
  `type` TINYINT(3) UNSIGNED NOT NULL, \
  `catagory` TINYINT(3) UNSIGNED NOT NULL, \
  `content` VARCHAR(24) NOT NULL, \
  PRIMARY KEY (`no`) \
)ENGINE=MyISAM"

#define CREATE_URL	"CREATE TABLE `policy`.`url` ( \
  `no` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, \
  `type` TINYINT(3) UNSIGNED NOT NULL, \
  `catagory` TINYINT(3) UNSIGNED NOT NULL, \
  `content` VARCHAR(255) NOT NULL, \
  PRIMARY KEY (`no`, `content`) \
)ENGINE=MyISAM"



MYSQL       *connection=NULL, conn;

int mysql_connection(char *host, char *user, char *password)
{		
	mysql_init(&conn);	
	connection = mysql_real_connect(&conn, host, user, password, NULL, 0, (char *)NULL, 0);
	if (connection == NULL){
			printf("%s\n", mysql_error(&conn));
			return -1;
	}
	return 0;
}


int query_invalied(MYSQL con, int query_stat)
{

	if (query_stat != 0){
		printf("%s\n", mysql_error(&con));
		return -1;
	}
	return 0;
}

int main(int argc, char ** argv)
{
	char query[1024], content[256];
	char host[15], password[24];
	int query_stat;
	FILE *fp;
	
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	printf("![CAUTION] Policy dtabase delete ALL DATA!");
	printf("!      Reconfiguration AGENT POLICY      !");
	printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
	
	printf("DB Server Host:");
	scanf("%s", host);
	
	printf("DB Server Password:");
	scanf("%s", password);
	
	
	if( mysql_connection(host, "root", password) == -1){
		puts("Can not connected to DB Server\nCheck your host or password");
		exit(1);
	}
	
	printf("Drop database policy? [Enter]");
	getch();
	
	
	
	printf("Create database policy? [Enter]");
	getch();	
	
	query_exe(CREATE_POLICY);
	query_exe(query_exe);
			
	query_exe(shop);
	query_exe(adult);
	query_exe(education);
	query_exe(society);
	query_exe(computer);
	query_exe(entertain);
	query_exe(media);
	query_exe(living);
	query_exe(culture);
	query_exe(tour);
	query_exe(religion);
	query_exe(game);
	query_exe(sports);
	query_exe(economy);
	query_exe(p2p);
	query_exe(organization);
	query_exe(internet);
	query_exe(international);
	query_exe(politics);
	query_exe(etc);
	
	query_exe(CREATE_IP);
	query_exe(CREATE_KEYWORD);
	query_exe(CREATE_URL);
		
	
	
	printf("Are you sure that catagory files in [dir]\"new_db\"? [Enter]");
	getch();
	
	printf("Insert database catagory? [Enter]");
	getch();
	
	insert_catagory("shop", 1);
	insert_catagory("adult", 2);
	insert_catagory("education", 3);
	insert_catagory("society", 4);
	insert_catagory("computer", 5);
	insert_catagory("entertain", 6);
	insert_catagory("media", 7);
	insert_catagory("living", 8);
	insert_catagory("culture", 9);
	insert_catagory("tour", 10);
	insert_catagory("religion", 11);
	insert_catagory("game", 12);
	insert_catagory("sports", 13);
	insert_catagory("economy", 14);
	insert_catagory("p2p", 15);
	insert_catagory("organization", 16);
	insert_catagory("internet", 17);
	insert_catagory("international", 18);
	insert_catagory("politics", 19);
	insert_catagory("etc", 20);
	
	
	
}


void insert_catagory(char *file, int num)
{
	
	char path[64];
	FILE *fp;
	char content[256], query[256];
	
	sprintf(path, "new_db/%s", file);	
	
	fp = fopen(path, "r");
	if(!fp){
		printf("can not open : %s", path);
		exit(1);
	}
	
	while(fgets(content, sizeof(content), fp)){
		content[strlen(content)-2] = '\0';
		sprintf(query, "insert into policy.url values('', 1, %d, '%s')",num, content);
	}
	fclose(fp);
	
}


void query_exe(char *qy)
{
	char  query[256];
	
	query_stat = mysql_real_query(connection, qy, strlen(qy));	
	if( query_invalied(conn, query_stat) ){
		printf("ERROR: %s",qy);
		exit(1);
	}
	puts(qy);
}


int delete_agent_policy()