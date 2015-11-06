#include <mysql.h>

/*
* @ file : db.h
*	brief : 
*/

/*
@database

agent_information
|
|_ master
|
|_ status


policy
|
|_ base_config
|
|_ base_rule
|
|_ agent_config
|
|_ agent1_rule... agent2_rule....


statics
|
|_ agent1 ... agent2....
*/





#define LOCALHOST "localhost"
#define HOST			"127.0.0.1"
#define USER			"root"
//#define PASSWORD 	"1234"




/*
* @ information database
*/

#define AGENT_INFORMATION "information"
#define AGENT_INFORMATION_MASTER	AGENT_INFORMATION".member"
#define AGENT_INFORMATION_STATUS	AGENT_INFORMATION".status"
#define CREATE_INFORMATION "create database "AGENT_INFORMATION

#define CREATE_INFORMATION_MEMBER " ( \
`ip` varchar(15) NOT NULL default '', \
`name` varchar(24) NOT NULL default '', \
`local` varchar(24) default NULL, \
`admin_name` varchar(24) default NULL, \
`admin_email` varchar(24) default NULL, \
`admin_phone` varchar(24) default NULL, \
`pass` varchar(50) NOT NULL default '', \
PRIMARY KEY  (`ip`) \
) ENGINE=MyISAM"

#define CREATE_INFORMATION_STATUS " ( \
`id` varchar(9) NOT NULL default '', \
`name` varchar(32) default NULL, \
`aliase` varchar(32) default NULL, \
`cpu` tinyint(4) NOT NULL default '0', \
`mem` tinyint(4) NOT NULL default '0', \
`disk1_name` varchar(8) default NULL, \
`disk1` tinyint(4) default NULL, \
`disk2_name` varchar(8) default NULL, \
`disk2` tinyint(4) default NULL, \
`save_time` tinyint(4) NOT NULL default '0', \
`backup_time` tinyint(4) NOT NULL default '0', \
`alive` tinyint(1) unsigned default NULL, \
`admin_name` varchar(32) default NULL, \
`admin_email` varchar(45) default NULL, \
`admin_phone` varchar(18) default NULL \
) ENGINE=MyISAM"




/*
* @ statics database
*/

#define STATICS "statics"
#define STATICS_AGENT STATICS".agent"

#define DB_STATICS "create database "STATICS

#define CREATE_STATICS " ( \
`date` char(10) NOT NULL default '', \
`time` char(2) NOT NULL default '', \
`tbyte` int unsigned NOT NULL default '0', \
`gbyte` int unsigned NOT NULL default '0', \
`mbyte` int unsigned NOT NULL default '0', \
`kbyte` int unsigned NOT NULL default '0', \
`byte` int unsigned NOT NULL default '0' \
) ENGINE=MyISAM"


#define POLICY	"policy"
#define POLICY_url			POLICY".url"
#define POLICY_ip				POLICY".ip"
#define POLICY_keyword	POLICY".keyword"
#define POLICY_agent		POLICY".agent"



/*
* @ agent database
*/


#define AGENT "agent"

#define LIVE "live"

#define CREATE_AGENT "(\
`src_ip` char(15) NOT NULL default '', \
`src_port` char(5) NOT NULL default '', \
`dest_ip` char(15) NOT NULL default '',	\
`dest_port` char(5) NOT NULL default '', \
`url` varchar(128) default NULL, \
`date` char(10) NOT NULL default '', \
`time` char(8) NOT NULL default '' \
) ENGINE=MyISAM"


#define CREATE_LIVE "(\
`src_ip` char(15) NOT NULL default '', \
`src_port` char(5) NOT NULL default '', \
`dest_ip` char(15) NOT NULL default '',	\
`dest_port` char(5) NOT NULL default '', \
`url` varchar(128) default NULL, \
`size` char(32) default NULL, \
`date` char(10) NOT NULL default '', \
`time` char(8) NOT NULL default '' \
) ENGINE=MyISAM"
	
MYSQL       *alive_connection=NULL, alive_conn;
MYSQL       *log_connection=NULL, log_conn;
MYSQL       *live_connection=NULL, live_conn;

	
int query_invalied(MYSQL con, int query_stat);
int mysql_log_connection(char *host, char *user, char *password);
int mysql_alive_connection(char *host, char *user, char *password);



int query_invalied(MYSQL con, int query_stat)
{

	if (query_stat != 0){
		printf("%s\n", mysql_error(&con));
		return -1;
	}
	return 0;
}




int mysql_log_connection(char *host, char *user, char *password)
{		
	mysql_init(&log_conn);	
	log_connection = mysql_real_connect(&log_conn, host, user, password, NULL, 0, (char *)NULL, 0);	
	if (log_connection == NULL){			
			return -1;
	}	
	return 0;
}


int mysql_alive_connection(char *host, char *user, char *password)
{		
	mysql_init(&alive_conn);	
	alive_connection = mysql_real_connect(&alive_conn, host, user, password, NULL, 0, (char *)NULL, 0);	
	if (alive_connection == NULL){			
			return -1;
	}	
	return 0;
}



