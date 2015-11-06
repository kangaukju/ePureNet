/*
* @ file : time.h
*	brief : 
*/

#include <time.h>




// Is this year  Leap year ?

#define isLeapYear(x)	(\
				(\
					( (x) % 4 == 0 ) && \
					( (x) % 100 != 0 ) \
				)|| \
				( (x) % 400 == 0 ) \
			)




typedef struct time_zone{
	
	time_t t;
	struct tm *tm;
	struct tm *pre_tm;
	
	// current time
	u_short	year, mon, mday;
	u_short wday;
	u_short hour, min, sec;	
	
	// 1hour ago
	u_short	pre_year, pre_mon, pre_mday;	
	u_short pre_hour;
	
}TIME_ZONE;


/*
*/
TIME_ZONE tz;
/*
*/


void get_localtime(void);


void get_localtime(void){
	
	time(&tz.t);
	tz.tm = localtime(&tz.t);	
	
	tz.year = tz.tm->tm_year + 1900;	// 2008, 2009....
	tz.mon = tz.tm->tm_mon;						//[0, 11]
	tz.mday = tz.tm->tm_mday;					//[1,31]
	
	tz.wday = tz.tm->tm_wday;					//[0,6]
	
	tz.hour = tz.tm->tm_hour;					//[0,23]
	tz.min = tz.tm->tm_min;						//[0,59]
	tz.sec = tz.tm->tm_sec;						//[0,59]
	
	tz.t -= 60*60;
	tz.tm = localtime(&tz.t);
	
	tz.pre_year = tz.tm->tm_year + 1900;	// 2008, 2009....
	tz.pre_mon = tz.tm->tm_mon;						//[0, 11]
	tz.pre_mday = tz.tm->tm_mday;					//[1,31]
	
	tz.pre_hour = tz.tm->tm_hour;					//[0,23]
	
	
	//another source
	/*
	
	if(tz.hour ==0 ){		
		tz.pre_hour = 23;
		
		if(tz.mday == 1){
			
			if(tz.mon == 0){
				tz.pre_year = tz.year -1;
				tz.pre_mon = 11;
				tz.pre_mday = 31;
			}
			else if(tz.mon == 2){				
				tz.pre_year = tz.year;
				tz.pre_mon = 1;
				
				if(isLeapYear(tz.year)){
					tz.pre_mday = 29;
				}else{
					tz.pre_mday = 28;
				}				
			}
			else{
				tz.pre_year = tz.year;
				tz.pre_mon 	= tz.mon;
				tz.pre_mday	= tz.mday;				
			}
		
			
		}
		else{
			tz.pre_mday = tz.mday -1;
		}
	}	
	
	else{	
		tz.pre_year = tz.year;
		tz.pre_mon  = tz.mon;
		tz.pre_mday	= tz.mday;
		tz.pre_hour = tz.hour - 1;	
	}
	*/
}

