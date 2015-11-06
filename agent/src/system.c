/*
* @ file : system.c system.h
*	brief : 
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "../include/system.h"

#define KERNERL_2_6
//#define KERNERL_2_4

#define BUFSIZE	256

#define DISK_CMD	"df -h"
#define MEM_CMD	"cat /proc/meminfo"
#define CPU_CMD	"cat /proc/stat"

#define keyword	"cpu"
#define keyword1	"MemTotal"
#define keyword2	"MemFree"

char buf[BUFSIZE];
char garbage[48];






/* get_mem
*/
char total[12], freed[12];
unsigned long tot, freem;


/* get_cpu
*/
double n_total, n_id;
double p_total, p_id;


#ifdef KERNEL_2_4
char tok[5][12];

#else	//KERNERL_2_6
char tok[8][12];
#endif




/***************************
 *  ��ũ ���� ���       *
 * MDD ȯ�濡 �°� �����  *
 *!!!!!!!!!!!!!!!!!!!!!!!!!*
 * ��Ƽ�� 2�� ���� ��°���*
 *!!!!!!!!!!!!!!!!!!!!!!!!!*
 ***************************/
void get_disk(){

	FILE *fp;
	int i=0;
	char tmp[8];
	
	fp = popen(DISK_CMD, "r");
	if(!fp){
					puts("can not found "DISK_CMD);
					exit(1);
	}
	
	fgets(buf, BUFSIZE-1, fp);
	
	for(i=0; i<2; i++){
		fgets(buf, BUFSIZE-1, fp);
		sscanf(buf,"%s %s %s %s %s %s", garbage, garbage, garbage, garbage, System.disk_used[i], System.disk_mount[i]);
		if(i==0)
			strcpy(tmp, System.disk_mount[i]);
				
		if(!System.disk_mount[i]){
			strcpy(System.disk_used[i], "null");
		}
		//puts(System.disk_used[1]);
		
		System.disk_used[i][strlen(System.disk_used[i])-1] = 0;
	}
	strcpy(System.disk_mount[0], tmp);
	pclose(fp);
}



/*********************
 * �޸� ���� ��� *
 *********************/
void get_mem(){

	FILE *fp;
	fp = popen(MEM_CMD, "r");
	if(!fp){
					puts("can not found "MEM_CMD);
					exit(1);
	}
					
	while(fgets(buf, BUFSIZE-1, fp)){
		
		//MemTotal
		if(strstr(buf, keyword1)){
			sscanf(buf,"%s %s", garbage, total);
		}
		
		//MemFree		
		if(strstr(buf, keyword2)){
			sscanf(buf,"%s %s", garbage, freed);
			break;
		}
	}
	pclose(fp);
	tot = atoi(total);
	freem = atoi(freed);
	
	System.mem_stat = ( (tot - freem) * 100  / tot );	
}





/*********************
 *���μ��� ���� ��� *
 *********************/
#ifdef KERNEL_2_4
void get_cpu(int interval){

	FILE *fp;
	
	// first cycle routine
	fp = popen(CPU_CMD, "r");
	if(!fp){
					puts("can not found "CPU_CMD);
					exit(1);
	}
					
	while(fgets(buf, BUFSIZE-1, fp)){
					if(strstr(buf, keyword)){									
							sscanf(buf,"%s %s %s %s %s", tok[0], tok[1], tok[2], tok[3], tok[4]);
							break;
					}
	}
	
	
	p_total = atoi(tok[0])+atoi(tok[1])+atoi(tok[2])+atoi(tok[3])+atoi(tok[4]);
	p_id = atoi(tok[4]);
	
	pclose(fp);
	
	sleep(interval);
	
	
	// second cycle routine	
	fp = popen(CPU_CMD, "r");
	if(!fp){
					puts("can not found "CPU_CMD);
					exit(1);
	}	
	
	while(fgets(buf, BUFSIZE-1, fp)){
					if(strstr(buf, keyword)){									
							sscanf(buf,"%s %s %s %s %s", tok[0], tok[1], tok[2], tok[3], tok[4]);
							break;
					}
	}
	

	n_total = atoi(tok[0])+atoi(tok[1])+atoi(tok[2])+atoi(tok[3])+atoi(tok[4]);
	n_id = atoi(tok[4]);
	
	
	System.cpu_stat  = ( 1 - ( (n_id - p_id) / (n_total - p_total)) )* 100;
	
	pclose(fp);	
	
}

#else	//KERNERL_2_6
void get_cpu(int interval){

	FILE *fp;
	
	// first cycle routine
	fp = popen(CPU_CMD, "r");
	if(!fp){
					puts("can not found "CPU_CMD);
					exit(1);
	}
					
	while(fgets(buf, BUFSIZE-1, fp)){
					if(strstr(buf, keyword)){
						sscanf(buf,"%s %s %s %s %s %s %s %s", tok[0], tok[1], tok[2], tok[3], tok[4], tok[5], tok[6], tok[7]);
						break;
					}
	}
		
	p_total = atoi(tok[0])+atoi(tok[1])+atoi(tok[2])+atoi(tok[3])+atoi(tok[4])+atoi(tok[5])+atoi(tok[6])+atoi(tok[7]);
	p_id = atoi(tok[4]);
	
	pclose(fp);
	
		
	sleep(interval);
	
	
	
	// second cycle routine	
	fp = popen(CPU_CMD, "r");
	if(!fp){
					puts("can not found "CPU_CMD);
					exit(1);
	}	
	
	while(fgets(buf, BUFSIZE-1, fp)){
					if(strstr(buf, keyword)){						
							sscanf(buf,"%s %s %s %s %s %s %s %s", tok[0], tok[1], tok[2], tok[3], tok[4], tok[5], tok[6], tok[7]);
							break;
					}
	}
	

	n_total = atoi(tok[0])+atoi(tok[1])+atoi(tok[2])+atoi(tok[3])+atoi(tok[4])+atoi(tok[5])+atoi(tok[6])+atoi(tok[7]);
	n_id = atoi(tok[4]);
	
	
	System.cpu_stat = ( 1 - ( (n_id - p_id) / (n_total - p_total)) )* 100;
	pclose(fp);
	
}
#endif


/* debug */
/*
main(){
	printf("%d\n", get_mem());
	printf("%d\n", get_cpu(3));
	
	get_disk();
	puts(disk_mount[0]);
	puts(disk_used[0]);
	
	puts(disk_mount[1]);
	puts(disk_used[1]);
	
	puts(disk_mount[2]);
	puts(disk_used[2]);
		
}
*/




void system_moniter(int interval){	
	
	get_mem();
	
	get_disk();
	
	get_cpu( interval );	
	
}


