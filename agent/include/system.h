/*
* @ file : system.h
*	brief : 
*/



struct system_monitor{
	
	char disk_used[2][3];
	char disk_mount[2][8];
	
	char mem_stat;
	
	char cpu_stat;	
};

struct system_monitor System;


