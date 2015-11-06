/*
* @ file : hash.c hash.h
*	brief : 
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../include/hash.h"


unsigned long hash(unsigned char *str);
int add_hashtable(char *p, unsigned long no, struct deny_link *table);
int add_ip_hashtable(unsigned long p, unsigned long no, struct ip_link *table);
int add_url_netobj(unsigned long p, unsigned long no, struct url_obj *table);
int add_ip_netobj(unsigned long p, unsigned long no, struct ip_obj *table);
int add_keyword_netobj(unsigned long p, unsigned long no, struct keyword_obj *table);
int add_keyword_base_hash(unsigned long no, struct keyword_base *table);
int add_ip_base_hash(unsigned long no, struct ip_base *table);
int add_url_base_hash(unsigned long no, struct url_base *table);


int free_hashtable(struct deny_link *table);
int free_ip_hashtable(struct ip_link *table);
int free_keyword_table(struct keyword_link *table, int size);
int free_ip_obj(struct ip_obj *table);
int free_keyword_obj(struct keyword_obj *table);
int free_url_obj(struct url_obj *table);
int free_base_obj(struct url_base *url_t, struct ip_base *ip_t, struct keyword_base *keyword_t);
int free_ip_obj(struct ip_obj *table);
int free_keyword_obj(struct keyword_obj *table);
int free_url_obj(struct url_obj *table);


void create_url_hash_table(char * filename); 
void create_ip_hash_table(char * filename);
void create_keyword_table(char * filename);
void create_ip_obj_table(char * filename);
void create_keyword_obj_table(char * filename);
void create_url_obj_table(char * filename);
void create_base_obj(char * f1, char * f2, char * f3);


unsigned long find_url(char *s, struct deny_link * table);
unsigned long find_ip(unsigned long s, struct ip_link * table);
int find_url_obj(unsigned long p, unsigned long no, struct url_obj *table);
int find_ip_obj(unsigned long p, unsigned long no, struct ip_obj *table);
int find_keyword_obj(unsigned long p, unsigned long no, struct keyword_obj *table);
int find_keyword_base(unsigned long n, struct keyword_base * table);
int find_ip_base(unsigned long n, struct ip_base * table);
int find_url_base(unsigned long n, struct url_base * table);

unsigned long _atoi(char *s);




unsigned long _atoi(char *s);

////////////////////////////////////////////////////////
//@ make hash value
//////////////////////////////////////////////////////// 
unsigned long hash(unsigned char *str)
{
        unsigned long hash = HASH;
        int c;

        while (c = *str++)
            hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

        return hash;
}


////////////////////////////////////////////////////////
// * @ insert hash value into hashtable (ver. url(type char *), url)
////////////////////////////////////////////////////////
int add_hashtable(char *p, unsigned long no, struct deny_link *table)
{
	int key;
	struct deny_link * news, * cur;

	key = hash(p) % LEN;	//해쉬
	cur = &table[key];
	
	if(table[key].target == NULL){
		table[key].target = (char *)malloc(strlen(p)+1);
		strcpy(table[key].target, p);
		table[key].no = no;
		table[key].next = NULL;		
	}
	else{
		while(cur->next)
			cur = cur->next;		

		news  = (struct deny_link *)malloc(sizeof(struct deny_link));
		news->target = (char *)malloc(strlen(p)+1);
		strcpy( news->target, p);
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;
	
}


////////////////////////////////////////////////////////
// * @ clean memory hashtable(url hashtable)
//////////////////////////////////////////////////////// 
int free_hashtable(struct deny_link *table)
{
	
	struct deny_link * cur, * tmp;
	int i;
	
	for(i=0; i<LEN; i++)
	{
		cur = &table[i];
		
		cur->target = NULL;
		
		cur = cur->next;
		
		while(cur){
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
}




////////////////////////////////////////////////////////
//* @ insert hash value into hashtable (ver. ip(type unsigned long))
//////////////////////////////////////////////////////// 
int add_ip_hashtable(unsigned long p, unsigned long no, struct ip_link *table)
{
	int key;
	struct ip_link * news, * cur;	

	key = p % LEN;
	cur = &table[key];

	if(table[key].target == NON_VALUE){	//NON_VALUE : -1		
		table[key].target = p;
		table[key].no = no;
		table[key].next = NULL;		
	}
	else{		
		while(cur->next)			
			cur = cur->next;		
		
		news  = (struct ip_link *)malloc(sizeof(struct ip_link));
		news->target = p;
		news->no = no;
		news->next = NULL;
		cur->next =  news;
	}
	return 0;
}


////////////////////////////////////////////////////////
// * @ clean memory hashtable(ip hashtable)
////////////////////////////////////////////////////////
int free_ip_hashtable(struct ip_link *table)
{
	
	struct ip_link * cur, * tmp;
	int i;
	
	for(i=0; i<LEN; i++)
	{
		cur = &table[i];
		
		cur->target = -1;
		
		cur = cur->next;
		
		while(cur){
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
}



////////////////////////////////////////////////////////
// * @ compare input value with hash table
////////////////////////////////////////////////////////
unsigned long find_url(char *s, struct deny_link * table)
{
	int key;
	struct deny_link * cur;
	key = hash(s) % LEN;

	cur = &table[key];
	
	if(cur->target == NULL)
		return 0;
	
	while(cur){		
		if(strcmp(cur->target, s) == 0){			
			return cur->no;
		}
		cur = cur->next;
	}
	return 0;
}



////////////////////////////////////////////////////////
//* @ compare input value with hash table
////////////////////////////////////////////////////////

unsigned long find_ip(unsigned long s, struct ip_link * table)
{
	unsigned long key;
	struct ip_link * cur;
	key = s % LEN;

	cur = &table[key];
	
	
	if(cur->target == NON_VALUE)
		return 0;
	
	while(cur){
		
		if(cur->target == s){
			return cur->no;
		}
		cur = cur->next;
	}
	return 0;
}



////////////////////////////////////////////////////////
// * @ create hash tables
////////////////////////////////////////////////////////
void create_url_hash_table(char * filename)
{
	FILE *fd;
	char val[300];
	char url[256];
	char no[33];
	unsigned long n;
		
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_url_hash_table()\n", fd);
    	exit(1);
  }
	
	free_hashtable(url_table);	
	
	while(fgets(val, sizeof(val), fd)){		
		
		if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n") )
		{
			
			sscanf(val, "%s	%s", no, url);			
			n = _atoi(no);
			
			add_hashtable(url, n, url_table);
		}
	}	

	fclose(fd);
	
}


////////////////////////////////////////////////////////
// * @ create hash tables
//////////////////////////////////////////////////////// 
void create_ip_hash_table(char * filename)
{	
	FILE *fd;
	char val[300], ip[33], no[33];
	unsigned long conv_addr, n;
		
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_ip_hash_table()\n", fd);
    	exit(1);
  }
  
  //초기화
  free_ip_hashtable(ip_table);
	
	
	while(fgets(val, sizeof(val), fd)){
		
		if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n") )
		{
			sscanf(val, "%s	%s", no, ip);			
			n = _atoi(no);
						
			conv_addr = inet_addr(ip);
			
			add_ip_hashtable(conv_addr, n, ip_table);
		}
	}
	fclose(fd);
}


////////////////////////////////////////////////////////
// * @ create keyword table
// * MAXKEYWORD 5000
//////////////////////////////////////////////////////// 
void create_keyword_table(char * filename)
{
	
	FILE *fd;	
	char val[300];
	char keyword[30], no[33];
	unsigned long n;
	int i=0;
	
	free_keyword_table(keyword_table, sizeof(keyword_table));	
	
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_keyword_table()\n", fd);
    	exit(1);
  }
  
  while(fgets(val, sizeof(val), fd)){
  	
  	if(i >= MAXKEYWORD )
		{
			puts("[MAXKEYWORD] 5000");
			break;
  	}  		
  	
  	else if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n"))
  	{
  		sscanf(val, "%s	%s", no, keyword);
  		
			n = _atoi(no);			
			  		
  		keyword_table[i].no = n;
  		
  		//////////////////////////////////////////
  		strcpy(keyword_table[i++].keyword, keyword);  		
  	}  	
  }  
  fclose(fd);
	
	
}


////////////////////////////////////////////////////////
//* @ clean memory keyword
////////////////////////////////////////////////////////
int free_keyword_table(struct keyword_link *table, int size)
{	
	memset(table, 0, size);	
}



//////////////////////////////////////////////////////////////////////////////
//ok														ip									no								url_obj
//////////////////////////////////////////////////////////////////////////////
int add_url_netobj(unsigned long p, unsigned long no, struct url_obj *table)
{
	
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
	
	struct url_obj * news, * cur;
	
	cur = &table[key];
	
	if(table[key].no == 0){		
		table[key].no = no;		
		table[key].next = NULL;
	}
	else{
		
		while(cur->next)
			cur = cur->next;
		
		news = (struct url_obj *)malloc(sizeof(struct url_obj));
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;	
}


//////////////////////////////////////////////////////////////////////////////
//ok														ip									no								url_obj
//////////////////////////////////////////////////////////////////////////////
int add_ip_netobj(unsigned long p, unsigned long no, struct ip_obj *table)
{
	
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
	
	struct ip_obj * news, * cur;
	
	cur = &table[key];

	if(table[key].no == 0){
		table[key].no = no;		
		table[key].next = NULL;		
	}
	else{
		while(cur->next)
			cur = cur->next;
		
		news = (struct ip_obj *)malloc(sizeof(struct ip_obj));
		news->no = no;
		news->next = NULL;
		cur->next =  news;
	}
	return 0;	
}


//////////////////////////////////////////////////////////////////////////////
//ok														ip									no								url_obj
//////////////////////////////////////////////////////////////////////////////
int add_keyword_netobj(unsigned long p, unsigned long no, struct keyword_obj *table)
{
	
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
	
	struct keyword_obj * news, * cur;
	
	cur = &table[key];

	if(table[key].no == 0){
		table[key].no = no;		
		table[key].next = NULL;			
	}
	else{
		while(cur->next)
			cur = cur->next;		
		
		news = (struct keyword_obj *)malloc(sizeof(struct keyword_obj));
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;	
}






//////////////////////////////////////////////////////////////////////////////
// * @ 
//////////////////////////////////////////////////////////////////////////////
int find_url_obj(unsigned long p, unsigned long no, struct url_obj *table)
{
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
	
	struct url_obj * news, * cur;
	
	cur = &table[key];
	
	if(cur->no == 0)
		return -1;
	
	while(cur){
		
		if( cur->no == no ){
			return 0;
		}
		cur = cur->next;
	}
	return -1;
}



//////////////////////////////////////////////////////////////////////////////
// * @ 
//////////////////////////////////////////////////////////////////////////////
int find_ip_obj(unsigned long p, unsigned long no, struct ip_obj *table)
{
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
	
	struct ip_obj * news, * cur;
	
	cur = &table[key];
	
	if(cur->no == 0)
		return -1;
	
	while(cur){
		if( cur->no == no ){
			return 0;
		}
		cur = cur->next;
	}
	return -1;
}


//////////////////////////////////////////////////////////////////////////////
// * @ 
//////////////////////////////////////////////////////////////////////////////
int find_keyword_obj(unsigned long p, unsigned long no, struct keyword_obj *table)
{
	unsigned char *index = (unsigned char *)&p;
	unsigned char key;
	
	key = *(index+3);
		
	if(key == 0){
		return 0;
	}
	
	struct keyword_obj * news, * cur;
	
	cur = &table[key];
	
	
	if(cur->no == 0)
		return -1;
	
	while(cur){
		
		if( cur->no == no ){
			return 0;
		}
		cur = cur->next;
	}
	return -1;
}


//////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////
void create_url_obj_table(char * filename)
{
	FILE *fd;
	char val[33];
	char url[33], no[33];
	unsigned long n, conv_addr;
		
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_url_obj_table\n", fd);
    	exit(1);
  }
	
	free_url_obj(url_netobj);
	
	while(fgets(val, sizeof(val), fd)){		
		
		if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n"))
		{
			sscanf(val, "%s	%s", no, url);			
			n = _atoi(no);
			
			conv_addr = inet_addr(url);
			
			add_url_netobj(conv_addr, n, url_netobj);
		}
	}
	
	puts("add_url_netobj(conv_addr, n, url_netobj)");
	fclose(fd);
	
}


//////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////
void create_keyword_obj_table(char * filename)
{
	FILE *fd;
	char val[33];
	char keyword[33], no[33];
	unsigned long n, conv_addr;
		
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_keyword_obj_table()\n", fd);
    	exit(1);
  }
	
	free_keyword_obj(keyword_netobj);
	
	while(fgets(val, sizeof(val), fd)){		
		
		if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n"))
		{
			sscanf(val, "%s	%s", no, keyword);			
			n = _atoi(no);
			conv_addr = inet_addr(keyword);
			
			add_keyword_netobj(conv_addr, n, keyword_netobj);
		}
	}
	fclose(fd);	
}


//////////////////////////////////////////////////////////////////////////////
//
//////////////////////////////////////////////////////////////////////////////
void create_ip_obj_table(char * filename)
{
	FILE *fd;
	char val[33];
	char ip[33], no[33];
	unsigned long n, conv_addr;
		
	if((fd = fopen(filename, "r")) == NULL){
    	printf("File open error(%d) : create_ip_obj_table()\n", fd);
    	exit(1);
  }
	
	free_ip_obj(ip_netobj);
	
	while(fgets(val, sizeof(val), fd)){		
		
		if(val != NULL && strcmp(val, "\r\n") && strcmp(val, "\n"))
		{
			sscanf(val, "%s	%s", no, ip);			
			n = _atoi(no);
			conv_addr = inet_addr(ip);
			
			add_ip_netobj(conv_addr, n, ip_netobj);
		}
	}

	fclose(fd);
	
}


////////////////////////////////////////////////////////
// * @ free_url_obj(struct url_obj *table)
////////////////////////////////////////////////////////
int free_url_obj(struct url_obj *table)
{
	
	struct url_obj * cur, * tmp;
	int i;
	
	for(i=0; i<OBJ_SIZE; i++)
	{
		cur = &table[i];
		
		cur->no = 0;
		
		cur = cur->next;
		
		while(cur){
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
}


////////////////////////////////////////////////////////
// * @ free_keyword_obj(struct url_obj *table)
////////////////////////////////////////////////////////
int free_keyword_obj(struct keyword_obj *table)
{
	
	struct keyword_obj * cur, * tmp;
	int i;
	
	for(i=0; i<OBJ_SIZE; i++)
	{
		cur = &table[i];
		
		cur->no = 0;
		
		cur = cur->next;
		
		while(cur){
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
}

////////////////////////////////////////////////////////
// * @ free_ip_obj(struct ip_obj *table)
////////////////////////////////////////////////////////
int free_ip_obj(struct ip_obj *table)
{
	
	struct ip_obj * cur, * tmp;
	int i;
	
	for(i=0; i<OBJ_SIZE; i++)
	{
		cur = &table[i];
		
		cur->no = 0;
		
		cur = cur->next;
		
		while(cur){
			tmp = cur->next;
			free(cur);
			cur = tmp;
		}
	}
}

////////////////////////////////////////////////////////
// * @ string To unsigned long
////////////////////////////////////////////////////////
unsigned long _atoi(char *s)
{
        int len = strlen(s);
        int i;
        unsigned long ret=0;

        for(i=0; i<len; i++){
                ret = 10 * ret + (s[i] - '0');
        }
        
        return ret;
}






//////////////////////////////////////////////////////////////////////////////
// create_base_obj - url_base, ip_base, keyword_base
//////////////////////////////////////////////////////////////////////////////
void create_base_obj(char * f1, char * f2, char * f3)
{	
	char no[33];
	unsigned long n;
	
	FILE * url, * ip, * keyword;
	
	if((url = fopen(f1, "r")) == NULL){
    	printf("File open error(%d) : create_base_obj_url\n", url);
    	exit(1);
  }
  if((ip = fopen(f2, "r")) == NULL){
    	printf("File open error(%d) : create_base_obj_ip\n", ip);
    	exit(1);
  }
  if((keyword = fopen(f3, "r")) == NULL){
    	printf("File open error(%d) : create_base_obj_keyword\n", ip);
    	exit(1);
  }
  
  
  free_base_obj(url_baseobj, ip_baseobj, keyword_baseobj);
  
  
  
  while(fgets(no, sizeof(no), url)){
		
		if(no != NULL && strcmp(no, "\n") && strcmp(no, "\r\n"))
		{
			no[strlen(no) - 1 ] = '\0';
			n = _atoi(no);
			//////////////////////////////////
			add_url_base_hash(n, url_baseobj);
		}
	}
	
	while(fgets(no, sizeof(no), ip)){
		
		if(no != NULL && strcmp(no, "\n") && strcmp(no, "\r\n"))
		{
			no[strlen(no) - 1 ] = '\0';
			n = _atoi(no);
			//////////////////////////////////
			add_ip_base_hash(n, ip_baseobj);			
		}
	}
	
	while(fgets(no, sizeof(no), keyword)){
		
		if(no != NULL && strcmp(no, "\n") && strcmp(no, "\r\n"))
		{
			no[strlen(no) - 1 ] = '\0';
			n = _atoi(no);
			//////////////////////////////////
			add_keyword_base_hash(n, keyword_baseobj);			
		}
	}
  fclose(ip);
  fclose(url);
  fclose(keyword);
  
}


//////////////////////////////////////////////////////////////////////////////
// 
//////////////////////////////////////////////////////////////////////////////
int add_url_base_hash(unsigned long no, struct url_base *table)
{
	int key;
	struct url_base * news, * cur;

	key = no % LEN;	//해쉬
	cur = &table[key];
	
	if(table[key].no == 0){		
		table[key].no = no;
		table[key].next = NULL;		
	}
	else{
		while(cur->next)
			cur = cur->next;

		news  = (struct url_base *)malloc(sizeof(struct url_base));
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;
	
}

//////////////////////////////////////////////////////////////////////////////
// 
//////////////////////////////////////////////////////////////////////////////
int add_ip_base_hash(unsigned long no, struct ip_base *table)
{
	int key;
	struct ip_base * news, * cur;

	key = no % LEN;	//해쉬
	cur = &table[key];
	
	if(table[key].no == 0){		
		table[key].no = no;
		table[key].next = NULL;		
	}
	else{
		while(cur->next)
			cur = cur->next;

		news  = (struct ip_base *)malloc(sizeof(struct ip_base));
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;
	
}

//////////////////////////////////////////////////////////////////////////////
// 
//////////////////////////////////////////////////////////////////////////////
int add_keyword_base_hash(unsigned long no, struct keyword_base *table)
{
	int key;
	struct keyword_base * news, * cur;

	key = no % LEN;	//해쉬
	cur = &table[key];
	
	if(table[key].no == 0){		
		table[key].no = no;
		table[key].next = NULL;		
	}
	else{
		while(cur->next)
			cur = cur->next;

		news  = (struct keyword_base *)malloc(sizeof(struct keyword_base));
		news->no = no;
		news->next = NULL;
		cur->next =  news;		
	}
	return 0;	
}

//////////////////////////////////////////////////////////////////////////////
// create_base_obj - url_base, ip_base, keyword_base
//////////////////////////////////////////////////////////////////////////////
int free_base_obj
(struct url_base *url_t, struct ip_base *ip_t, struct keyword_base *keyword_t)
{
	struct url_base 		*url_c, 		*url_tmp;
	struct ip_base 			*ip_c	,			*ip_tmp;
	struct keyword_base *keyword_c,	*keyword_tmp;
		
	int i;
	
	for(i=0; i<OBJ_SIZE; i++)
	{
		
		url_c			= &url_t[i];
		ip_c			= &ip_t[i];
		keyword_c = &keyword_t[i];
		
		url_c->no = 0;
		ip_c->no = 0;
		keyword_c->no = 0;
		
		url_c = url_c->next;		
		while(url_c){
			url_t = url_c->next;
			free(url_c);
			url_c = url_t;
		}
		
		ip_c = ip_c->next;		
		while(ip_c){
			ip_t = ip_c->next;
			free(ip_c);
			ip_c = ip_t;
		}
		
		keyword_c = keyword_c->next;		
		while(ip_c){
			keyword_t = keyword_c->next;
			free(keyword_c);
			keyword_c = keyword_t;
		}
	}
	return 0;
}

int find_url_base(unsigned long n, struct url_base * table)
{
	int key;
	struct url_base * cur;
	key = n % LEN;
	
	cur = &table[key];
	
	if(cur->no == 0)
		return -1;
	
	while(cur){
		if( cur->no == n){			
			return 0;
		}
		cur = cur->next;
	}
	return -1;
	
}

int find_ip_base(unsigned long n, struct ip_base * table)
{
	int key;
	struct ip_base * cur;
	key = n % LEN;
	
	cur = &table[key];
	
	if(cur->no == 0)
		return -1;
	
	while(cur){		
		if( cur->no == n){			
			return 0;
		}
		cur = cur->next;
	}
	return -1;
	
}


int find_keyword_base(unsigned long n, struct keyword_base * table)
{
	int key;
	struct keyword_base * cur;
	key = n % LEN;
	
	cur = &table[key];
	
	if(cur->no == 0)
		return -1;
	
	while(cur){		
		if( cur->no == n){			
			return 0;
		}
		cur = cur->next;
	}
	return -1;
	
}



