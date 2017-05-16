/*
 * DNS SLA Checker 
 *
 * Usage: ./DNSChecker <ip> <port>
 * Terminates with an exit code of 0: Operating normally
 * Terminates with an exit code of 1: Operating abnormally
 * Terminates with an exit code of 2: Cannot establish a connection to the target address
 * */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;


//check IP dotted formatting.  
//return 0: valid IP
//return 1; invalid IP
int validIPCheck(const char* ip)
{  
    int splitedIP[4];
    int len = strlen(ip);
    char tail[16];
    int c, i; 
    tail[0] = 0;
    
    if(len < 7 || len > 15)
        return 1;
    
    c = sscanf(ip, "%3u.%3u.%3u.%3u%s", &splitedIP[0], &splitedIP[1], &splitedIP[2], &splitedIP[3], tail);
    
    if(c != 4 || tail[0])
        return 1;
    
    for(i = 0 ; i < 4; i ++)
        if(splitedIP[i] > 255)
            return 1;
    
    return 0;
}

int main(int argc, char** argv)
{
    FILE *expect = NULL;
    unsigned short port = 0;
    char *endp;
    int returnVal = 0;
    int socket;

    if(argc != 3)
    {
        printf("Usage: ./DNSChecker <ip> <port>\n");
	exit(2);
    }

    expect = fopen("expect.csv", "r");

    if(expect == NULL)
    {
        printf("Error: No \'expect.csv\' file\n");
	exit(2);
    }

    //convert string to unsigned short value 
    port = (unsigned short)strtoul(argv[2], &endp, 0);
    if(endp == argv[2])
    {
         printf("Error: Can't convert the port string to unsigned short value\n");
	 exit(2);
    }
     
    //check the invalid IP address formatting
    returnVal = validIPCheck(argv[1]);
    if(returnVal == 1)
    {
        printf("Error: Invalid IP address fromatting\n");
	exit(2);
    }

    //socket = openUDPSocket(argv[1], port);  
    if(socket < 0)
        exit(2);

    //Now get the ip of hostname, A record
    sendDNS(hostname, T_A);

  
    return 0;
}
