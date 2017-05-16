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
#include <sys/socket.h>    //you know what this is for
#include <arpa/inet.h> //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>


#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
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

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) 
{
    int lock = 0 , i;
    strcat((char*)host,".");
     
    for(i = 0 ; i < strlen((char*)host) ; i++) 
    {
        if(host[i]=='.') 
        {
            *dns++ = i-lock;
            for(;lock<i;lock++) 
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}

void ngethostbyname(unsigned char *host, int query_type, int socket)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
    int returnVal;

    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("Resolving %s" , host);

    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 

    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)

    printf("\nSending Packet...");
    returnVal = sendMsg(socket,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION));
    
    if(returnVal < 0)
    {
        printf("Error: Can't send the DNS packet\n");
        exit(2);
    }

    printf("Done");
}

int main(int argc, char** argv)
{
    FILE *expect = NULL;
    unsigned short port = 0;
    char *endp;
    int returnVal = 0;
    int socket;
    unsigned char *host, *ip;

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
    
    while(!feof(expect))
    {
        fscanf(expect, "%s, %s\n", host, ip);
        returnVal = validIPCheck(ip);
	if(returnVal == 1)
	{
	    printf("Error: Invalid IP address fromatting\n");
	    exit(2);
	}
	
	//Now get the ip of hostname, A record
        ngethostbyname(host, T_A, socket);
    }

  
    return 0;
}
