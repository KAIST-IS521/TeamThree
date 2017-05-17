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

/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
    name = (unsigned char*)malloc(256);
 
    name[0]='\0';
 
    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader = reader+1;
 
        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }
 
    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }
 
    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++) 
    {
        p=name[i];
        for(j=0;j<(int)p;j++) 
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

void ngethostbyname(unsigned char *host, int query_type, int s, char *ip)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop;
    int returnVal;
    char recevIP[20];
    struct sockaddr_in a; //

    struct RES_RECORD answers[20]; //the replies from the DNS server
    struct sockaddr_in dest;  //

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("Resolving %s" , host);

    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //

    dest.sin_family = AF_INET; //
    dest.sin_port = htons(53); //
    dest.sin_addr.s_addr = inet_addr("127.0.0.1"); //

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
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        printf("Error: sendto failed");
	exit(2);
    }
    printf("Done");
    
    /*returnVal = sendMsg(socket,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION));
    
    if(returnVal < 0)
    {
        printf("Error: Can't send the DNS packet\n");
        exit(2);
    }*/

    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        printf("Error: recvfrom failed");
	exit(2);
    }
    printf("Done");

    dns = (struct DNS_HEADER*) buf;
 
    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
 
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
 
    //Start reading answers
    stop=0;
 
    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;
 
        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);
 
        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));
 
            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }
 
            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';
 
            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }
 
    //print answers
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("Name : %s ",answers[i].name);
 
        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            strcpy(recevIP, inet_ntoa(a.sin_addr));
	    printf("has IPv4 address : %s", recevIP);
	    if(strcmp(ip, recevIP))
	    {
	        printf(": Not Match!\n");
		if(i == (ntohs(dns->ans_count)-1))  //if it is not match with ip and it is last answer
		    exit(1);
	    }
	    else
	    {
	        printf(": Match!\n");
	        break;
	    }
        }
         
        if(ntohs(answers[i].resource->type)==5) 
        {
            //Canonical name for an alias
            printf("has alias name : %s\n",answers[i].rdata);
	}
    }
    return;
}

int main(int argc, char** argv)
{
    unsigned short port = 0;
    char *endp = NULL;
    int returnVal = 0;
    int socket = 0;
    char ip[20];
    unsigned char host[40];
    FILE *expect = NULL;

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
        fscanf(expect, "%[^,], %s\n", host, ip);
	returnVal = validIPCheck(ip);
	if(returnVal == 1)
	{
	    printf("Error: Invalid IP address fromatting\n");
	    exit(2);
	}
	
	//Now get the ip of hostname, A record
        ngethostbyname(host, T_A, socket, ip);
    }
    fclose(expect);
    exit(0);
    return 0;
}
