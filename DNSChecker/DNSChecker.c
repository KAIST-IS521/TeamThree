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

//check IP dotted formatting.  
//return 0: valid IP
//return 1; invalid IP
int validIPCheck(const char* ip)
{   
    int* splitedIP;
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
     
    validIPCheck(argv[1]);
 
    socket = openUDPSocket(argv[1], port);  
    if(socket < 0)
        exit(2);

    

  
    return 0;
}
