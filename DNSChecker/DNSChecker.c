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

int main(int argc, char** argv)
{
    FILE *expect = NULL;

    if(argc != 3)
    {
        printf("Usage: ./DNSChecker <ip> <port>\n");
	return 0;
    }

    expect = fopen("expect.csv", "r");

    if(expect == NULL)
    {
        printf("Usage: ./DNSChecker <ip> <port>\n");
	return 0;
    }

    return 0;
}
