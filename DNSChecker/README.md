# DNS SLA Checker
# Usage
## How to Use
```
cd ../build
./DNSChecker <name server ip address> <port>
```
- Terminates with an exit code of 0: Operating normally
- Terminates with an exit code of 1: Operating abnormally
- Terminates with an exit code of 2: Cannot establish a connection to the target address
- You need ./expect.csv input file whilch consists of two columns: the first column is a domain name to query (e.g. ”bank.com”), and the second column is the IP expected as response (e.g. ”10.0.0.1”).
```
bank.com, 10.0.0.1
naver.com, 142.523.52.5
```
- If there are many ip address that are binded in one domain name, it will check iterative for find at least one of the ip address that are specified in ./expect.csv.
- If there are no response from nameserver, it will exit with number 1 after 5 second.


# Deliverables

- [./slalib.h](slalib.h): The header file that made by [SLA library](../slalib)
- [./libsla.so](libsla.so): The library file that made by [SLA library](../slalib)
- [./DNSChecker.c](DNSChecker.c): For SLA check for domain name server, this program read test case as input, and iteratively send raw dns query using given library.
