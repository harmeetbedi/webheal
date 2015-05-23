Install on Linux OS
-------------------
1. Ensure libpcap is installed using your package manager. e.g. with command $ sudo yum install libpcap 
2. Ensure JDK 1.7 is installed and working 
3. select and create install directory e.g. ~/webheal
4. Unzip webheal.zip in this directory
5. find path using command 'echo $PATH'. Copy libjpcap.so in a folder that is in your path
To troubleshoot pcap install
1. Install tcpdump using your package manager e.g. with command $ sudo yum install tcpdump

2. Verify tcpdump starts and you can see sniff traffic. Consult tcpdump man pages if you need using $man tcpdump
3. For tcpdump or webheal to run, need to select a network interface to sniff traffic from. List of interfaces can be obtained by command $ifconfig

Run webheal
---------
1. Navigate to install directory. e.g. $ cd ~/webheal
2. Run command line using commands like these 
$ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Main -i eth0 -c webheal.properties

For list of options:
$ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Cli 
usage: java org.webheal.sniffer.Main
 -c <arg>   configuration file
 -f <arg>   pcap file containing test payload. only one of -f or -i should
            be specified
 -i <arg>   network interface. only one of -f or -i should be specified

Operational notes
-----------------
See webheal.properties for configuration information
1. 'dir.trace' property will cause disk to get filled up quickly with trace of http requests and responses. This should only be run for short time or for debugging
2. logs directory contains a number of useful files. 
2a. skip.log* will give http requests-response that are skipped and reason for that. 
2b. stat.log* will give statistics per rule per http request-response, per rule and for all rules. Use this to determine correctness and cost 
3. rulehit directory is where rule hits are logged. There is a new rulehits file created every minute to ease rule hit imports into other systems
4. A subset of modsecurity config file syntax is supported. It is not a 100% compatible, yet it is complete enough to detect most pattern matching security attacks. Here is the subset that is accepted 
4a. Directives. Only SecRule. Other directives are ignored if present. 
4b. Variables supported: ARGS, ARGS_NAMES, QUERY_STRING, REQUEST_BODY, REQUEST_URI, REMOTE_ADDR, REQUEST_METHOD, RESPONSE_BODY, RESPONSE_CONTENT_LENGTH, RESPONSE_CONTENT_TYPE, RESPONSE_STATUS, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, REQUEST_HEADERS_NAMES, RESPONSE_HEADERS, RESPONSE_HEADERS_NAMES, REQUEST_LINE
4c. Actions supported to process variable value: convertToLowercase, removeSelfReferences, convertBackslashes, compressSlashes, compressWhitespace, decodeEscaped, decodeURLEncoded,decodeURLEncodedAgain
4d. Operators supported to do rule match: contains, pm, rx, startsWith, endsWith