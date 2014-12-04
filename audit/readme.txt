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
2a $ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Cli -i eth0 -t 5s -dt ./trace -dh ./rulehit -m test.conf
2b $ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Cli -i eth0 -t 5s -dt ./trace -dh ./rulehit -m test.conf -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml -h testfire
2c $ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Cli -i eth0 -t 5s -dt ./trace -dh ./rulehit -ne gif,css,jpg,jpeg,png,xls,pdf,xlsx,doc,csv,txt,js,mov,ico -nt image,xml -C hostrules.txt
in (2c) hostrules.txt could contain lines like these: (used to associate separate config files with each host)
bing.com,bing.ca=/Users/harmeet/dev/kodemuse/ext/webheal/bing.conf
yahoo.com,yahoo.ca=/Users/harmeet/dev/kodemuse/ext/webheal/yahoo.conf

For list of options:
$ sudo java -Djava.ext.dirs=./lib org.webheal.sniffer.Cli 
usage: java org.webheal.sniffer.Cli
 -C <arg>    file with each line having format <comma separated hostnames>=<rule configuration file>. 
 	         If this is specified, -m and -h parameters are ignored
 -dh <arg>   directory where rule hit logs are stored
 -dt <arg>   (optional) if present, directory where tcp flow files are
             stored. If not specified, tcp flows trace files are not
             created
 -h <arg>    (optional) comma separated list of hosts in http request that
             are tracked
 -i <arg>    network interface
 -m <arg>    mod security rule file
 -ne <arg>   (optional) ignore requests for comma separated list of
             extensions
 -nt <arg>   (optional) ignore requests that result in comma separated
             list of content type response
 -t <arg>    max idle time for a network connection
 -v          (optional) verbose output


Operational notes
-----------------
1. -dt option will cause disk to get filled up quickly with trace of http requests and responses. This should only be run for short time or for debugging
2. logs directory contains a number of useful files. 
2a. skip.log* will give http requests-response that are skipped and reason for that. Skipping is usually due to -ne -nt and -h options
2b. stat.log* will give statistics per rule per http request-response, per rule and for all rules. Use this to determine correctness and cost 
3. rulehit directory '-dh' is where rule hits are logged. There is a new rulehits file created every minute to ease rule hit imports into other systems
4. -m can be used to specify modsecurity config file. This is not a 100% compatible with modsecurity rules, yet it is complete enough to detect most WAF oriented attacks. Here is the subset that is accepted 
4a. Directives. Only SecRule. Other directives are ignored if present. 
4b. Variables supported: ARGS, ARGS_NAMES, QUERY_STRING, REQUEST_BODY, REQUEST_URI, REMOTE_ADDR, REQUEST_METHOD, RESPONSE_BODY, RESPONSE_CONTENT_LENGTH, RESPONSE_CONTENT_TYPE, RESPONSE_STATUS, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, REQUEST_HEADERS_NAMES, RESPONSE_HEADERS, RESPONSE_HEADERS_NAMES, REQUEST_LINE
4c. Actions supported to process variable value: convertToLowercase, removeSelfReferences, convertBackslashes, compressSlashes, compressWhitespace, decodeEscaped, decodeURLEncoded,decodeURLEncodedAgain
4d. Operators supported to do rule match: contains, pm, rx, startsWith, endsWith