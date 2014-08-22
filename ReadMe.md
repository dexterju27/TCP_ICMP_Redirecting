# TCP forwarding Pentration Testing 
##Description
This program is designed to forwarding TCP and ICMP packet using winpcap sending eth packet. When a TCP or ICMP packet arrive. The program will change the IP and ETH header of the packet and resend it to the internet. And receiving the response form the server, change the packet, send it to the original sender.
##Dependence
*	Windows only
*	Winpcap driver 4.1.2 is required.
 And the developer pack of Winpcap is required to compile the program. The path of the pack should be designated in the project file._Known compatibility issues with Winpcap 4.1.3._
*	IPhelper API


##Usage
1.	Compile the program
2.	Write conf.txt file in the same folder of the executable file. The first two lines of the file follow the rule of Winpcap filter file. And the rest lines is the IP address you want to fake and redirecting to.Here is an example.
`tcp or icmp and dst host 58.192.114.8`
`tcp or icmp and src host 23.244.180.1`
`58.192.114.8`
`23.244.180.1`

3.	Run the program choose the netcard for source and destination. source means where the tcp request coming from. And destination is the netcard linked to the internet.
4.	Because Windows will send a RST packet when receive the TCP packet responding to the redirecting one. So in order to build the TCP connection. The destination server should block all RST request using iptables.
5.	Change the server's http connection from keepalive to closed to ensure the stable connection.

##Lisence
The program is under MIT lisence. For testing use only, any immoral and illegal use is not permitted.