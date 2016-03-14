#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

char cpre580f98[] = "netdump";

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;

int total_ARP = 0, total_IP = 0, total_ICMP = 0, total_broadcast;  // total packet counter

int
main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
		}
	}

	putchar('\n');
	printf("Total broadcast packets: ");
	printf("%d", total_broadcast);
	putchar('\n');	
	printf("Total ARP packets: ");
	printf("%d", total_ARP);
	putchar('\n');
	printf("Total IP packets: ");
	printf("%d", total_IP);
	putchar('\n');
	printf("Total ICMP packets: ");
	printf("%d", total_ICMP);
	putchar('\n');		

	exit(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

/*
insert your code in this routine

*/

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
        u_int length = h->len;
        u_int caplen = h->caplen;
	register const u_char *pc; //working pointer. This will grab the bytes 

	pc = p;

	u_char byte1 = *pc++;
	u_char byte2 = *pc++;
	u_char byte3 = *pc++;
	u_char byte4 = *pc++;
	u_char byte5 = *pc++;
	u_char byte6 = *pc++;
	u_char byte7 = *pc++;
	u_char byte8 = *pc++;
	u_char byte9 = *pc++;
	u_char byte10 = *pc++;

	u_char byte11 = *pc++;
	u_char byte12 = *pc++;
	u_char byte13 = *pc++;
	u_char byte14 = *pc++;
	u_char byte15 = *pc++;
	u_char byte16 = *pc++;
	u_char byte17 = *pc++;
	u_char byte18 = *pc++;
	u_char byte19 = *pc++;
	u_char byte20 = *pc++;

	u_char byte21 = *pc++;
	u_char byte22 = *pc++;
	u_char byte23 = *pc++;
	u_char byte24 = *pc++;
	u_char byte25 = *pc++;
	u_char byte26 = *pc++;
	u_char byte27 = *pc++;
	u_char byte28 = *pc++;	
	u_char byte29 = *pc++;
	u_char byte30 = *pc++;

	u_char byte31 = *pc++;
	u_char byte32 = *pc++;
	u_char byte33 = *pc++;
	u_char byte34 = *pc++;
	u_char byte35 = *pc++;
	u_char byte36 = *pc++;
	u_char byte37 = *pc++;
	u_char byte38 = *pc++;
	u_char byte39 = *pc++;
	u_char byte40 = *pc++;

	u_char byte41 = *pc++;
	u_char byte42 = *pc++;
	u_char byte43 = *pc++;
	u_char byte44 = *pc++;
	u_char byte45 = *pc++;
	u_char byte46 = *pc++;
	u_char byte47 = *pc++;
	u_char byte48 = *pc++;
	u_char byte49 = *pc++;
	u_char byte50 = *pc++;

	u_char byte51 = *pc++;
	u_char byte52 = *pc++;
	u_char byte53 = *pc++;
	u_char byte54 = *pc++;
	u_char byte55 = *pc++;
	u_char byte56 = *pc++;
	u_char byte57 = *pc++;
	u_char byte58 = *pc++;
	u_char byte59 = *pc++;
	u_char byte60 = *pc++;

	u_char byte61 = *pc++;
	u_char byte62 = *pc++;
	u_char byte63 = *pc++;
	u_char byte64 = *pc++; 

	//ARP PACKET
	u_int ethernet_type = byte13*256+byte14;
 	u_int HW_Type = byte15*256 + byte16;
	u_int ARP_Protocol = byte17*256+byte18;
	u_char HA_Length = byte19;
	u_char PA_Length = byte20;
	u_int Operation = byte21*256 + byte22;// if its 1, its a request, if its 2, its a rpely
	//Send_HA = 23-28;
	//Send_PA = 29-32;
	//Target_HA = 33-38;
	//Target_PA = 39-42;
	//Pad_Bytes =- 43-60;
	u_long FCS = byte64 + (byte63 << 8) + (byte62 << 16) + (byte61 << 24);//FCS = 61_64;

	//TCP PACKET
	//Ver/IHL = 15
	//Type = 16 (usually zero)
	u_int t_len = byte17*256+byte18; //total length of packet, display as decimal
	u_int packetID = byte19*256+byte20;
	//Flags = byte 21
	u_int offset = byte21*256+byte22;
	//TTL = 23
	//Protocol = 24
	u_int checksum = byte25*256+byte26;
	//SA = 27-30 DISPLAY AS DECIMAL
	//DA = 31-34  DISPLAY AS DECIMAL
	u_int s_port = byte35*256+byte36;
	u_int d_port = byte37*256+byte38;
	u_long seqnum = byte42 + (byte41 << 8) + (byte40 << 16) + (byte39 << 24);// 39-42
	u_long acknum = byte46 + (byte45 << 8) + (byte44 << 16) + (byte33 << 24);// 39-42; // 43- 46
	//TCP Header length = 47
	// 48 = FLAGS, U, A, P, R,S, F
	u_int window = byte49*256+byte50;
	u_int tcpchecksum = byte51*256+byte52;
	u_int urgent_pointer = byte53*256+byte54;

	//ICMP PACKET
	u_int icmptype = byte21*256+byte22;
	u_int icmpcode = byte23*256+byte24;
	u_long icmpchecksum = byte28 + (byte27 << 8) + (byte26 << 16) + (byte25 << 24);//25-28
	//icmp checksum


	//PRINTING

	putchar('\n');	
	printf("\nDestination MAC Address: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:", byte1,byte2,byte3,byte4,byte5,byte6);
	printf("\nSource MAC Address: ");
	printf("%02x:%02x:%02x:%02x:%02x:%02x:", byte7,byte8,byte9,byte10,byte11,byte12);


	if(ethernet_type <= 1500) //checks to see if length field
	{
		printf("\nLength: ");
		printf("%d", ethernet_type); //formats for decimal 
		total_broadcast++;
	}
	else if(ethernet_type >= 1536) //checks to see if type field, and prints the payload type.
	{
		printf("\nType: %04x", ethernet_type); //formats for hex
	
		if(ethernet_type == 2048) // IPv4
		{
			printf("\nPayload: IPv4");
			total_IP++;
			printf("\nVer/IHL: %02x", byte15);
			printf("\nService Type: %02x", byte16);
			printf("\nTotal Packet Length: %04d", t_len);
			printf("\nPacket ID: %04d", packetID);
			printf("\nIP Flag: %04d", byte21);
			printf("\nOffset: %04d", offset);
			printf("\nTime To Live: %02d", byte23);
			printf("\nProtocol: %02d", byte24);	
			printf("\nIP Checksum: %04d", checksum);
			printf("\nSource IP Address: %02d.%02d.%02d.%02d", byte27,byte28,byte29,byte30);
			printf("\nDestination IP Address: %02d.%02d.%02d.%02d", byte31,byte32,byte33,byte34);
			if(byte24 == 1)
			{
				total_ICMP++;
				printf("\nIP Flag: %02x (ICMP)", byte21);
				printf("\nType: %04d", icmptype);
				printf("\nCode: %04d", icmpcode);
				printf("\nChecksum: %08lu", icmpchecksum);
			}
			else if(byte24 == 4)
			{
				printf("\nIP Protocol: %02x (IPv4)", byte24);
			}
			else if(byte24 == 6)
			{
				printf("\nIP Protocol: %02x (TCP)", byte24);
				printf("\nSource Port: %04d", s_port);
				printf("\nDestination Port: %04d", d_port);
				printf("\nSequence Number: %08lu", seqnum);
				printf("\nACK Number: %08lu", acknum);
				printf("\nTCP Length: %02d", byte47);
				if(byte48 == 1)
				{
					printf("\nTCP Flag: FIN");
				}
				else if(byte48 == 2)
				{
					printf("\nTCP Flag: SYN");
				}
				else if(byte48 == 4)
				{
					printf("\nTCP Flag: RST");
				}
				else if(byte48 == 8)
				{
					printf("\nTCP Flag: PSH");
				}
				else if(byte48 == 16)
				{
					printf("\nTCP Flag: ACK");
				}
				else if(byte48 == 32)
				{
					printf("\nTCP Flag: URG");
				}
				else
				{
				printf("\nTCP Flag undefined");
				}
				printf("\nTCP Window %04d", window);
				printf("\nTCP Checksum %04d", tcpchecksum);
				printf("\nTCP Urgent Pointer %04d", urgent_pointer);
			}
			else if(byte24 == 17)
			{
				printf("\nIP Protocol: %02x (UDP)", byte24);
			}
			else if(byte24 == 41)
			{
				printf("\nIP Protocol: %02x (IPv6)", byte24);
			}
			else 
			{
				printf("\nIP Protocol: %02x (Undefined)", byte24);
			}

		} 
		else if(ethernet_type == 2054) //ARP
		{
			printf("\nPayload: ARP");
			total_ARP++;
			printf("\nHardware Type: %04x", HW_Type) ;
			printf("\nProtocol: %04x", ARP_Protocol);
			printf("\nHardware Address Length: %02d", byte19);
			printf("\nProtocol Address Length: %02d", byte20);		
			if(Operation == 1)
				{
				printf("\nOperation: %04x: ARP Request", Operation);
				}
			else if(Operation == 2)
				{
				printf("\nOperation: %04x: ARP Reply", Operation);
				}
			else
				{
				printf("\nOperation undefined");
				}
			printf("\nSender Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", byte23,byte24,byte25,byte26,byte27,byte28);
			printf("\nSender Protocol Address: %02d.%02d.%02d.%02d", byte29,byte30,byte31,byte32); //need to print in ip format
			printf("\nTarget Hardware Address: %02x:%02x:%02x:%02x:%02x:%02x", byte33,byte34,byte35,byte36,byte37,byte38);
			printf("\nTarget Protocol Address: %02d.%02d.%02d.%02d", byte39,byte40,byte41,byte42); //need to print in ip format
			printf("\nPad Bytes: %02x%02x%02x%02x%02x%02x", byte43,byte44,byte45,byte46,byte47,byte48);
			printf("%02x%02x%02x%02x%02x%02x",byte49,byte50,byte51,byte52,byte53,byte54);
			printf("%02x%02x%02x%02x%02x%02x",byte55,byte56,byte57,byte58,byte59,byte60);
			printf("\nFrame Control Sequence: %08lu", FCS);    
		}
		else if(ethernet_type == 34525) //IPv6
		{
		printf("\nPayload: IPv6");
		total_IP++;
		}
	}
	else
	{
		printf("Type/Length: Undefined");
	}

	//decimal of 1500 and below indicates size, 1536 and above = type
	//hex of 0800 is ip(2048) , hex of 0806 is arp(2054)
	//NOTE: noticed that 90% of the packets on my system were IPv6 (0x86dd) so I added some code to distinguish it. 
       putchar('\n');
	default_print(p, caplen);
        putchar('\n');
}