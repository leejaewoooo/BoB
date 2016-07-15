/*IP Header*/
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;
/*IP Address*/
typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;
/*UDP Header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;
/*Prototype of the packet Handler*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
/*Main*/
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;
	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);
	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	/* Open the adapter */
	if ((adhandle = pcap_open(d->name,  // name of the device
		65536,     // portion of the packet to capture. 
		// 65536 grants that the whole packet will be captured on all the MACs.
		PCAP_OPENFLAG_PROMISCUOUS,         // promiscuous mode
		1000,      // read timeout
		NULL,      // remote authentication
		errbuf     // error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}
/*Callback Function invoked by libpcap for every incoming packet*/
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	ip_header *ih;
	udp_header *uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	printf(" Destination Mac Address : ");
	for (int i = 1; i < 6; i++)
	{
		printf("%02x ", *(unsigned char*)(pkt_data + i));
	}
	printf("  Source Mac Address : ");
	for (int i = 6; i < 12; i++)
	{
		printf("%02x ", *(unsigned char*)(pkt_data + i));
	}
	printf("\n");
	printf("Source IP : ");
	for (int i = 26; i < 30; i++) {
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}
	printf("  Destination IP : ");
	for (int i = 30; i < 34; i++)
	{
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}
	printf("\n");
	printf("Ethertype : %02X", ntohs(*((unsigned short *)(pkt_data + 12))));

	printf("  Protocol number : ");
	for (int i = 23; i < 24; i++)
	{
		printf("%d ", *(unsigned char*)(pkt_data + i));
	}
	printf("\n");
	printf(" Source port : ");
	printf("%d", ntohs(*(unsigned short*)(pkt_data + 34)));

	printf(" Destination port : ");
	printf("%d", ntohs(*(unsigned short*)(pkt_data + 36)));
	printf("\n");
	printf("------------------------------------------\n");
	printf("\n");
}
