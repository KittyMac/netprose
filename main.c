#include <stdio.h>
#include <pcap.h>
#include <ncurses.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/tcp.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};


#define kBytesHistory 5

typedef struct
{
	struct in_addr ip_dst;
	char ip_address[32];
	long bytes[kBytesHistory];
	long total_bytes;
	pthread_mutex_t lock;
}TrafficInfo;


static void finish(int sig);
static void exit_finish();

static const char * current_device = NULL;
static pcap_t * pcap_handle = NULL;
static long actual_packets_processed = 0;

static TrafficInfo * all_traffic = NULL;
static long n_traffic = 0;

static float total_traffic_second = 0;

static int building_history = 0;


void init_ncurses()
{
	initscr();
	
    keypad(stdscr, TRUE);
	
    nonl();
    cbreak();
    noecho();
	
    if (has_colors())
    {
        start_color();
		
        init_pair(1, COLOR_BLACK, COLOR_WHITE);
		init_pair(2, COLOR_BLUE, COLOR_WHITE);
		init_pair(3, COLOR_RED, COLOR_WHITE);
		
		init_pair(4, COLOR_BLUE, COLOR_WHITE);
		init_pair(5, COLOR_BLACK, COLOR_WHITE);
		
		assume_default_colors(COLOR_BLACK,COLOR_WHITE);
    }
	
	
	/*
		move(1, 1);
		addch(c);
		attroff(COLOR_PAIR(1));
	 */
	
	signal(SIGINT, finish);
	atexit(exit_finish);
}

void init_pcap(const char * device)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	pcap_handle = pcap_open_live(device, 68, 1, 1000, errbuf);
	if (pcap_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		exit(2);
	}
	
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1)
	{
		net = 0;
		mask = 0;
	}
	
	if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		exit(2);
	}
	if (pcap_setfilter(pcap_handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pcap_handle));
		exit(2);
	}
		
	current_device = device;
}

void fill_line(int y)
{
	int i = COLS;
	move(y, 0);
	while(i--)
	{
		addch(' ');
	}
}

int calculate_center(char * str)
{
	return COLS/2 - strlen(str)/2;
}

void print_header()
{
	char * new_info;
	char * app_name = "netprose";
	struct pcap_stat stats;
	
	pcap_stats(pcap_handle, &stats);
	
	asprintf(&new_info, "Device: %s      Packets: %d     Lag: %d   Dropped: %d    Total: %0.2f Mb/s", current_device, actual_packets_processed, stats.ps_recv - actual_packets_processed, stats.ps_drop, total_traffic_second);
		
	attron(COLOR_PAIR(3));
	fill_line(0);
	mvprintw(0, calculate_center(app_name), app_name);
	attroff(COLOR_PAIR(3));
	
	attron(COLOR_PAIR(1));
	fill_line(1);
	mvprintw(1, calculate_center(new_info), "%s", new_info);
	
	attron(A_UNDERLINE);
	fill_line(2);
	mvprintw(2, 0, "  Dest IP Address   |     Net Bytes      |   Current Bytes    |       Average Mb/s ");
	attroff(COLOR_PAIR(1));
	attroff(A_UNDERLINE);
	
	free(new_info);
}

void print_traffic()
{
	TrafficInfo * info = all_traffic;
	int i = 0;
	int j = 0;
	int line = 3;
	long bytes = 0;
	long total_bytes = 0;
	long avg_bytes = 0;
	
	if(all_traffic == NULL)
	{
		return;
	}
	
	if(building_history < kBytesHistory)
	{
		attron(COLOR_PAIR(3));
		attron(A_BOLD);
		mvprintw(LINES/2, COLS/2-25/2, "BUILDING TRANSFER HISTORY");
		attroff(A_BOLD);
		attroff(COLOR_PAIR(3));
		
		building_history++;
		
		j = n_traffic;
		while(j--)
		{
			if(line & 0x1)
			{
				attron(COLOR_PAIR(4));
				//attron(A_BOLD);
			}
			else
			{
				attron(COLOR_PAIR(5));
				//attroff(A_BOLD);
			}
			
			pthread_mutex_lock(&info->lock);
			for(i = kBytesHistory-1; i > 0 ; i--)
			{
				avg_bytes += info->bytes[i];
				info->bytes[i] = info->bytes[i-1];
			}
			info->bytes[0] = 0;
			pthread_mutex_unlock(&info->lock);
			info++;
		}
		
		
		
		return;
	}
	if(building_history == kBytesHistory)
	{
		fill_line(LINES/2);
		building_history++;
	}
	
	j = n_traffic;
	total_traffic_second = 0;
	
	while(j--)
	{
		if(line & 0x1)
		{
			attron(COLOR_PAIR(4));
			//attron(A_BOLD);
		}
		else
		{
			attron(COLOR_PAIR(5));
			//attroff(A_BOLD);
		}
		
		pthread_mutex_lock(&info->lock);
		bytes = info->bytes[0];
		avg_bytes = info->bytes[0];
		total_bytes = info->total_bytes;
		for(i = kBytesHistory-1; i > 0 ; i--)
		{
			avg_bytes += info->bytes[i];
			info->bytes[i] = info->bytes[i-1];
		}
		info->bytes[0] = 0;
		pthread_mutex_unlock(&info->lock);
		
		avg_bytes /= kBytesHistory;
		
		fill_line(line);
		mvprintw(line, 0, "%s", info->ip_address);
		mvprintw(line, 24, "%d", total_bytes);
		mvprintw(line, 45, "%d (%0.2f Mb)", bytes, ((float)bytes / (1024.0f * 1024.0f)) * 8.0f);
		mvprintw(line, 72, "%0.2f", ((float)avg_bytes / (1024.0f * 1024.0f)) * 8.0f);
		
		total_traffic_second += ((float)avg_bytes / (1024.0f * 1024.0f)) * 8.0f;
		
		attroff(COLOR_PAIR(4));
		attroff(COLOR_PAIR(5));
		
		info++;
		line++;
	}
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct sniff_ethernet * ethernet;
	struct sniff_ip * ip;
	u_int size_ip;
	TrafficInfo * info = NULL;
	int i = 0;
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
	{
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	if(all_traffic == NULL)
	{
		n_traffic = 1;
		all_traffic = malloc(sizeof(TrafficInfo));
		info = all_traffic;
		info->ip_dst = ip->ip_dst;
		strcpy(info->ip_address, inet_ntoa(ip->ip_dst));
		memset(info->bytes, 0, sizeof(info->bytes));
		info->total_bytes = 0;
		pthread_mutex_init(&info->lock, 0);
	}
	else
	{
		i = n_traffic;
		info = all_traffic;
		while(i--)
		{
			if(memcmp(&(info->ip_dst), &(ip->ip_dst), sizeof(struct in_addr)) == 0)
			{
				i = -99;
				break;
			}
			info++;
		}
		if(i != -99)
		{
			// we did not find this ip_dst
			all_traffic = realloc(all_traffic, sizeof(TrafficInfo)*(n_traffic+1));
			info = all_traffic + n_traffic;
			info->ip_dst = ip->ip_dst;
			strcpy(info->ip_address, inet_ntoa(ip->ip_dst));
			memset(info->bytes, 0, sizeof(info->bytes));
			info->total_bytes = 0;
			n_traffic++;
			pthread_mutex_init(&info->lock, 0);
		}
	}
	
	// By here, info is always accurate
	pthread_mutex_lock(&info->lock);
	info->bytes[0] += ntohs(ip->ip_len) + SIZE_ETHERNET;
	info->total_bytes += ntohs(ip->ip_len) + SIZE_ETHERNET;
	pthread_mutex_unlock(&info->lock);
	
	actual_packets_processed++;
}

void * thread_process_pcap(void * arg)
{
	pcap_loop(pcap_handle, -1, got_packet, NULL);
	return NULL;
}

int main(int argc, const char * argv[])
{
	pthread_t sniffer_thread;
	
	if(argc != 2)
	{
		fprintf(stdout, "usage:  netprose <network interface>\n");
		exit(2);
	}
	
	init_pcap(argv[1]);
	init_ncurses();
	
	pthread_create(&sniffer_thread, 
				   NULL,
				   thread_process_pcap,
				   NULL);
	
	while(true)
	{
		print_traffic();
		print_header();
		refresh();
		sleep(1);
	}
	
    finish(0);
}

static void finish(int sig)
{
    endwin();
		
    exit(0);
}

static void exit_finish()
{
	finish(0);
}