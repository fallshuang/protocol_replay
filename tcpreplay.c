
#include <stdio.h>
#include <pcap.h>
#include <errno.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN (6)
#endif

#define _MULTI_THREAD_

struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
};

struct sniff_ip {
	u_int ip_hl:4,
	ip_v:4; 
	u_char ip_tos; 
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
#define IP_RF 0x8000 
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};

struct sniff_tcp {
u_short th_sport;
u_short th_dport;
u_int th_seq;
u_int th_ack;
u_int th_x2:4,
th_off:4;
u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FINTH_SYNTH_RSTTH_ACKTH_URGTH_ECETH_CWR)
u_short th_win;
u_short th_sum;
u_short th_urp;
};

static int count = 0;
static pcap_t *g_file = NULL;
static pcap_t *descr;
static pthread_mutex_t mutex;
static pthread_cond_t cond;
static remote_seq = 0;

unsigned short comp_chksum(unsigned short *addr, int len) {
    long sum = 0;

    while (len > 1) {
        sum += *(addr++);
        len -= 2;
    }

    if (len > 0)
        sum += *addr;

    while (sum >> 16)
        sum = ((sum & 0xffff) + (sum >> 16));

    sum = ~sum;

    return ((u_short) sum);

}

void my_callback(u_char *useless,
		const struct pcap_pkthdr *pkthdr,
		const u_char *packet)
{	
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	size_t sz_ethernet = sizeof(struct sniff_ethernet);
	size_t sz_ip = sizeof(struct sniff_ip);

	count++;
	printf("%d, len=%d\n", count, pkthdr->len);

	ethernet = (struct sniff_ethernet *)local_packet;
	ip = (struct sniff_ip *)(local_packet + sz_ethernet);
	tcp = (struct sniff_tcp *)(local_packet + sz_ethernet + sz_ip);

	remote_seq = ntohl(tcp->th_seq);

#ifdef _MULTI_THREAD_
	pthread_mutex_lock(&mutex);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
#endif
}


void *start_traffic(void *arg)
{
	char *dev;
	u_char *local_packet;
	struct pcap_pkthdr local_header;
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	size_t sz_ethernet = sizeof(struct sniff_ethernet);
	size_t sz_ip = sizeof(struct sniff_ip);
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	pcap_t *wdescr;
	
	dev = pcap_lookupdev(errbuf);

	if (!dev) {
		printf("%s\n",errbuf);
		return -1;
	}

	printf("DEV2: %s\n", dev);

	wdescr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	if (!wdescr) {
		printf("pcap_open_live(): %s\n", errbuf);
		return -2;
	}

	sleep(1);

	g_file = pcap_open_offline("1.pcap", errbuf);
	local_packet = (u_char *)pcap_next(g_file, &local_header);

	ethernet = (struct sniff_ethernet *)local_packet;
	ip = (struct sniff_ip *)(local_packet + sz_ethernet);
	tcp = (struct sniff_tcp *)(local_packet + sz_ethernet + sz_ip);

	
	ret = pcap_sendpacket(wdescr, local_packet, local_header.len);
	printf("send ret=%d, len=%d\n", ret, local_header.len);
	
	while (1) {
		local_packet = (u_char *)pcap_next(g_file, &local_header);
		if (!local_packet)
			break;
		ethernet = (struct sniff_ethernet *)local_packet;
		ip = (struct sniff_ip *)(local_packet + sz_ethernet);
		tcp = (struct sniff_tcp *)(local_packet + sz_ethernet + sz_ip);
		//printf("read pkt, len=%d\n", local_header.len);
		if (ntohs(tcp->th_sport) == 80) {
#ifdef _MULTI_THREAD_
			pthread_mutex_lock(&mutex);
			pthread_cond_wait(&cond, &mutex);
			pthread_mutex_unlock(&mutex);
#endif
			continue;
		}

		ret = pcap_sendpacket(wdescr, local_packet, local_header.len);
		printf("send ret=%d, len=%d\n", ret, local_header.len);
	}

	pcap_close(wdescr);

	return NULL;
}

int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter;
	char filter_app[] = "tcp src port 80";
	bpf_u_int32 maskp;         
	bpf_u_int32 netp;
	struct pcap_pkthdr local_header;
	struct pcap_pkthdr net_header;
	struct sniff_ethernet *ethernet;
	struct sniff_ip *ip;
	struct sniff_tcp *tcp;
	u_char *net_packet;
	u_char *local_packet;
	size_t sz_ethernet = sizeof(struct sniff_ethernet);
	size_t sz_ip = sizeof(struct sniff_ip);
	int ret;
	pthread_t tid;

	pthread_mutex_init(&mutex, NULL);
	pthread_cond_init(&cond, NULL);

	dev = pcap_lookupdev(errbuf);

	if (!dev) {
		printf("%s\n",errbuf);
		return -1;
	}

	printf("DEV: %s\n", dev);

	//pcap_lookupnet(dev, &netp, &maskp, errbuf);

	descr = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);

	if (!descr) {
		printf("pcap_open_live(): %s\n", errbuf);
		return -2;
	}

	if (-1 == pcap_compile(descr, &filter, filter_app, 0, PCAP_NETMASK_UNKNOWN))
	{
		printf("Error calling pcap_compile\n");
		return -3;
	}

	if (-1 == pcap_setfilter(descr, &filter))
	{
		printf("Error calling pcap_setfilter\n");
		return -4;
	}

	printf("pcap setup done\n");
#ifdef _MULTI_THREAD_
	ret = pthread_create(&tid, NULL, start_traffic, NULL);
	if (ret) {
		printf("pthread_create fail, ret=%d\n", ret);
	}
#endif
	ret = pcap_loop(descr, -1, my_callback, NULL);

	pcap_close(descr);

	return 0;
}
