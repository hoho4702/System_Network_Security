#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <iostream>
#include <fstream>
#include <string>
#include <set>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

#define HARMFUL 1
#define NOT_HARMFUL 0
#define TCP 0x06
#define HTTP 0x50
#define SPACEBAR 0x20
#define HOST "Host:"

set<string> sites;
int isharmful = 0;

struct IpHdr {
	uint8_t version:4;
	uint8_t IHL:4;
	uint8_t temp[8];
	uint8_t protocol;
	uint8_t temp2[10];
};

struct TcpHdr {
	uint16_t SrcPort;
	uint16_t DstPort;
	uint16_t temp[4];
	uint8_t reserved:4; //little endian
	uint8_t offset:4;
	uint8_t flag;
	uint16_t temp2[3];
};

void usage()
{
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}

char *strnstr(const char *haystack, const char *needle, size_t len)
{
        int i;
        size_t needle_len;

        if (0 == (needle_len = strnlen(needle, len)))
                return (char *)haystack;

        for (i=0; i<=(int)(len-needle_len); i++)
        {
                if ((haystack[0] == needle[0]) &&
                        (0 == strncmp(haystack, needle, needle_len)))
                        return (char *)haystack;

                haystack++;
        }
        return NULL;
}

static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
	}

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	
	struct nfqnl_msg_packet_hdr *ph;
	int ret;
	unsigned char *_data;

	struct IpHdr *ip;
	struct TcpHdr *tcp;
	char *http;

	char method[9][8] = {"GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "TRACE", "OPTIONS", "PATCH"};
	char method_len[9] = {3, 4, 3, 6, 4, 7, 5, 7, 5};

	ret = nfq_get_payload(nfa, &_data);  
	if (ret >= 0) {
		ip = (IpHdr*)_data;
		isharmful = NOT_HARMFUL;

		// check TCP
		if (ip->protocol == TCP) {
			tcp = (TcpHdr*)((char*)ip + (ip->IHL * 5));

			// check HTTP
			if ((ntohs(tcp->SrcPort) == HTTP) || (ntohs(tcp->DstPort) == HTTP)) {
				http = (char*)tcp + (tcp->offset * 4);
				char* payload = http;

				// check Method
				for(int i = 0 ; i < 9; i++) {
					if(strncmp(payload, method[i], method_len[i]) == 0) {

						// find "Host:"
						char* site = strnstr(payload, HOST, ret);
						if(site) {

							// find site
							site += 5;
							while(*site == SPACEBAR) site++;

							// char* -> string for using find in set
							site = strtok(site, "\r\n");
							strcat(site, "\0");
							string visitSite = site;

							if(sites.find(visitSite) != sites.end()) {
								printf("#Blocked: Access to Unsafe Site Detected!\n");
								isharmful = HARMFUL;
							} else printf("#Accept: This is safe site\n");
						}
						break;
					}
				}
			}
		}
	}

	if (isharmful == HARMFUL) {
		printf("#Request to Harmful Site Detected! This Packet is Dropped\n");
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else if (isharmful == NOT_HARMFUL) {
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
	else printf("error\n");
}

int csv2map(string fileName)
{
	ifstream readFile;    
	readFile.open(fileName);
	if(readFile.is_open())
	{
		int a = 0;
		while(!readFile.eof())
		{
			string site;
			getline(readFile, site);
			site = site.substr(site.find(',') + 1);
			sites.insert(site);
		}
	}
	else {
		printf("no such file\n");
		return 0;
	}
	printf("map insert finish\n");
	readFile.close();
}

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	string site_list = argv[1];
	csv2map(site_list);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));


	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			//printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}