#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <event.h>
#include <glib.h>

#define LOG(x,s...) do { \
      if (!debug) break; \
      time_t t = time(NULL); \
      char *d = ctime(&t); \
      fprintf(stderr,"%.*s %s[%d] %s(): ",\
            (int)strlen(d)-1,d, __FILE__,\
            __LINE__,__FUNCTION__); \
      fprintf(stderr,x,## s); \
} while(0);


typedef struct pkt_flow {
    gpointer        key;
    uint32_t        src_addr;
    uint32_t        dst_addr;
    uint16_t        src_port;
    uint16_t        dst_port;
    uint32_t        time_start;
    uint64_t        total_bytes_xferred;
    uint32_t        current_bytes;
    uint64_t        total_packets;
    GPtrArray      *bytes_per_sec;
    struct event    timer;
} pkt_flow_t;

struct event    pcap_event;
struct event    stop_event;
int             debug;
int             detail;
int             runtime;
int             top_limit;
char           *bpf;
char           *iface;
int             quiet;
pcap_t         *pcap_desc;
GHashTable     *flow_tbl;

void free_flow_tbl(pkt_flow_t *flow);

void
globals_init(void)
{
    quiet = 0;
    debug = 0;
    bpf = NULL;
    iface = "eth0";
    pcap_desc = NULL;
    runtime = 60;
    detail = 0;
    top_limit = 0;
    flow_tbl = g_hash_table_new_full(g_str_hash, g_str_equal, 
	    NULL, (void *)free_flow_tbl);
}

void 
free_flow_key(gpointer key)
{
    free(key);
}

void
free_bps_node(uint32_t *a, void *d)
{
    free(a);
}

void 
free_flow_tbl(pkt_flow_t *flow)
{
    free(flow->key);
    evtimer_del(&flow->timer);
    // DERR
     
    g_ptr_array_foreach(flow->bytes_per_sec, (void*)free_bps_node, NULL);
    g_ptr_array_free(flow->bytes_per_sec, TRUE);
    free(flow);
}

void
parse_args(int argc, char **argv)
{
    int             c;

    while ((c = getopt(argc, argv, "ql:di:f:r:D")) != -1) {
        switch (c) {

        case 'D':
            debug++;
            break;
        case 'd':
            detail++;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'f':
            bpf = optarg;
            break;
        case 'r':
            runtime = atoi(optarg);
            break;
	case 'l':
	    top_limit = atoi(optarg);
	    break;
	case 'q':
	    quiet = 1;
	    break;
        default:
            printf("Usage: %s [opts]\n"
                   "   -d: debug\n"
                   "   -i <iface>\n"
                   "   -f <bpf filter>\n" 
		   "   -l <limit to top x>\n"
		   "   -q: quiet\n"
		   "   -r <runtime>\n", argv[0]);
            exit(1);
        }
    }
}

void
do_flow_transforms(int sock, short which, pkt_flow_t * flow)
{
    uint32_t       *bytes_ps;
    struct timeval  tv;

    LOG("Doing transform for %u:%d -> %u:%d (%u bytes)\n",
        flow->src_addr, ntohs(flow->src_port),
        flow->dst_addr, ntohs(flow->dst_port), flow->current_bytes);

    bytes_ps = malloc(sizeof(uint32_t));

    memcpy(bytes_ps, &flow->current_bytes, sizeof(uint32_t));
    g_ptr_array_add(flow->bytes_per_sec, bytes_ps);

    flow->current_bytes = 0;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    evtimer_set(&flow->timer, (void *) do_flow_transforms, flow);
    evtimer_add(&flow->timer, &tv);
}

pkt_flow_t     *
find_flow(uint32_t src_addr, uint16_t src_port,
          uint32_t dst_addr, uint16_t dst_port)
{
    char            buff[10 + 5 + 10 + 5 + 1];
    pkt_flow_t     *flow;
    struct timeval  tv;

    memset(buff, 0, sizeof(buff));

    snprintf(buff, sizeof(buff) - 1, "%u%d%u%d",
             src_addr, src_port, dst_addr, dst_port);

    if ((flow = g_hash_table_lookup(flow_tbl, buff)))
        return flow;

    snprintf(buff, sizeof(buff) - 1, "%u%d%u%d",
             dst_addr, dst_port, src_addr, src_port);

    if ((flow = g_hash_table_lookup(flow_tbl, buff)))
        return flow;

    flow = malloc(sizeof(pkt_flow_t));
    flow->src_addr = src_addr;
    flow->dst_addr = dst_addr;
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->time_start = time(NULL);
    flow->total_bytes_xferred = 0;
    flow->current_bytes = 0;
    flow->total_packets = 0;
    flow->bytes_per_sec = g_ptr_array_new();
    flow->key = strdup(buff);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    evtimer_set(&flow->timer, (void *) do_flow_transforms, flow);
    evtimer_add(&flow->timer, &tv);

    g_hash_table_insert(flow_tbl, flow->key, flow);

    return flow;
}


void
packet_handler(const unsigned char *arg,
               const struct pcap_pkthdr *hdr, const unsigned char *pkt)
{
    uint32_t        src_addr,
                    dst_addr;
    uint16_t        src_port,
                    dst_port;
    uint32_t        ip_proto;
    struct ip      *ip4;
    struct udphdr  *udp;
    struct tcphdr  *tcp;
    uint32_t        ip_hl;
    pkt_flow_t     *flow;

    ip4 = (struct ip *) (pkt + 14);

    if (ip4->ip_v != 4)
        return;

    src_addr = ip4->ip_src.s_addr;
    dst_addr = ip4->ip_dst.s_addr;
    ip_proto = ip4->ip_p;
    ip_hl = ip4->ip_hl * 4;

    switch (ip_proto) {
    case IPPROTO_UDP:
        udp = (struct udphdr *) ((unsigned char *) (ip4) + ip_hl);
        src_port = udp->uh_sport;
        dst_port = udp->uh_dport;
        break;
    case IPPROTO_TCP:
        tcp = (struct tcphdr *) ((unsigned char *) (ip4) + ip_hl);
        src_port = tcp->th_sport;
        dst_port = tcp->th_dport;
        break;
    default:
        LOG("Unknown protocol %d\n", ip_proto);
        return;
    }

    if (!(flow = find_flow(src_addr, src_port, dst_addr, dst_port)))
        return;

    LOG("blah: %u\n", hdr->len);
    flow->total_bytes_xferred += hdr->len;
    flow->current_bytes += hdr->len;
    flow->total_packets += 1;
}


void
ev_packet_handler(int sock, short which, void *data)
{
    pcap_dispatch(pcap_desc, 1, (void *) packet_handler, data);
}

void
pcap_init(void)
{
    struct bpf_program filterp;
    bpf_u_int32     maskp,
                    netp;
    char            errbuf[PCAP_ERRBUF_SIZE];
    int             pcap_fd;

    if (!(pcap_desc = pcap_open_live(iface, 512, 1, 0, errbuf)))
        goto pcap_err;

    if (bpf) {
        if (pcap_compile(pcap_desc, &filterp, bpf, 0, netp) < 0)
            goto pcap_err;

        pcap_setfilter(pcap_desc, &filterp);
    }

    if (pcap_setnonblock(pcap_desc, 1, errbuf) < 0)
        goto pcap_err;

    if ((pcap_fd = pcap_get_selectable_fd(pcap_desc)) <= 0)
        goto pcap_err;

    event_set(&pcap_event, pcap_fd, EV_READ | EV_PERSIST,
              (void *) ev_packet_handler, NULL);
    event_add(&pcap_event, 0);
    return;

  pcap_err:
    LOG("PCap Error: %s\n", errbuf);
    return;
}

void
deal_with_bps_node(uint32_t * bytes, void *userdata)
{
    printf("  Bps: %u, Mbps: %u\n", *bytes, *bytes * 8 / 1024 / 1024);
    //free(bytes);
}

void
print_flow(pkt_flow_t * flow)
{
    uint32_t timediff;
    uint32_t Bps, Mbps;
    char sbuf[22];
    char dbuf[22];

    timediff = time(NULL) - flow->time_start;

    Bps = Mbps = 0;

    if (timediff)
    {
	Bps  = flow->total_bytes_xferred / timediff;
	Mbps = (flow->total_bytes_xferred / timediff) * 8 / 1024 / 1024;
    }

    snprintf(sbuf, 21, "%s:%d", 
	    inet_ntoa(*(struct in_addr *) &flow->src_addr),
	    ntohs(flow->src_port));
    snprintf(dbuf, 21, "%s:%d",
	    inet_ntoa(*(struct in_addr *) &flow->dst_addr),
	    ntohs(flow->dst_port));

    printf("%-21s %-21s ", sbuf, dbuf);
    printf("tp=%-10llu ", flow->total_packets);
    printf("tB=%-10llu ", flow->total_bytes_xferred);
    printf("Bps=%-10u ",  Bps); 
    printf("Mbps=%u ", Mbps); 

    if (detail) {
        printf("\n");
        g_ptr_array_foreach(flow->bytes_per_sec, (void*)deal_with_bps_node, NULL);
    } else printf("\n");

}

int
flow_cmp(void *ap, void *bp)
{
    pkt_flow_t     *a = *(pkt_flow_t **) ap;
    pkt_flow_t     *b = *(pkt_flow_t **) bp;

    if (a->total_bytes_xferred > b->total_bytes_xferred)
        return -1;
    if (a->total_bytes_xferred < b->total_bytes_xferred)
        return 1;

    return 0;
}

void
deal_with_flow(char *key, pkt_flow_t * flow, GArray * array)
{
    g_array_append_val(array, flow);
}

void
report(int sock, short which, void *data)
{
    struct timeval tv;
    GArray         *ordered_array;
    int             i;

    if (!quiet)
	printf("-- START %ld\n", time(NULL) - runtime);
    else 
	printf("\n");

    ordered_array = g_array_new(FALSE, FALSE, sizeof(pkt_flow_t *));
    g_hash_table_foreach(flow_tbl, (void *)deal_with_flow, ordered_array);
    g_array_sort(ordered_array, (void *)flow_cmp);

    for (i = 0; i < ordered_array->len; i++)
    {
	if (top_limit && i >= top_limit)
	    break;

	printf("%4d. ", i+1);
        print_flow(g_array_index(ordered_array, pkt_flow_t *, i));
    }

    g_hash_table_remove_all(flow_tbl);
    g_array_free(ordered_array, TRUE);

    tv.tv_usec = 0;
    tv.tv_sec  = runtime;

    evtimer_set(&stop_event, (void *)report, NULL);
    evtimer_add(&stop_event, &tv);

    if (!quiet)
	printf("-- END   %ld\n\n", (long int)time(NULL));
}

void exit_prog(int sig)
{
    signal(SIGINT, SIG_DFL);
    report(0, 0, NULL);
    exit(1);
}

int
main(int argc, char **argv)
{
    struct timeval  tv;
    globals_init();
    parse_args(argc, argv);
    event_init();
    pcap_init();

    tv.tv_sec = runtime;
    tv.tv_usec = 0;

    evtimer_set(&stop_event, (void *) report, NULL);
    evtimer_add(&stop_event, &tv);

    signal(SIGINT, exit_prog);

    event_loop(0);

    return 0;
}
