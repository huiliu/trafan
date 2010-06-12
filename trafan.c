#include <stdio.h>

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
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

#define LOG(x, s...) do { \
        if (!debug) { break; } \
        time_t t = time(NULL); \
        char  *d = ctime(&t); \
        fprintf(stderr, "%.*s %s[%d] %s(): ", \
                (int)strlen(d) - 1, d, __FILE__, \
                __LINE__, __FUNCTION__); \
        fprintf(stderr, x, ## s); \
} while (0);

typedef struct pkt_flow_aggregate {
    uint32_t address;
    uint32_t packets;
    uint8_t  top_level : 4;
    uint8_t  protocol : 4;
    uint64_t bytes_xferred;
    /*
     * tree of pkt_flow_aggregates
     */
    GTree *talked_to;
} pkt_flow_aggregate_t;

typedef struct pkt_flow {
    gpointer     key;
    uint32_t     src_addr;
    uint32_t     dst_addr;
    uint16_t     src_port;
    uint16_t     dst_port;
    uint32_t     time_start;
    uint64_t     total_bytes_xferred;
    uint32_t     current_bytes;
    uint64_t     total_packets;
    uint8_t      proto;
    GPtrArray   *bytes_per_sec;
    struct event timer;
} pkt_flow_t;

typedef enum {
    ORDER_BY_TOTAL_BYTES,
    ORDER_BY_MBPS,
    ORDER_BY_BPS,
    ORDER_BY_TOTAL_PACKETS,
    ORDER_BY_DESTINATION_COUNT
} order_by_t;

struct event pcap_event;
struct event stop_event;
int          debug;
int          detail;
int          runtime;
int          top_limit;
int          report_top_limit;
int          report_dest_limit;
int          stop_count;
int          count_stop;
char        *bpf;
char        *iface;
int          quiet;
uint64_t     global_bytes_xferred;
uint32_t     global_time;
int          reverse_order;
order_by_t   order_by;
order_by_t   aggregate_order_by;
char        *pcap_in_file;

/*
 * if the aggregate option is set, we don't use a flow, but we see a per
 * host statistics
 */
uint32_t    aggregate_flows;
pcap_t     *pcap_desc;
GHashTable *flow_tbl;
GTree      *aggregates;

void            free_flow_tbl(pkt_flow_t * flow);

void
globals_init(void)
{
    quiet = 0;
    debug = 0;
    bpf = NULL;
    iface = "eth0";
    pcap_desc = NULL;
    runtime = 1;
    detail = 0;
    top_limit = 0;
    reverse_order = 0;
    report_top_limit = 0;
    report_dest_limit = 0;
    stop_count = 0;
    aggregate_flows = 0;
    global_bytes_xferred = 0;
    aggregates = NULL;
    pcap_in_file = NULL;
    order_by = ORDER_BY_TOTAL_BYTES;
    aggregate_order_by = ORDER_BY_TOTAL_BYTES;

    flow_tbl = g_hash_table_new_full(g_str_hash, g_str_equal,
                                     NULL, (void *)free_flow_tbl);
}

void
free_flow_key(gpointer key)
{
    free(key);
}

void
free_bps_node(uint32_t * a, void *d)
{
    free(a);
}

void
free_flow_tbl(pkt_flow_t * flow)
{
    free(flow->key);

    if (pcap_in_file == NULL) {
        evtimer_del(&flow->timer);
    }

    if (detail) {
        g_ptr_array_foreach(flow->bytes_per_sec,
                            (void *)free_bps_node, NULL);
        g_ptr_array_free(flow->bytes_per_sec, TRUE);
    }

    free(flow);
}

static int
addr_cmp(const void *a, const void *b)
{
    if (*(uint32_t *)a < *(uint32_t *)b) {
        return(-1);
    }

    if (*(uint32_t *)a > *(uint32_t *)b) {
        return(1);
    }

    return(0);
}

void
parse_args(int argc, char **argv)
{
    int   c;
    char *tok;

    while ((c = getopt(argc, argv, "nhRqL:l:di:f:r:Dac:O:o:p:")) != -1) {
        switch (c) {

            case 'D':
                debug++;
                break;
            case 'p':
                pcap_in_file = optarg;
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
		if (*optarg == '-')
		    runtime = 0x7FFFFFFF;
		else
		    runtime = atoi(optarg);
		printf("%d\n", runtime);
                break;
            case 'l':
                top_limit = atoi(optarg);
                break;
            case 'L':
                tok = strtok(optarg, ":");
                report_top_limit = atoi(tok);
                tok = strtok(NULL, ":");
                if (tok) {
                    report_dest_limit = atoi(tok);
                }
                break;
            case 'q':
                quiet++;
                break;
            case 'a':
                aggregate_flows = 1;
                break;
            case 'c':
                stop_count = atoi(optarg);
                count_stop = stop_count;
                break;
            case 'O':
                switch (*optarg) {
                    case 'p':
                        order_by = ORDER_BY_TOTAL_PACKETS;
                        break;
                    case 'B':
                        order_by = ORDER_BY_TOTAL_BYTES;
                        break;
                    case 'b':
                        order_by = ORDER_BY_BPS;
                        break;
                    case 'm':
                        order_by = ORDER_BY_MBPS;
                        break;
                    default:
                        printf
                              ("Unknown ordering %c, using default (order by total bytes)\n",
                              *optarg);
                        break;
                }
                break;
            case 'o':
                switch (*optarg) {
                    case 'p':
                        aggregate_order_by = ORDER_BY_TOTAL_PACKETS;
                        break;
                    case 'B':
                        aggregate_order_by = ORDER_BY_TOTAL_BYTES;
                        break;
                    case 'h':
                        aggregate_order_by = ORDER_BY_DESTINATION_COUNT;
                        break;
                }
                break;
            case 'R':
                aggregates = g_tree_new((GCompareFunc)addr_cmp);
                break;
            case 'n':
                reverse_order = 1;
                break;
            case 'h':
            default:
                printf("Usage: %s [opts]\n"
                       "   -D: debug\n"
                       "   -i  <iface>\n"
                       "   -p  <infile>: an offline pcap file\n"
                       "   -f  <bpf filter>\n"
                       "   -l  <limit to top x>\n"
                       "   -L  <aggregate report top X>:<aggregate report destination top X>\n"
                       "   -d: second-by-second details\n"
                       "   -q: quiet\n"
                       "   -r  <runtime>\n"
                       "   -a: aggregate (disable flows)\n"
                       "   -R: display aggregate flow report at exit\n"
                       "  -Op: Order by total packets\n"
                       "  -Ob: Order by Bps\n"
                       "  -Om: Order by Mbps\n"
                       "  -OB: Order by total bytes (default)\n"
                       "  -op: Order aggregation report by packets\n"
                       "  -oB: Order aggregation report by total_bytes\n"
                       "  -oh: Order aggregation report by distinct dest host counts\n"
                       "   -n: Reverse ordering (small to large)\n"
                       "   -c  <num>: exit after count reports.\n", argv[0]);
                exit(1);
        } /* switch */
    }
} /* parse_args */

void
do_flow_transforms(int sock, short which, pkt_flow_t * flow)
{
    uint32_t      *bytes_ps;
    struct timeval tv;

    LOG("Doing transform for %u:%d -> %u:%d (%u bytes)\n",
        flow->src_addr, ntohs(flow->src_port),
        flow->dst_addr, ntohs(flow->dst_port), flow->current_bytes);

    if (detail) {
        bytes_ps = malloc(sizeof(uint32_t));

        memcpy(bytes_ps, &flow->current_bytes, sizeof(uint32_t));
        g_ptr_array_add(flow->bytes_per_sec, bytes_ps);
    }

    flow->current_bytes = 0;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (pcap_in_file == NULL) {
        evtimer_set(&flow->timer, (void *)do_flow_transforms, flow);
        evtimer_add(&flow->timer, &tv);
    }
}

pkt_flow_aggregate_t *
do_aggregate(uint32_t src_addr, uint32_t dst_addr, uint32_t bytes,
             uint8_t proto)
{
    pkt_flow_aggregate_t *found,
    *dst_found;

    if (aggregates == NULL) {
        return(NULL);
    }

    /*
     * check the aggregates hash for the src_addr
     */
    found = g_tree_lookup(aggregates, &src_addr);

    if (!found) {
        found = malloc(sizeof(pkt_flow_aggregate_t));

        found->address = src_addr;
        found->packets = 0;
        found->bytes_xferred = 0;
        found->top_level = 1;
        found->talked_to = g_tree_new((GCompareFunc)addr_cmp);

        g_tree_insert(aggregates, &found->address, found);
    }

    found->bytes_xferred += bytes;
    found->packets += 1;

    dst_found = g_tree_lookup(found->talked_to, &dst_addr);

    if (!dst_found) {
        /*
         * create a new destination node, then slap it into the founds
         * talked_to tree
         */
        dst_found = malloc(sizeof(pkt_flow_aggregate_t));

        dst_found->address = dst_addr;
        dst_found->packets = 0;
        dst_found->bytes_xferred = 0;
        dst_found->top_level = 0;
        dst_found->talked_to = NULL;

        g_tree_insert(found->talked_to, &dst_found->address, dst_found);
    }

    dst_found->packets += 1;
    dst_found->bytes_xferred += bytes;
    dst_found->protocol = proto;

    return(found);
} /* do_aggregate */

pkt_flow_t     *
find_flow(uint32_t src_addr, uint16_t src_port,
          uint32_t dst_addr, uint16_t dst_port)
{
    char           buff[10 + 5 + 10 + 5 + 1];
    pkt_flow_t    *flow;
    struct timeval tv;
    uint16_t       src_port_copy,
                   dst_port_copy;
    uint32_t       dst_addr_copy;

    memset(buff, 0, sizeof(buff));

    src_port_copy = src_port;
    dst_port_copy = dst_port;
    dst_addr_copy = dst_addr;

    if (aggregate_flows) {
        /*
         * turn off the destination stuff, we only care about the total
         * for that host
         */
        dst_addr = 0;
        dst_port = 0;
        src_port = 0;
    } else {
        /*
         * if aggregation is turned on, we only care about one side of the
         * conversation
         */
        snprintf(buff, sizeof(buff) - 1, "%u%d%u%d",
                 src_addr, src_port, dst_addr, dst_port);

        if ((flow = g_hash_table_lookup(flow_tbl, buff))) {
            return(flow);
        }
    }

    snprintf(buff, sizeof(buff) - 1, "%u%d%u%d",
             dst_addr, dst_port, src_addr, src_port);

    if ((flow = g_hash_table_lookup(flow_tbl, buff))) {
        return(flow);
    }

    flow = malloc(sizeof(pkt_flow_t));
    flow->src_addr = src_addr;
    flow->dst_addr = dst_addr;
    flow->src_port = src_port;
    flow->dst_port = dst_port;
    flow->time_start = time(NULL);
    flow->total_bytes_xferred = 0;
    flow->current_bytes = 0;
    flow->total_packets = 0;
    flow->key = strdup(buff);

    if (detail) {
        flow->bytes_per_sec = g_ptr_array_new();
    }

    if (pcap_in_file == NULL) {
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        evtimer_set(&flow->timer, (void *)do_flow_transforms, flow);
        evtimer_add(&flow->timer, &tv);
    }

    g_hash_table_insert(flow_tbl, flow->key, flow);

    return(flow);
} /* find_flow */


void
packet_handler(const unsigned char *arg,
               const struct pcap_pkthdr *hdr, const unsigned char *pkt)
{
    uint32_t       src_addr,
                   dst_addr;
    uint16_t       src_port,
                   dst_port;
    uint32_t       ip_proto;
    struct ip     *ip4;
    struct udphdr *udp;
    struct tcphdr *tcp;
    uint32_t       ip_hl;
    pkt_flow_t    *flow;

    if (hdr->caplen < sizeof(struct ip) + 14) {
        return;
    }

    ip4 = (struct ip *)(pkt + 14);

    if (ip4->ip_v != 4) {
        return;
    }

    src_addr = ip4->ip_src.s_addr;
    dst_addr = ip4->ip_dst.s_addr;
    ip_proto = ip4->ip_p;
    ip_hl = ip4->ip_hl * 4;

    switch (ip_proto) {
        case IPPROTO_UDP:
            if (hdr->caplen < sizeof(struct ip) + 14 +
                ip_hl + sizeof(struct udphdr)) {
                return;
            }

            udp = (struct udphdr *)((unsigned char *)(ip4) + ip_hl);
            src_port = udp->uh_sport;
            dst_port = udp->uh_dport;
            break;
        case IPPROTO_TCP:
            if (hdr->caplen < sizeof(struct ip) + 14 +
                ip_hl + sizeof(struct tcphdr)) {
                return;
            }

            tcp = (struct tcphdr *)((unsigned char *)(ip4) + ip_hl);
            src_port = tcp->th_sport;
            dst_port = tcp->th_dport;
            break;
        default:
            src_port = 0;
            dst_port = 0;
            return;

    } /* switch */

    if (!(flow = find_flow(src_addr, src_port, dst_addr, dst_port))) {
        return;
    }

    LOG("blah: %u\n", hdr->len);
    flow->total_bytes_xferred += hdr->len;
    flow->current_bytes += hdr->len;
    flow->total_packets += 1;
    flow->proto = ip_proto;

    if (aggregates) {
        do_aggregate(src_addr, dst_addr, hdr->len, ip_proto);
    }

    global_bytes_xferred += hdr->len;
} /* packet_handler */


void
ev_packet_handler(int sock, short which, void *data)
{
    pcap_dispatch(pcap_desc, 1, (void *)packet_handler, data);
}

void
pcap_init(void)
{
    struct bpf_program filterp;
    bpf_u_int32        maskp,
                       netp;
    char               errbuf[PCAP_ERRBUF_SIZE];
    int                pcap_fd;

    if (pcap_in_file) {
        pcap_desc = pcap_open_offline(pcap_in_file, errbuf);
    } else {
        pcap_desc = pcap_open_live(iface, 90, 1, 0, errbuf);
    }

    if (pcap_desc == NULL) {
        goto pcap_err;
    }

    if (bpf) {
        if (pcap_compile(pcap_desc, &filterp, bpf, 0, netp) < 0) {
            goto pcap_err;
        }

        pcap_setfilter(pcap_desc, &filterp);
    }

    if (pcap_setnonblock(pcap_desc, 1, errbuf) < 0) {
        goto pcap_err;
    }

    if ((pcap_fd = pcap_get_selectable_fd(pcap_desc)) <= 0) {
        goto pcap_err;
    }


    if (pcap_in_file == NULL) {
        event_set(&pcap_event, pcap_fd, EV_READ | EV_PERSIST,
                  (void *)ev_packet_handler, NULL);
        event_add(&pcap_event, 0);
    }
    return;

pcap_err:
    LOG("PCap Error: %s\n", errbuf);
    return;
} /* pcap_init */

void
deal_with_bps_node(uint32_t * bytes, void *userdata)
{
    printf("      Bps=%-10u Mbps=%-10u\n", *bytes,
           *bytes * 8 / 1024 / 1024);
}

void
calculate_ps(uint32_t time_start, uint64_t xferred,
             uint32_t * in_Mbps, uint32_t * in_Bps)
{
    uint32_t timediff;
    uint32_t Bps,
             Mbps;

    Bps = Mbps = 0;

    if (pcap_in_file == NULL) {
        timediff = time(NULL) - time_start;
    } else {
        timediff = runtime;
    }

    if (timediff) {
        Bps = xferred / timediff;
        Mbps = (xferred / timediff) * 8 / 1024 / 1024;
    }

    *in_Mbps = Mbps;
    *in_Bps = Bps;
}

void
print_flow(pkt_flow_t * flow)
{
    uint32_t Bps,
             Mbps;
    char     sbuf[22];
    char     dbuf[22];

    calculate_ps(flow->time_start, flow->total_bytes_xferred, &Mbps, &Bps);

    snprintf(sbuf, 21, "%s:%d",
             inet_ntoa(*(struct in_addr *)&flow->src_addr),
             ntohs(flow->src_port));
    snprintf(dbuf, 21, "%s:%d",
             inet_ntoa(*(struct in_addr *)&flow->dst_addr),
             ntohs(flow->dst_port));

    printf("%-21s %-21s ", sbuf, dbuf);
    printf("p=%-2d ", flow->proto);
    printf("tp=%-10llu ", flow->total_packets);
    printf("tB=%-10llu ", flow->total_bytes_xferred);
    printf("Bps=%-10u ", Bps);
    printf("Mbps=%u ", Mbps);

    if (detail) {
        printf("\n");
        g_ptr_array_foreach(flow->bytes_per_sec,
                            (void *)deal_with_bps_node, NULL);
    } else{
        printf("%s", top_limit != 1 ? "\n" : "");
    }

}

int
aggregate_cmp(void *ap, void *bp)
{
    uint64_t              var1,
                          var2;
    order_by_t            order;
    pkt_flow_aggregate_t *a;
    pkt_flow_aggregate_t *b;

    if (reverse_order) {
        a = *(pkt_flow_aggregate_t **)bp;
        b = *(pkt_flow_aggregate_t **)ap;
    } else {
        a = *(pkt_flow_aggregate_t **)ap;
        b = *(pkt_flow_aggregate_t **)bp;
    }

    order = aggregate_order_by;

    if (!a->top_level) {
        order = ORDER_BY_TOTAL_BYTES;
    }

    switch (order) {
        case ORDER_BY_TOTAL_BYTES:
            var1 = a->bytes_xferred;
            var2 = b->bytes_xferred;
            break;
        case ORDER_BY_TOTAL_PACKETS:
            var1 = a->packets;
            var2 = b->packets;
            break;
        case ORDER_BY_DESTINATION_COUNT:
            var1 = g_tree_nnodes(a->talked_to);
            var2 = g_tree_nnodes(b->talked_to);
            break;
        default:
            var1 = 0;
            var2 = 0;
    }
    if (var1 > var2) {
        return(-1);
    }
    if (var1 < var2) {
        return(1);
    }

    return(0);
} /* aggregate_cmp */

int
flow_cmp(void *ap, void *bp)
{
    pkt_flow_t *a;              /* = *(pkt_flow_t **) ap; */
    pkt_flow_t *b;              /* = *(pkt_flow_t **) bp; */
    uint64_t    var1,
                var2;
    uint32_t    Mbps,
                Bps;

    if (reverse_order) {
        a = *(pkt_flow_t **)bp;
        b = *(pkt_flow_t **)ap;
    } else {
        a = *(pkt_flow_t **)ap;
        b = *(pkt_flow_t **)bp;
    }

    Mbps = Bps = 0;

    switch (order_by) {
        case ORDER_BY_TOTAL_BYTES:
            var1 = a->total_bytes_xferred;
            var2 = b->total_bytes_xferred;
            break;
        case ORDER_BY_MBPS:
            calculate_ps(a->time_start, a->total_bytes_xferred, &Mbps, &Bps);

            var1 = Mbps;

            calculate_ps(b->time_start, b->total_bytes_xferred, &Mbps, &Bps);

            var2 = Mbps;
            break;
        case ORDER_BY_BPS:
            calculate_ps(a->time_start, a->total_bytes_xferred, &Mbps, &Bps);

            var1 = Bps;

            calculate_ps(b->time_start, b->total_bytes_xferred, &Mbps, &Bps);

            var2 = Bps;
            break;
        case ORDER_BY_TOTAL_PACKETS:
            var1 = a->total_packets;
            var2 = b->total_packets;
            break;
        default:
            var1 = 0;
            var2 = 0;
            break;
    } /* switch */

    if (var1 > var2) {
        return(-1);
    }
    if (var1 < var2) {
        return(1);
    }

    return(0);
} /* flow_cmp */

void
deal_with_flow(char *key, void *flow, GArray * array)
{
    g_array_append_val(array, flow);
}

gboolean
order_aggregates(uint32_t * addr,
                 pkt_flow_aggregate_t * node, GArray * array)
{
    g_array_append_val(array, node);
    return(FALSE);
}

int
report_talker(GArray * array)
{
    int i;

    for (i = 0; i < array->len; i++) {
        pkt_flow_aggregate_t *node;

        if (report_dest_limit && i >= report_dest_limit) {
            break;
        }

        node = g_array_index(array, pkt_flow_aggregate_t *, i);

        printf("%4d. %-16s p=%-2d tp=%-12u tB=%-20llu\n", i + 1,
               inet_ntoa(*(struct in_addr *)&node->address),
               node->protocol, node->packets, node->bytes_xferred);

        free(node);
    }
}

void
report_aggregate(GArray * array)
{
    int i;

    for (i = 0; i < array->len; i++) {
        pkt_flow_aggregate_t *node;
        GArray               *ordered_array;

        if (report_top_limit && i >= report_top_limit) {
            break;
        }

        node = g_array_index(array, pkt_flow_aggregate_t *, i);

        printf("%-27s tp=%-12u tB=%-20llu dh=%d\n",
               inet_ntoa(*(struct in_addr *)&node->address),
               node->packets, node->bytes_xferred,
               g_tree_nnodes(node->talked_to));

        if (quiet < 2) {
            ordered_array = g_array_new(FALSE, FALSE,
                                        sizeof(pkt_flow_aggregate_t *));

            g_tree_foreach(node->talked_to,
                           (GTraverseFunc)order_aggregates,
                           ordered_array);

            g_array_sort(ordered_array, (void *)aggregate_cmp);

            report_talker(ordered_array);
            g_array_free(ordered_array, TRUE);
            printf("\n");
        }

        g_tree_destroy(node->talked_to);
        free(node);
    }
}

void
report_aggregates(void)
{
    GArray *ordered_array;

    if (aggregates == NULL) {
        return;
    }

    printf
                  ("\n-[ Aggregate report ]------------------------------------------------\n");
    ordered_array =
        g_array_new(FALSE, FALSE, sizeof(pkt_flow_aggregate_t *));

    g_tree_foreach(aggregates,
                   (GTraverseFunc)order_aggregates, ordered_array);

    g_array_sort(ordered_array, (void *)aggregate_cmp);

    report_aggregate(ordered_array);
    g_array_free(ordered_array, TRUE);
    g_tree_destroy(aggregates);
}

void
report(int sock, short which, void *data)
{
    struct timeval tv;
    GArray        *ordered_array;
    int            i;

    if (!quiet) {
        uint32_t global_Bps,
                 global_Mbps;

        calculate_ps(global_time, global_bytes_xferred,
                     &global_Mbps, &global_Bps);

        printf("-- START %ld [ tB=%llu Bps=%u Mbps=%u ]\n",
               time(NULL) - runtime, global_bytes_xferred,
               global_Bps, global_Mbps);

        global_bytes_xferred = 0;
        global_time = time(NULL);
    } else{
        printf("%s", g_hash_table_size(flow_tbl) ? "\n" : "");
    }

    ordered_array = g_array_new(FALSE, FALSE, sizeof(pkt_flow_t *));
    g_hash_table_foreach(flow_tbl, (void *)deal_with_flow, ordered_array);
    g_array_sort(ordered_array, (void *)flow_cmp);

    for (i = 0; i < ordered_array->len; i++) {
        if (top_limit && i >= top_limit) {
            break;
        }

        printf("%4d. ", i + 1);
        print_flow(g_array_index(ordered_array, pkt_flow_t *, i));
    }

    g_hash_table_remove_all(flow_tbl);
    g_array_free(ordered_array, TRUE);

    if (pcap_in_file == NULL) {
        tv.tv_usec = 0;
        tv.tv_sec = runtime;

        evtimer_set(&stop_event, (void *)report, NULL);
        evtimer_add(&stop_event, &tv);
    }

    if (!quiet) {
        struct pcap_stat ps;

        pcap_stats(pcap_desc, &ps);
        printf("-- END   %ld [ pcap_recvd=%d pcap_dropped=%d ]\n\n",
               (long int)time(NULL), ps.ps_recv, ps.ps_drop);
    }

    if (stop_count && --count_stop <= 0) {
        report_aggregates();
        exit(1);
    }
} /* report */

void
exit_prog(int sig)
{
    signal(SIGINT, SIG_DFL);
    report(0, 0, NULL);
    report_aggregates();
    exit(1);
}

void
offline_reset_flows(gpointer key, pkt_flow_t * flow, gpointer args)
{
    do_flow_transforms(0, 0, flow);
}

void
do_offline_analysis(void)
{
    struct pcap_pkthdr   hdr;
    const unsigned char *pkt;
    uint32_t             reset_flow_test_start;
    uint32_t             report_test_start;

    reset_flow_test_start = time(NULL);
    report_test_start = 0;

    while ((pkt = pcap_next(pcap_desc, &hdr)) != NULL) {
        packet_handler(NULL, &hdr, pkt);

        if (report_test_start == 0) {
            /*
             * we've never recv'd any packets, set this to our first
             * header ts
             */
            report_test_start = hdr.ts.tv_sec;
        }

        if (reset_flow_test_start == 0) {
            reset_flow_test_start = hdr.ts.tv_sec;
        }

        if (time(NULL) > reset_flow_test_start) {
            /*
             * it's been one second, reset our offline flows
             */
            g_hash_table_foreach(flow_tbl, (GHFunc)offline_reset_flows,
                                 NULL);
            reset_flow_test_start = time(NULL);
        }

        if (hdr.ts.tv_sec - report_test_start >= runtime) {
            report_test_start = 0;
            report(0, 0, NULL);
        }
    }

    report(0, 0, NULL);
}

int
main(int argc, char **argv)
{
    struct timeval tv;

    globals_init();

    parse_args(argc, argv);

    event_init();
    pcap_init();

    signal(SIGINT, exit_prog);

    if (pcap_in_file) {
        do_offline_analysis();
        return(0);
    }


    tv.tv_sec = runtime;
    tv.tv_usec = 0;

    evtimer_set(&stop_event, (void *)report, NULL);
    evtimer_add(&stop_event, &tv);

    event_loop(0);
    return(0);
}
