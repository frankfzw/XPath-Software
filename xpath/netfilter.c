#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "netfilter.h"
#include "routing.h"
#include "flow_table.h"
#include "path_table.h"
#include "path_group.h"
#include "net_util.h"
#include "params.h"

/* Flow Table */
extern struct xpath_flow_table ft;
/* Path Table */
extern struct xpath_path_table pt;
/* Path Group */
extern struct xpath_group_entry pg[XPATH_PATH_GROUP_SIZE];

/* NIC device name */
extern char *param_dev;
/* TCP port */
extern int param_port;

/* Netfilter hook for outgoing packets */
static struct nf_hook_ops xpath_nf_hook_out;
/* Netfilter hook for incoming packets */
static struct nf_hook_ops xpath_nf_hook_in;

/* Hook function for outgoing packets */
static unsigned int xpath_hook_func_out(const struct nf_hook_ops *ops,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
        struct iphdr *iph = ip_hdr(skb);
        struct iphdr tiph;	/* tunnel (outer) IP header */
        struct tcphdr *tcph;
        struct xpath_path_entry *path_ptr = NULL;
        u32 path_ip = 0;	/* IP address of the path */
	    u32 payload_len = 0;	/* tcp payload length */

        if (likely(out) && param_dev && strncmp(out->name, param_dev, IFNAMSIZ) != 0)
                return NF_ACCEPT;

        /* we only filter TCP packets */
        if (likely(iph) && iph->protocol == IPPROTO_TCP) {
		tcph = tcp_hdr(skb);
                if (param_port != 0 &&
                    ntohs(tcph->source) != param_port &&
                    ntohs(tcph->dest) != param_port)
                        return NF_ACCEPT;

		payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
		path_ptr = xpath_search_path_table(&pt, iph->daddr);

                /* no available path */
                if (unlikely(!path_ptr || path_ptr->num_paths == 0)) {
			xpath_modify_ip_header(iph, payload_len);
			return NF_ACCEPT;
		}

                /* Reduce MSS value in SYN packets */
                if (tcph->syn &&
                    unlikely(!xpath_reduce_tcp_mss(skb, sizeof(struct iphdr)))) {
                        xpath_debug_info("XPath: cannot modify MSS\n");
                        return NF_DROP;
                }

                switch (xpath_load_balancing) {
                        case ECMP:
			        path_ip = ecmp_routing(skb, path_ptr);
			        break;
                        case PRESTO:
			        path_ip = presto_routing(skb, path_ptr);
			        break;
                        case RPS:
                                path_ip = rps_routing(skb, path_ptr);
                                break;
                        case FLOWBENDER:
				path_ip = flowbender_routing(skb, path_ptr);
				break;
                        case LETFLOW:
                                path_ip = letflow_routing(skb, path_ptr);
                                break;
                        case TLB:
                                path_ip = tlb_routing(skb, path_ptr);
                                break;
                        default:
			        printk(KERN_INFO "XPath: unknown LB scheme %d\n",
                                                 xpath_load_balancing);
		}

                /* find path IP, then construct tunnel (outer) IP header */
		if (likely(path_ip > 0)) {
                        tiph.version = 4;
                        tiph.ihl = sizeof(struct iphdr) >> 2;
                        tiph.tot_len =  htons(ntohs(iph->tot_len) + \
                                        sizeof(struct iphdr));
                        tiph.id = iph->id;
                        tiph.frag_off = iph->frag_off;
                        tiph.protocol = IPPROTO_IPIP;
                        tiph.tos = iph->tos;
                        tiph.daddr = path_ip;
                        tiph.saddr = iph->saddr;
                        tiph.ttl = iph->ttl;
			xpath_modify_ip_header(&tiph, payload_len);

		/* cannot find path IP */
                } else {
			xpath_modify_ip_header(iph, payload_len);
			return NF_ACCEPT;
		}

                /* add tunnel (outer) IP header */
		if (unlikely(!xpath_ipip_encap(skb, &tiph, out))) {
                        xpath_debug_info("XPath: cannot add IP header\n");
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

static
unsigned int xpath_tlb_hook_func_in (const struct nf_hook_ops *ops,
                                     struct sk_buff *skb,
                                     const struct net_device *in,
                                     const struct net_device *out,
                                     int (*okfn)(struct sk_buff *))
{
    ktime_t now = ktime_get();
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct xpath_flow_entry f, *flow_ptr = NULL;
    struct xpath_path_entry *path_ptr = NULL;
	u32 ack_seq, prev_ack_seq, bytes_acked, bytes_ecn, sample_fraction;
    unsigned int path_group_id;
	unsigned long flags;
	unsigned int i, age_path_group_id;

    /* after decap outer IP header, we need to get the inner IP header */
	iph = ip_hdr(skb);
	/* we only handle TCP ACK packets */
	if (iph->protocol != IPPROTO_TCP || !(tcph = tcp_hdr(skb)) || !(tcph->ack))
		goto out;

	/* Note that the packet is from the reverse direction */
	xpath_set_flow_4tuple(&f, iph->daddr, iph->saddr, ntohs(tcph->dest), ntohs(tcph->source));
	if (unlikely(!(flow_ptr = xpath_search_flow_table(&ft, &f))))
		goto out;

	/* initialize ACK Seq */
	if (unlikely(flow_ptr->info.ack_seq == 0)) {
        flow_ptr->info.ack_seq = ntohl(tcph->ack_seq);
        goto out;
    }

    ack_seq = ntohl(tcph->ack_seq);
    /* It should be an effective ACK */
	if (unlikely(!seq_after(ack_seq, flow_ptr->info.ack_seq)))
		goto out;

    prev_ack_seq = flow_ptr->info.ack_seq;
    flow_ptr->info.ack_seq = ack_seq;

    /* we need to ensure that all bytes ACKed are sent in current path */
    if (!seq_after_eq(prev_ack_seq, flow_ptr->info.seq_prev_path))
        goto out;

    bytes_acked = ack_seq - prev_ack_seq;
    bytes_ecn = (tcph->ece) ? bytes_acked : 0;
    flow_ptr->info.bytes_acked += bytes_acked;
    flow_ptr->info.bytes_ecn += bytes_ecn;
    /* calculate per-flow ECN fraction */
    if (flow_ptr->info.bytes_acked > xpath_tlb_ecn_sample_bytes) {
        /* sample fraction <= 1024 */
        sample_fraction = (flow_ptr->info.bytes_ecn << 10) /
                           flow_ptr->info.bytes_acked;
        /* smooth = smooth * 0.25 + sample * 0.75 */
        flow_ptr->info.ecn_fraction = (flow_ptr->info.ecn_fraction +
                                       sample_fraction * 3) >> 2;
        flow_ptr->info.bytes_acked = 0;
        flow_ptr->info.bytes_ecn = 0;
    }

    if (!(path_ptr = xpath_search_path_table(&pt, iph->saddr)))
        goto out;

    if (unlikely(flow_ptr->info.path_index >= path_ptr->num_paths))
        goto out;

    path_group_id = path_ptr->path_group_ids[flow_ptr->info.path_index];
    if (unlikely(path_group_id >= XPATH_PATH_GROUP_SIZE))
        goto out;

    /* traverse all path groups and reset per-path-group state if long time no update */
    for (i = 0; i < path_ptr->num_paths; i++) {
        // don't age itself
        // if (i == flow_ptr->info.path_index)
        //     continue;
        age_path_group_id = path_ptr->path_group_ids[i];
        if (now.tv64 - pg[age_path_group_id].last_update_time.tv64 > 5000 *
	        (s64)xpath_tlb_ecn_sample_us) {
	            spin_lock_irqsave(&(pg[age_path_group_id].lock), flags);
	            pg[age_path_group_id].last_update_time = now;
	            if (pg[age_path_group_id].ecn_fraction > 256) {
	               	pg[age_path_group_id].ecn_fraction = (pg[age_path_group_id].ecn_fraction * 6) >> 3;
	            } else {
	               	pg[age_path_group_id].ecn_fraction = (pg[age_path_group_id].ecn_fraction * 10) >> 3;
	            }

			    if (pg[age_path_group_id].smooth_rtt_us > xpath_tlb_rtt_low_thresh) {
	               	pg[age_path_group_id].smooth_rtt_us = (pg[age_path_group_id].smooth_rtt_us * 6) >> 3;
	            } else {
	               	pg[age_path_group_id].smooth_rtt_us = (pg[age_path_group_id].smooth_rtt_us * 10) >> 3;
	            }
	            spin_unlock_irqrestore(&(pg[age_path_group_id].lock), flags);
	    }
    }

    spin_lock_irqsave(&(pg[path_group_id].lock), flags);
    pg[path_group_id].last_update_time = now;
    pg[path_group_id].bytes_acked += bytes_acked;
    pg[path_group_id].bytes_ecn += bytes_ecn;

    /* our measurement cycle is large enough */
    if (pg[path_group_id].bytes_acked > xpath_tlb_ecn_sample_bytes &&
        now.tv64 - pg[path_group_id].last_ecn_update_time.tv64 > 1000 *
        (s64)xpath_tlb_ecn_sample_us) {
            /* sample fraction <= 1024 */
            sample_fraction = (pg[path_group_id].bytes_ecn << 10) /
                               pg[path_group_id].bytes_acked;
            /* smooth = smooth * 0.25 + sample * 0.75 */
            // if (pg[path_group_id].bytes_acked > 30720) {
            pg[path_group_id].ecn_fraction = (pg[path_group_id].ecn_fraction +
                                    3 * sample_fraction) >> 2;
            // } else {
            //     pg[path_group_id].ecn_fraction = (pg[path_group_id].ecn_fraction + sample_fraction) >> 1;
            // }
            pg[path_group_id].bytes_acked = 0;
            pg[path_group_id].bytes_ecn = 0;
            pg[path_group_id].last_ecn_update_time = now;
    }

    spin_unlock_irqrestore(&(pg[path_group_id].lock), flags);

out:
    return NF_ACCEPT;
}

static
unsigned int xpath_clove_hook_func_in (const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
{
    ktime_t now = ktime_get();
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	struct xpath_flow_entry f, *flow_ptr = NULL;
    struct xpath_path_entry *path_ptr = NULL;
	u32 ack_seq, prev_ack_seq;
    unsigned int current_path_index = 0;
    unsigned int path_index = 0;
    unsigned int reduced_weight = 0;
    unsigned int total_weight = 0;

    /* after decap outer IP header, we need to get the inner IP header */
	iph = ip_hdr(skb);
	/* we only handle TCP ACK packets */
	if (iph->protocol != IPPROTO_TCP || !(tcph = tcp_hdr(skb)) || !(tcph->ack))
		goto out;

	/* Note that the packet is from the reverse direction */
	xpath_set_flow_4tuple(&f, iph->daddr, iph->saddr, ntohs(tcph->dest), ntohs(tcph->source));
	if (unlikely(!(flow_ptr = xpath_search_flow_table(&ft, &f))))
		goto out;

	/* initialize ACK Seq */
	if (unlikely(flow_ptr->info.ack_seq == 0)) {
        flow_ptr->info.ack_seq = ntohl(tcph->ack_seq);
        goto out;
    }

    ack_seq = ntohl(tcph->ack_seq);
    /* It should be an effective ACK */
	if (unlikely(!seq_after(ack_seq, flow_ptr->info.ack_seq)))
		goto out;

    prev_ack_seq = flow_ptr->info.ack_seq;
    flow_ptr->info.ack_seq = ack_seq;

    /* we need to ensure that all bytes ACKed are sent in current path */
    if (!seq_after_eq(prev_ack_seq, flow_ptr->info.seq_prev_path))
        goto out;

    if (!tcph->ece)
        goto out;

    if (!(path_ptr = xpath_search_path_table(&pt, iph->saddr)))
        goto out;

    current_path_index = flow_ptr->info.path_index;

    if (ktime_to_us(ktime_sub(now, path_ptr->last_weight_reduce_times[current_path_index]))
            <= xpath_clove_reduce_gap)
        goto out;
    path_ptr->last_weight_reduce_times[current_path_index] = now;

    reduced_weight = path_ptr->weights[current_path_index] / 3;
    path_ptr->weights[current_path_index] -= reduced_weight;

    for (path_index = 0; path_index < path_ptr->num_paths; ++path_index) {
        if (path_index != current_path_index) {
            path_ptr->weights[path_index] += (reduced_weight / (path_ptr->num_paths - 1));
        }
        total_weight += path_ptr->weights[path_index];
    }

    if (total_weight - path_ptr->num_paths * xpath_clove_init_weight > xpath_clove_weight_reset_threshold ||
            path_ptr->num_paths * xpath_clove_init_weight - total_weight > xpath_clove_weight_reset_threshold) {
        for (path_index = 0; path_index < path_ptr->num_paths; ++path_index) {
            path_ptr->weights[path_index] =
                path_ptr->weights[path_index] * (path_ptr->num_paths * xpath_clove_init_weight) / total_weight;
        }
    }

out:
    return NF_ACCEPT;

}


/* Hook function for incoming packets */
static unsigned int xpath_hook_func_in(const struct nf_hook_ops *ops,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);

	if (likely(in) && param_dev && strncmp(in->name, param_dev, IFNAMSIZ) != 0)
        goto out;

	if (unlikely(!iph) || iph->protocol != IPPROTO_IPIP)
		goto out;

	if (unlikely(!xpath_ipip_decap(skb))) {
		printk(KERN_INFO "XPath: cannot remove IP header\n");
		goto out;
	}

	/* Only TLB and CLOVE needs to update some states in RX path */
    if (xpath_load_balancing == TLB) {
        return xpath_tlb_hook_func_in (ops, skb, in, out, okfn);
    } else if (xpath_load_balancing == CLOVE) {
        return xpath_clove_hook_func_in (ops, skb, in, out, okfn);
    } else {
        goto out;
    }

out:
    return NF_ACCEPT;

}

/* Install Netfilter hooks. Return true if it succeeds */
bool xpath_netfilter_init(void)
{
        /* register outgoing Netfilter hook */
        xpath_nf_hook_out.hook = xpath_hook_func_out;
        xpath_nf_hook_out.hooknum = NF_INET_POST_ROUTING;
        xpath_nf_hook_out.pf = PF_INET;
        xpath_nf_hook_out.priority = NF_IP_PRI_FIRST;

        if (unlikely(nf_register_hook(&xpath_nf_hook_out))) {
                printk(KERN_INFO "XPath: cannot register TX Netfilter hook\n");
                return false;
        }

        /* register incoming Netfilter hook */
        xpath_nf_hook_in.hook = xpath_hook_func_in;
        xpath_nf_hook_in.hooknum = NF_INET_PRE_ROUTING;
        xpath_nf_hook_in.pf = PF_INET;
        xpath_nf_hook_in.priority = NF_IP_PRI_FIRST;

        if (unlikely(nf_register_hook(&xpath_nf_hook_in))) {
                printk(KERN_INFO "XPath: cannot register RX Netfilter hook\n");
                return false;
        }

        return true;
}

/* Uninstall Netfilter hooks */
void xpath_netfilter_exit(void)
{
        nf_unregister_hook(&xpath_nf_hook_out);
        nf_unregister_hook(&xpath_nf_hook_in);
}
