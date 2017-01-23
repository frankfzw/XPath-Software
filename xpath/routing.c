#include <linux/netfilter.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/ktime.h>
#include <linux/netfilter_ipv4.h>

#include "routing.h"
#include "flow_table.h"
#include "path_group.h"
#include "net_util.h"
#include "params.h"

struct dctcp {
	u32 acked_bytes_ecn;
	u32 acked_bytes_total;
	u32 prior_snd_una;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 delayed_ack_reserved;
	u16 num_cong_rtts;
	u16 reroute;
};

/* Flow Table */
extern struct xpath_flow_table ft;
/* Path Table */
extern struct xpath_path_table pt;
/* Path Group */
extern struct xpath_group_entry pg[XPATH_PATH_GROUP_SIZE];

u32 ecmp_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
					     iph->daddr,
					     tcph->source,
					     tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 presto_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        u32 payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
        u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
		                             iph->daddr,
					     tcph->source,
                                             tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

        xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
        f.info.path_index = path_index;

        if (tcph->syn && unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
		xpath_debug_info("XPath: insert flow fails\n");

        } else if ((tcph->fin || tcph->rst) && !xpath_delete_flow_table(&ft, &f)) {
		xpath_debug_info("XPath: delete flow fails\n");

        } else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
                path_index = flow_ptr->info.path_index;
		/* exceed flowcell threshold */
                if (flow_ptr->info.bytes_sent + payload_len > xpath_flowcell_thresh) {
                        flow_ptr->info.bytes_sent = payload_len;
                        if (++path_index >= path_ptr->num_paths)
                                path_index -= path_ptr->num_paths;
                        flow_ptr->info.path_index = path_index;
                } else {
                        flow_ptr->info.bytes_sent += payload_len;
                }
        }

        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 rps_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        u32 path_index = (u32)atomic_inc_return(&path_ptr->current_path);
	path_index = path_index % path_ptr->num_paths;
        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 flowbender_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph = tcp_hdr(skb);
        struct dctcp *ca = inet_csk_ca(skb->sk);
	u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
		                             iph->daddr,
					     tcph->source,
                                             tcph->dest);
        /* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
        u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;

        if (likely(ca)) {
                path_index = (path_index + ca->reroute) % path_ptr->num_paths;
                if (xpath_enable_debug)
                        printk(KERN_INFO "Reroute %hu\n", ca->reroute);
        }

        /* Get path IP based on path index */
        return path_ptr->path_ips[path_index];
}

u32 letflow_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
	ktime_t now = ktime_get();
	/* When all bits of the packet have been pushed to the link */
	ktime_t pkt_tx_time = ktime_add_ns(now, xpath_l2t_ns(skb->len));
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	//u32 payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
					     iph->daddr,
					     tcph->source,
					     tcph->dest);

	/* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
	u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

	xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
	f.info.path_index = path_index;
	f.info.last_tx_time = pkt_tx_time;

	if (tcph->syn && unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
		xpath_debug_info("XPath: insert flow fails\n");

	} else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
		path_index = flow_ptr->info.path_index;
		/* delete the flow entry */
		if (tcph->fin || tcph->rst) {
			xpath_delete_flow_table(&ft, &f);
			goto out;
		}
		/* flowlet */
		if (ktime_to_us(ktime_sub(now, flow_ptr->info.last_tx_time))
		    > xpath_flowlet_thresh) {
			if (++path_index >= path_ptr->num_paths)
				path_index = 0;
			flow_ptr->info.path_index = path_index;
			flow_ptr->info.num_flowlet++;
		}
		flow_ptr->info.last_tx_time = pkt_tx_time;
	}

out:
	/* Get path IP based on path index */
	return path_ptr->path_ips[path_index];
}

/* generate a random number in [0, range). range <= 255 */
static inline u8 random_number(u8 range)
{
	u8 result = 0;

	if (unlikely(range == 0))
		goto out;

	get_random_bytes(&result, sizeof(result));
	while (result >= range)
		result -= range;

out:
	return result;
}

u32 tlb_routing(const struct sk_buff *skb, struct xpath_path_entry *path_ptr)
{
	u16 i, path_group_id;
	// const struct tcp_sock *tp = tcp_sk(skb->sk);
	// unsigned long flags;
	bool reroute = false;
	ktime_t now = ktime_get();
	/* When all bits of the packet have been pushed to the link */
	ktime_t pkt_tx_time = ktime_add_ns(now, xpath_l2t_ns(skb->len));
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *tcph = tcp_hdr(skb);
	u32 payload_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	u32 seq = (u32)ntohl(tcph->seq) + (payload_len > 1)? payload_len - 1 : 0;
	u16 hash_key = xpath_flow_hash_crc16(iph->saddr,
					     iph->daddr,
					     tcph->source,
					     tcph->dest);

	/* hash_key_space = 1 << 16; path_index = hash_key * path_ptr->num_paths / region_size; */
	u32 path_index = ((unsigned long long)hash_key * path_ptr->num_paths) >> 16;
	struct xpath_flow_entry f, *flow_ptr = NULL;

	xpath_init_flow_entry(&f);
	xpath_set_flow_4tuple(&f, iph->saddr, iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
	f.info.path_index = path_index;
	f.info.last_tx_time = pkt_tx_time;
	f.info.last_reroute_time = now;
    f.info.dre_bytes_sent = 0;
    f.info.dre_last_update_time = now;

	if (tcph->syn) {
		path_index = tlb_where_to_route(path_index, path_ptr);
		f.info.path_index = path_index;
		if (unlikely(!xpath_insert_flow_table(&ft, &f, GFP_ATOMIC))) {
			xpath_debug_info("XPath: insert flow fails\n");
		}

	} else if (likely(flow_ptr = xpath_search_flow_table(&ft, &f))) {
		path_index = flow_ptr->info.path_index;

		// update srrt
		path_group_id = path_ptr->path_group_ids[path_index];
		// if (tp) {
  //       	spin_lock_irqsave(&(pg[path_group_id].lock), flags);
		// 	pg[path_group_id].smooth_rtt_us = (pg[path_group_id].smooth_rtt_us + 3 * (tp->srtt_us >> 3)) >> 2;
	 //        pg[path_group_id].last_rtt_update_time = now;
  //       	spin_unlock_irqrestore(&(pg[path_group_id].lock), flags);
		// }
				/* delete the flow entry */
		// if (tcph->fin || tcph->rst) {
		// 	xpath_delete_flow_table(&ft, &f);
		// 	goto out;
		// }

		/* reroute when current path is highly congested */
		// if (flow_ptr->info.ecn_fraction >= xpath_tlb_ecn_high_thresh &&
		//     (tp->srtt_us << 3) >= xpath_tlb_rtt_high_thresh &&
	 //            flow_ptr->info.bytes_sent >= xpath_tlb_reroute_bytes_thresh &&
		//     now.tv64 - flow_ptr->info.last_reroute_time.tv64 > 1000 *
		//     xpath_tlb_reroute_time_thresh &&
		//     random_number(100) < xpath_tlb_reroute_prob) {
		// 	reroute = true;
		// }
		// if ((flow_ptr->info.ecn_fraction >= xpath_tlb_ecn_high_thresh && flow_ptr->info.bytes_sent >= xpath_tlb_reroute_bytes_thresh)
		// 	|| ktime_to_us(ktime_sub(now, flow_ptr->info.last_tx_time)) > xpath_flowlet_thresh) {
		// if (ktime_to_us(ktime_sub(now, flow_ptr->info.last_tx_time)) > xpath_flowlet_thresh) {
		if ((pg[path_group_id].ecn_fraction > xpath_tlb_ecn_high_thresh) &&
			(flow_ptr->info.bytes_sent > xpath_tlb_reroute_bytes_thresh)) {
			reroute = true;
		}
		/* find a path to reroute */
		if (reroute) {
			printk(KERN_INFO "Current flow: %u, path_index %u, path_group_id %u, ecn %u\n",
				hash_key, path_index, path_ptr->path_group_ids[path_index], pg[path_ptr->path_group_ids[path_index]].ecn_fraction);

			path_index = tlb_where_to_route(path_index, path_ptr);

			printk(KERN_INFO "Reroute path_index %u, path_group_id %u\n", path_index, path_ptr->path_group_ids[path_index]);
			for (i = 0; i < path_ptr->num_paths; i++) {
				path_group_id = path_ptr->path_group_ids[i];
				if (likely(path_group_id < XPATH_PATH_GROUP_SIZE)) {
			            printk(KERN_INFO "\t%u, ecn: %u, srtt: %u\n", path_group_id, pg[path_group_id].ecn_fraction, pg[path_group_id].smooth_rtt_us);
			    }
	        }
			// if (++path_index >= path_ptr->num_paths)
			// 	path_index = 0;
		}

		/* not reroute or cannot find a better path */
		if (!reroute || path_index == flow_ptr->info.path_index) {
			flow_ptr->info.last_tx_time = pkt_tx_time;
			if (seq_after(seq, flow_ptr->info.seq_curr_path))
				flow_ptr->info.seq_curr_path = seq;
			flow_ptr->info.bytes_sent += payload_len;
            flow_ptr->info.dre_bytes_sent += payload_len;
            if (ktime_to_us (ktime_sub (now, flow_ptr->info.dre_last_update_time)) >=
                (xpath_tlb_dre_t >> xpath_tlb_dre_alpha_bit)) {
                flow_ptr->info.dre_last_update_time = now;
                flow_ptr->info.dre_bytes_sent -=
                    (flow_ptr->info.dre_bytes_sent >> xpath_tlb_dre_alpha_bit);
            }
			goto out;
		}

		/* update per-flow state for reroute */
		flow_ptr->info.path_index = path_index;
		flow_ptr->info.last_tx_time = pkt_tx_time;
		flow_ptr->info.last_reroute_time = now;
		flow_ptr->info.seq_prev_path = flow_ptr->info.seq_curr_path;
		flow_ptr->info.seq_curr_path = seq;
		flow_ptr->info.bytes_sent = payload_len;
        flow_ptr->info.dre_bytes_sent = payload_len;
        flow_ptr->info.dre_last_update_time = now;
	}

out:
	/* Get path IP based on path index */
	return path_ptr->path_ips[path_index];
}

inline bool is_good_path_group(struct xpath_group_entry group)
{
	return group.ecn_fraction < xpath_tlb_ecn_low_thresh;
}

inline bool is_gray_path_group(struct xpath_group_entry group)
{
	return  group.ecn_fraction >= xpath_tlb_ecn_low_thresh &&
		group.ecn_fraction < xpath_tlb_ecn_high_thresh;
}


inline unsigned int quantized_dre(struct xpath_flow_entry *flow_ptr)
{
	ktime_t now = ktime_get();
    // If null pointer we should definitely explicly return 0
    if (!flow_ptr) {
        return 0;
    }
    // If the dre value has not been updated for a long time (larger than RTT),
    // we should return 0 as well
    if (ktime_to_us(ktime_sub(now, flow_ptr->info.dre_last_update_time)) >= xpath_tlb_dre_t) {
        return 0;
    }

    return (flow_ptr->info.dre_bytes_sent << 3 >> xpath_tlb_dre_capacity_bit << xpath_tlb_dre_quantized_bit ) * 10^6 / xpath_tlb_dre_t;
}

/*
 * where_to_route() of tlb load balancing algorithm
 * return desired path index
 */
u16 tlb_where_to_route(u16 current_path_index, struct xpath_path_entry *path_ptr)
{
	u16 i, path_index = current_path_index;
	unsigned int path_group_id;
	struct xpath_group_entry current_path = pg[path_ptr->path_group_ids[path_index]];

	/* randomly select a good path */
	for (i = 0; i < path_ptr->num_paths - 1; i++) {
		if (++path_index >= path_ptr->num_paths)
			path_index -= path_ptr->num_paths;

		path_group_id = path_ptr->path_group_ids[path_index];
		if (likely(path_group_id < XPATH_PATH_GROUP_SIZE) &&
		    is_good_path_group(pg[path_group_id]) &&
	    	    pg[path_group_id].ecn_fraction <= current_path.ecn_fraction) {
			goto out;
		}
	}

	/* randomly select a gray path */
	path_index = current_path_index;
	for (i = 0; i < path_ptr->num_paths - 1; i++) {
		if (++path_index >= path_ptr->num_paths)
			path_index -= path_ptr->num_paths;

		path_group_id = path_ptr->path_group_ids[path_index];
		if (likely(path_group_id < XPATH_PATH_GROUP_SIZE) &&
		    is_gray_path_group(pg[path_group_id]) &&
	            pg[path_group_id].ecn_fraction <= current_path.ecn_fraction) {
			goto out;
		}
	}

	path_index = current_path_index;
out:
        return path_index;
}
