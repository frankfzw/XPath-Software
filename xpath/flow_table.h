#ifndef __FLOW_TABLE_H__
#define __FLOW_TABLE_H__

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/ip.h>
#include <net/tcp.h>

struct xpath_flow_info
{
        u16 path_index; /* index of current path, 0 =< path_index < num_paths */
        u16 num_flowlet;        /* # of flowlets in this connection */
        ktime_t last_tx_time;   /* last time when we observe a transmitted packet */
        ktime_t last_reroute_time;      /* last time when we change the path */

        u32 seq_prev_path;      /* largest seq sent in previous path */
        u32 seq_curr_path;      /* largest seq sent in current path */
        u32 ack_seq;    /* latest ACK seq number */

        u32 bytes_sent; /* bytes sent in current path */
        u32 bytes_acked;        /* bytes ACKed in current path */
        u32 bytes_ecn;  /* bytes that get ECN marked in current path */
        u16 ecn_fraction;       /* ECN fraction in current path */

        u16 rate_mbps;  /* sending rate in Mbps */
        u32 bytes_sent_cycle;   /* bytes sent in current rate measurement cycle */
        ktime_t cycle_start_time;       /* start time of current rate measurement cycle */

        u32 dre_bytes_sent; /* bytes sent in current path, which is used in dre calculation */
        ktime_t dre_last_update_time; /* Last update time for dre degradation */
};

/* A TCP flow <local_ip, remote_ip, local_port, remote_port> */
struct xpath_flow_entry
{
        u32 local_ip;   /* local IP address */
        u32 remote_ip;  /* remote IP address */
        u16 local_port; /* local port */
        u16 remote_port;        /* remote port */
        struct xpath_flow_info info;    /* flow information */
        struct list_head list;  /* linked list */
        spinlock_t lock;        /* per-flow lock */
};

/* Link List of Flows */
struct xpath_flow_list
{
        struct list_head head_node;     /* head node of the flow list */
        unsigned int len;   /* total number of flows in the list */
        spinlock_t lock;    /* lock for this flow list */
};

/* Hash Table of Flows */
struct xpath_flow_table
{
        struct xpath_flow_list *flow_lists;  /* array of linked lists */
        atomic_t size;
};

/* Print functions */
void xpath_print_flow_entry(struct xpath_flow_entry *f, char *operation);
void xpath_print_flow_list(struct xpath_flow_list *fl);
void xpath_print_flow_table(struct xpath_flow_table *ft);

inline unsigned int xpath_hash_flow(struct xpath_flow_entry *f);
inline bool xpath_equal_flow(struct xpath_flow_entry *f1,
                             struct xpath_flow_entry *f2);

/* Initialization functions */
bool xpath_init_flow_info(struct xpath_flow_info *info);
bool xpath_init_flow_entry(struct xpath_flow_entry *f);
bool xpath_init_flow_list(struct xpath_flow_list *fl);
bool xpath_init_flow_table(struct xpath_flow_table *ft);
void xpath_set_flow_4tuple(struct xpath_flow_entry *f,
                           u32 local_ip,
                           u32 remote_ip,
                           u16 local_port,
                           u16 remote_port);

/* Search functions: search a flow entry from flow table/list */
struct xpath_flow_entry *xpath_search_flow_list(struct xpath_flow_list *fl,
                                                struct xpath_flow_entry *f);
struct xpath_flow_entry *xpath_search_flow_table(struct xpath_flow_table *ft,
                                                 struct xpath_flow_entry *f);

/* Insert functions: insert a new flow entry to flow table/list */
bool xpath_insert_flow_list(struct xpath_flow_list *fl,
                            struct xpath_flow_entry *f,
                            int flags);
bool xpath_insert_flow_table(struct xpath_flow_table *ft,
                             struct xpath_flow_entry *f,
                             int flags);

/* Delete functions: delete a flow entry from flow table/list */
bool xpath_delete_flow_list(struct xpath_flow_list *fl,
                            struct xpath_flow_entry *f);
bool xpath_delete_flow_table(struct xpath_flow_table *ft,
                             struct xpath_flow_entry *f);

/* Clear functions: clear flow entries from flow table/list */
bool xpath_clear_flow_list(struct xpath_flow_list *fl);
bool xpath_clear_flow_table(struct xpath_flow_table *ft);

/* Exit functions: delete whole flow table */
bool xpath_exit_flow_table(struct xpath_flow_table *ft);

#endif
