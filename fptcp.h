#ifndef __FPTCP_H
#define __FPTCP_H

#include <linux/parser.h>

/**
 * @file    fptcp.c
 * @brief   FPTCP header
 * @author  Tejas Wanjari <tejas.wanjari@emc.com>
 */

#define DELIM                   ",\n"

#ifndef MAX_NR_FLOWS
#define MAX_NR_FLOWS            64
#endif

/* sysfs string parser types */
enum {
    opt_cmd, opt_s_ip, opt_s_port, opt_d_ip, opt_d_port, opt_perc, opt_err=-1
};

#define FPTCP_CMD_NULL          0
#define FPTCP_CMD_ADD           1
#define FPTCP_CMD_ADD_S         "add"
#define FPTCP_CMD_DEL           2
#define FPTCP_CMD_DEL_S         "del"

static match_table_t tokens = {
    {   opt_cmd,        "cmd=%s"        },
    {   opt_s_ip,       "s_ip=%s"       },
    {   opt_s_port,     "s_port=%u"     },
    {   opt_d_ip,       "d_ip=%s"       },
    {   opt_d_port,     "d_port=%u"     },
    {   opt_perc,       "perc=%u"       },
    {   opt_err,        NULL            },
};

typedef struct { 
    u32         percent;        /* Percentage of segments to be corrupted */
    __be32      ip_src;         /* Source IP */
    __be32      ip_dst;         /* Destination IP */
    __be16      port_src;       /* Source port */
    __be16      port_dst;       /* Destination port */

    /* Non-parameters */
    struct {
        u32         pkt_cnt;        /* Counter for arriving pkts */
        u32         pkt_interval;   /* Depends on percent: 100/percent-val */
    } hidden;      
} fptcp_rule_t;

/* r = rule pointer */
#define __pkt_cnt(r)            ((r)->hidden).pkt_cnt
#define __pkt_interval(r)       ((r)->hidden).pkt_interval
#define calc_set_interval(r)    __pkt_interval(r) = (100/(r)->percent)
#define inc_pkt_cnt(r)          __pkt_cnt(r)++
#define should_corrupt_seg(r)   ((__pkt_cnt(r) % __pkt_interval(r)) == 0)

typedef struct {
    int             enable;                 /* Enabled/Disabled */
    int             inst_nr_rules;          /* No. of rules present/installed */
    fptcp_rule_t    rules[MAX_NR_FLOWS];    /* Rules listing */
} fptcp_conf_t;

/* c = config pointer, i = rule index */
#define CONF_ENABLE(c)              (c).enable
#define CONF_INST_NR_RULES(c)       (c).inst_nr_rules
#define CONF_RULE(c, i)             (c).rules[i]
#define CONF_PERCENT(c, i)          (c).rules[i].percent
#define CONF_IP_SRC(c, i)           (c).rules[i].ip_src
#define CONF_IP_DST(c, i)           (c).rules[i].ip_dst
#define CONF_PORT_SRC(c, i)         (c).rules[i].port_src
#define CONF_PORT_DST(c, i)         (c).rules[i].port_dst

/* Reorder: Eg.\x31 \x32 \x33 \x34 => \x33 \x34 \x31 \x32 */
#define __fp_reorder(x)     \
    ((((x) & 0x0000ffff) << 16) | (((x) & 0xffff0000) >> 16))

/* Logging */
#ifndef FPTCP_LOG_LVL
#define FPTCP_LOG_LVL   KERN_INFO
#endif
#define fplog(format, ...)                                      \
    printk(FPTCP_LOG_LVL "FPTCP:%s " format, __func__, ##__VA_ARGS__);

#endif      /* __FPTCP_H */
