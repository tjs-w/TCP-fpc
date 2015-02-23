/**
 * vim:     set noexpandtab:ts=4:sw=4:cindent
 *
 * @file    fptcp.c
 * @brief   False Positive Checksum for TCP:
 *          Kernel module to create false-positives w.r.t. TCP checksum for
 *          ingress data. Taps the inbound TCP segments by tweaking the
 *          the data to have same csum, and sets it back on the way to
 *          userspace/upper-layer. The TCP stack will be unable to detect 
 *          the corruption and the end-point will receive the courrpt data.
 *
 *          Supports IPv4 flows only. No wildcards are supported!
 *
 * @author  Tejas Wanjari <tejaswanjari@gmail.com>
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4.h>
#include <linux/configfs.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>

#include "fptcp.h"

static struct nf_hook_ops   nfh_ops;    /* Netfilter hook operations */

/* Configfs */
typedef struct fptcp_cfgfs {
	struct configfs_subsystem   subsys;
	fptcp_conf_t                fpc;
} fptcp_cfgfs_t;
#define __fpc_enable(c)              CONF_ENABLE((c)->fpc)
#define __fpc_inst_nr_rules(c)       CONF_INST_NR_RULES((c)->fpc)
#define __fpc_rule(c, i)             CONF_RULE((c)->fpc, i)
#define __fpc_percent(c, i)          CONF_PERCENT((c)->fpc, i)
#define __fpc_ip_src(c, i)           CONF_IP_SRC((c)->fpc, i)
#define __fpc_ip_dst(c, i)           CONF_IP_DST((c)->fpc, i)
#define __fpc_port_src(c, i)         CONF_PORT_SRC((c)->fpc, i)
#define __fpc_port_dst(c, i)         CONF_PORT_DST((c)->fpc, i)

typedef struct fptcp_cfg_attr {
	struct configfs_attribute attr;
	ssize_t (*show)(fptcp_cfgfs_t *, char *);
	ssize_t (*store)(fptcp_cfgfs_t *, const char *, size_t);
} fptcp_cfg_attr_t;

static inline fptcp_cfgfs_t *to_fptcp_cfgfs(struct config_item *item) {
	return item ? \
		container_of(to_configfs_subsystem(to_config_group(item)), 
				fptcp_cfgfs_t, subsys) : \
		NULL;
}

/**
 * @brief   Read callback for /sys/kernel/config/fptcp/show_rules
 */
static ssize_t show_rules(fptcp_cfgfs_t *cfg, char *buf)
{
	int     i, l;
	char    *out = buf;

	fplog("buf: %p\n", buf);

	/* Header */
	l = sprintf(out, "%-20s%-10s%-20s%-10s%-5s\n\n", 
			"src_ip", "src_port", "dst_ip", "dst_port", "%corrupt");
	if (l < 0)
		return l;
	out += l;

	/* Entries */
	for (i = 0; i < __fpc_inst_nr_rules(cfg); i++) {
		l = sprintf(out, "%-20pI4%-10u%-20pI4%-10u%-5u\n",
				&__fpc_ip_src(cfg, i),
				ntohs(__fpc_port_src(cfg, i)),
				&__fpc_ip_dst(cfg, i),
				ntohs(__fpc_port_dst(cfg, i)),
				__fpc_percent(cfg, i));
		fplog("rd: %s\n", out);
		if (l < 0)
			return l;
		out += l;
	}

	fplog("buf: %p\n", buf);
	print_hex_dump(KERN_ALERT, "FPTCP ", DUMP_PREFIX_NONE, 32, 1, 
			buf, 1024, true);
	return strlen(buf);
}

static int parse_rule(const char *s, size_t count, const char *delim,
		fptcp_rule_t *rule, int *cmd)
{

	char *ptr, *opts, *orig, *str_val;
	substring_t args[MAX_OPT_ARGS];
	int int_val, token;

	opts = kstrndup(s, PAGE_SIZE, GFP_KERNEL);
	if (!opts) {
		fplog("Out of memory.\n");
		return -ENOMEM;
	}
	memset(rule, 0, sizeof(fptcp_rule_t));

	orig = opts;
	fplog("Opts: %s\n", orig);
	while ((ptr = strsep(&opts, delim)) != NULL) {
		if (!ptr)
			continue;

		token = match_token(ptr, tokens, args);
		fplog("Token=%d %s %s\n", token, ptr, args->from);
		switch (token) {
		case opt_cmd:
			str_val = match_strdup(args);
			fplog("cmd = %s\n", str_val);
			if (strncmp(str_val, FPTCP_CMD_ADD_S, 
						strlen(FPTCP_CMD_ADD_S)) == 0) {
				*cmd = FPTCP_CMD_ADD;
			}
			else if ((strncmp(str_val, FPTCP_CMD_DEL_S, 
							strlen(FPTCP_CMD_DEL_S)) == 0)) {
				*cmd = FPTCP_CMD_DEL;
			}
			else if (unlikely(str_val == FPTCP_CMD_NULL)) {
				fplog("Invalid token=%d\n", token);
				return -EINVAL;
			}
			kfree(str_val);
			break;
		case opt_s_ip:
			str_val = match_strdup(args);
			fplog("s_ip = %s %x\n", str_val, in_aton(str_val));
			rule->ip_src = in_aton(str_val);
			kfree(str_val);
			break;
		case opt_s_port:
			match_int(args, &int_val);
			fplog("s_port = %u\n", int_val);
			rule->port_src = htons(int_val);
			break;
		case opt_d_ip:
			str_val = match_strdup(args);
			fplog("d_ip = %s %x\n", str_val, in_aton(str_val));
			rule->ip_dst = in_aton(str_val);
			kfree(str_val);
			break;
		case opt_d_port:
			match_int(args, &int_val);
			fplog("d_port = %u\n", int_val);
			rule->port_dst = htons(int_val);
			break;
		case opt_perc:
			match_int(args, &int_val);
			fplog("perc = %u\n", int_val);
			rule->percent = int_val;
			calc_set_interval(rule);
			break;
		default:
			fplog("Token=%d %s %s\n", token, ptr, args->from);
			break;
		}
	}
	kfree(orig);

	return 0;
}

/** 
 * @brief   Appends the rule in the array.
 * @return  Returns total installed rules, -ENOMEM otherwise.
 */
static int add_rule(fptcp_cfgfs_t *cfg, fptcp_rule_t *rule)
{
	if (__fpc_inst_nr_rules(cfg) >= MAX_NR_FLOWS) {
		fplog("add: nr rules %d\n", __fpc_inst_nr_rules(cfg));
		return -ENOMEM;
	}

	__fpc_rule(cfg, __fpc_inst_nr_rules(cfg)++) = *rule;

	return __fpc_inst_nr_rules(cfg);
}

/** 
 * @brief   Sequential search in array. :(
 * @return  Returns index if found, -EINVAL otherwise.
 */
static int search_rule(fptcp_cfgfs_t *cfg, fptcp_rule_t *rule)
{
	u64 key, itr;
	int i;

	key = *(u64 *) rule;
	for (i = 0; i < __fpc_inst_nr_rules(cfg); i++) {
		itr = *(u64 *) &__fpc_rule(cfg, i);
		if (key == itr)
			return i;
	}

	return -EINVAL;
}

/** 
 * @brief   Removal sequential. :/
 * @return  Returns index where rule was found, -EINVAL if not
 */
static int del_rule(fptcp_cfgfs_t *cfg, fptcp_rule_t *rule)
{
	int idx, i;

	idx = search_rule(cfg, rule);
	if (idx < 0)
		return idx;
	for (i = idx+1; i < __fpc_inst_nr_rules(cfg); i++)
		__fpc_rule(cfg, i-1) = __fpc_rule(cfg, i);
	__fpc_inst_nr_rules(cfg)--;

	return idx;
}

/**
 * @brief   Write callback for /sys/kernel/config/fptcp/store_rules
 */
static ssize_t store_rules(fptcp_cfgfs_t *cfg, const char *buf, size_t count)
{
	fptcp_rule_t rule;
	int ret, cmd = FPTCP_CMD_NULL;

	fplog("nr rules %d\n", __fpc_inst_nr_rules(cfg));
	if (__fpc_inst_nr_rules(cfg) >= MAX_NR_FLOWS) {
		fplog("nr rules %d\n", __fpc_inst_nr_rules(cfg));
		return -ENOMEM;
	}

	ret = parse_rule(buf, count, DELIM, &rule, &cmd);
	if (ret < 0) {
		return ret;
	}

	if (!(rule.ip_src && rule.ip_dst && 
				rule.port_src && rule.port_dst && 
				(rule.percent > 0) && (rule.percent <= 100))) {
		fplog("parse o/p: ip_src=%pI4 ip_dst=%pI4\
				port_src=%hhu port_dst=%hhu percent=%u\n", 
				&(rule.ip_src), &(rule.ip_dst),
				rule.port_src, rule.port_dst, rule.percent);
		return -EINVAL;
	}

	switch(cmd) {
	case FPTCP_CMD_ADD:
		add_rule(cfg, &rule);
		break;
	case FPTCP_CMD_DEL:
		del_rule(cfg, &rule);
	default:
		fplog("Invalid cmd=%d\n", cmd);
		return -EINVAL;
	}

	fplog("wr: %s\n", buf);
	return count;
}

/**
 * @brief   Configfs for flushing all rules 
 *			/sys/kernel/config/fptcp/flush_rules
 */ 
static ssize_t flush_rules(fptcp_cfgfs_t *cfg, const char *buf, size_t count)
{
	fplog("nr rules %d\n", __fpc_inst_nr_rules(cfg));
	if (strcmp(buf, "1\n") == 0)
		__fpc_inst_nr_rules(cfg) = 0;
	else
		return -EINVAL;
	fplog("nr rules %d\n", __fpc_inst_nr_rules(cfg));
	return count;
}

/**
 * @brief   Show enable/disable in configfs
 */
static ssize_t enable_show(fptcp_cfgfs_t *cfg, char *buf)
{
	return sprintf(buf, "%d\n", __fpc_enable(cfg));
}

/**
 * @brief   Write enable/disable in configfs
 */
static ssize_t enable_store(fptcp_cfgfs_t *cfg, const char *buf, size_t count)
{
	int val, r;
	if ((r = sscanf(buf, "%d", &val)) < 0) {
		fplog("Invalid val=%d err=%d\n", val, r);
		return r;
	}
	fplog("val=%d __fpc_enable=%d count=%ld buf=%s\n", 
			val, __fpc_enable(cfg), count, buf);
	if (val == __fpc_enable(cfg))
		return count;
	if (val == 1) {
		r = nf_register_hook(&nfh_ops);
		if (r < 0) {
			fplog("err=%d\n", r);
			return r;
		}
		nfh_ops.priv = cfg;
	} 
	else if (val == 0) {
		nf_unregister_hook(&nfh_ops);
		nfh_ops.priv = NULL;
	}
	__fpc_enable(cfg) = val;
	return count;
}

static fptcp_cfg_attr_t cfg_attr_show_rules = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "show_rules",
		.ca_mode = S_IRUGO
	},
	.show = show_rules,
};

static fptcp_cfg_attr_t cfg_attr_store_rules = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "store_rules",
		.ca_mode = S_IWUGO
	},
	.store = store_rules,
};

static fptcp_cfg_attr_t cfg_attr_flush_rules = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "flush_rules",
		.ca_mode = S_IWUGO
	},
	.store = flush_rules,
};

static fptcp_cfg_attr_t cfg_attr_enable = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "enable",
		.ca_mode = S_IWUGO | S_IRUGO
	},
	.show = enable_show,
	.store = enable_store,
};

static struct configfs_attribute *cfg_attrs[] = {
	&cfg_attr_show_rules.attr,
	&cfg_attr_store_rules.attr,
	&cfg_attr_flush_rules.attr,
	&cfg_attr_enable.attr,
	NULL,
};

static ssize_t cfg_attr_show(struct config_item *item,
		struct configfs_attribute *attr,
		char *buf)
{
	fptcp_cfgfs_t *cfg = to_fptcp_cfgfs(item);
	fptcp_cfg_attr_t *cfg_attr = 
		container_of(attr, fptcp_cfg_attr_t, attr);
	ssize_t ret = 0;

	if (cfg_attr->show)
		ret = cfg_attr->show(cfg, buf);
	return ret;
}

static ssize_t cfg_attr_store(struct config_item *item,
		struct configfs_attribute *attr,
		const char *buf, size_t count)
{
	fptcp_cfgfs_t *cfg = to_fptcp_cfgfs(item);
	fptcp_cfg_attr_t *cfg_attr =
		container_of(attr, fptcp_cfg_attr_t, attr);
	ssize_t ret = -EINVAL;

	if (cfg_attr->store)
		ret = cfg_attr->store(cfg, buf, count);
	return ret;
}

static struct configfs_item_operations cfg_item_ops = {
	.show_attribute = cfg_attr_show,
	.store_attribute = cfg_attr_store,
};

static struct config_item_type cfg_type = {
	.ct_item_ops = &cfg_item_ops,
	.ct_attrs = cfg_attrs,
	.ct_owner = THIS_MODULE,
};

static fptcp_cfgfs_t cfg_subsys = {
	.subsys = {
		.su_group = {
			.cg_item = {
				.ci_namebuf = "fptcp",
				.ci_type = &cfg_type,
			},
		},
	},
};

static int __init create_configfs(void)
{
	int error;

	/* Create /sys/kernel/config/fptcp/ dir */
	mutex_init(&cfg_subsys.subsys.su_mutex);
	error = configfs_register_subsystem(&cfg_subsys.subsys);

	if (error) {
		pr_err("%s:%d %s: configfs creation failed\n", 
				__FILE__, __LINE__, __func__);
		goto _exit;
	}
	fplog("/sys/kernel/config/fptcp/ created.\n");

	return 0;
_exit:
	return error;
}

static inline void __exit destroy_configfs(void)
{
	configfs_unregister_subsystem(&cfg_subsys.subsys);
}

/**
 * @brief   Make the TCP segment false positive.
 */
static inline void fptcp_process_seg(struct sk_buff *sock_buff)
{
	char *data;
	u32 *dp;
	struct tcphdr *tcphdr = tcp_hdr(sock_buff);

	data = ((char *) tcphdr) + (tcphdr->doff * 4);

	dp = (u32 *) data;
	*dp = __fp_reorder(*dp);

	fplog("%s: tweaked the TCP seg for false-positive checksum\n", __func__);
}

/**
 * @brief   The NF hook funtion defining the criterion for the applying the
 *          filtering the necessary packets to generate the false-positives
 * @return  NF_ACCEPT - process the packet, if necessary, and let go!
 */
static unsigned int fptcp_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb, const struct net_device *in, 
		const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct sk_buff  *sock_buff = skb;
	struct iphdr    *iphdr;
	struct tcphdr   *tcphdr;
	int i;
	fptcp_cfgfs_t *cfg = (fptcp_cfgfs_t *) ops->priv;

	if (!__fpc_inst_nr_rules(cfg)) {
		goto ret;
	}

	if (!sock_buff) {
		goto ret;
	}

	iphdr = ip_hdr(sock_buff);
	if (!iphdr) {
		goto ret;
	}

	if (iphdr->protocol != IPPROTO_TCP) {
		goto ret;
	}

	tcphdr = tcp_hdr(sock_buff);

	/* Match flows */
	for (i = 0; i < __fpc_inst_nr_rules(cfg); i++) {
		if ((iphdr->saddr == __fpc_ip_src(cfg, i)) 
				&& (tcphdr->dest == __fpc_port_dst(cfg, i))
				&& (iphdr->daddr == __fpc_ip_dst(cfg, i)) 
				&& (tcphdr->source == __fpc_port_src(cfg, i))) {
			inc_pkt_cnt(&__fpc_rule(cfg, i));
			if (should_corrupt_seg(&__fpc_rule(cfg, i))) {
				fptcp_process_seg(sock_buff);
			}
		}
	}

ret:
	return NF_ACCEPT;
}

static int __init fptcp_init(void)
{
	int error; 

	/* Netfilter setup */
	nfh_ops.hook = fptcp_hook;
	nfh_ops.hooknum = 1;
	nfh_ops.pf = PF_INET;
	nfh_ops.priority = NF_IP_PRI_FIRST;
	nfh_ops.priv= NULL;

	/* Configfs */
	error = create_configfs();
	if (error) {
		return error;
	}

	/* NOTE:
	 * nf is initially disabled. Registered using the configfs enable 
	 * by the user.
	 */

	return 0;
}

static void __exit fptcp_exit(void)
{
	destroy_configfs();
	if (nfh_ops.priv) {
		nf_unregister_hook(&nfh_ops);
		nfh_ops.priv= NULL;
	}
}

module_init(fptcp_init);
module_exit(fptcp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tejas Wanjari");
MODULE_DESCRIPTION("False-positive checksuming for TCP segment corruption.\n");

