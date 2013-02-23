#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <net/netlink.h>
#include <linux/pkt_sched.h>
#include <net/sch_generic.h>
#include <net/pkt_sched.h>

/*
 * Simple parallel token bucket for efficient rate limiting at high
 * speeds. This is a classless qdisc. Classful qdisc to follow soon!.
 * -- Vimal <j.vimal@gmail.com>
 */

/* Minimum delta_t between two hrtimer ticks. */
#define QUANTA l2t_ns(&rl->rate_to_time, 65536)

/*
 * This limits the maximum token count that the token bucket can
 * accumulate. Since we have TSO sized packets, anything less than 64k
 * will result in a deadlock where the qdisc can never dequeue a
 * single TSO sized segment.
 */

#define PTB_MIN_PACKET_BYTES (64)
#define PTB_MAX_PACKET_BYTES (65536)

struct ptb_sched;

/*
 * The parallel rate limiter works by having multiple, per-TX ring
 * queues (ptb_local), to preserve locality as much as possible.  The
 * design avoids per-packet contention by lazily querying for tokens
 * from the shared pool stored in ptb_sched.  To provide fairness
 * among queues waiting on tokens, we use simple round robin among
 * waiters.
 */

struct ptb_rate_cfg {
	u64 rate_bps;
	u32 mult;
	u32 shift;
};

struct ptb_local {
	struct ptb_sched *rl;
	struct Qdisc *sch;
	int idx, cpu;
	struct sk_buff_head list;

	int waiting;
	u64 tokens;
	struct list_head wait_node;

	/* Virtual time */
	struct hrtimer timer;
};

struct ptb_sched {
	u32 rate;
	u64 tokens;
	struct ptb_rate_cfg rate_to_time;

	struct Qdisc **qdiscs;
	spinlock_t spinlock;

	/* Parameters */
	int max_len;

	/* Virtual time based approach */
	u64 now, next;

	struct Qdisc *sch;
};

static u64 l2t_ns(struct ptb_rate_cfg *r, unsigned int len);

/* We may want to use this function to correct for GSO fragments and
 * account for the true number of bytes sent on wire. */
static inline int skb_size(struct sk_buff *skb)
{
	return skb->len;
}

static int ptb_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	if(sch->q.qlen < qdisc_dev(sch)->tx_queue_len) {
		sch->q.qlen++;
		return qdisc_enqueue_tail(skb, sch);
	}

	return qdisc_drop(skb, sch);
}

/* Why do we need this? */
static unsigned int ptb_drop(struct Qdisc *sch)
{
	return 0;
}

static inline void ptb_local_watchdog(struct ptb_local *q, u64 dt_ns)
{
	if(!hrtimer_active(&q->timer)) {
		hrtimer_start(&q->timer, ktime_set(0, dt_ns),
			      HRTIMER_MODE_REL);
	}
}

enum hrtimer_restart ptb_local_timeout(struct hrtimer *timer) {
	struct ptb_local *q = container_of(timer, struct ptb_local, timer);
	struct ptb_sched *rl = q->rl;

	q->tokens += QUANTA;
	qdisc_unthrottled(q->sch);
	__netif_schedule(qdisc_root(q->sch));

	return HRTIMER_NORESTART;
}

/*
 * If the local Qdisc's token count runs out, try to borrow from the
 * shared pool.  We ensure fairness in a simple way by servicing
 * waiters in first come first served basis.  The only assumption we
 * make is that ktime_get() is synchronised across CPUs.
 *
 * The design is as follows.  rl->next denotes the next _overall_
 * permissible transmit time so that rate limits are never violated.
 * Each queue basically obtains a `permit' to transmit from rl->next
 * and rl->next+quantum.  If rl->next was less than current time, the
 * queue can transmit immediately.  If not, it can transmit only after
 * (rl->next - now) nanosec.
 *
 * This automatically takes care of fairness.  So if multiple queues
 * try to grab tokens, they will be serialised and serviced round
 * robin.  The only disadvantage of this design to the previous design
 * is that you need multiple timers, one per CPU.  Most server-class
 * CPUs use lapic as clock event device, so it's in fact better to
 * have one timer per CPU instead of CPUs sending IPIs to each other.
 */
static inline int ptb_borrow_tokens(struct ptb_sched *rl,
				    struct ptb_local *q,
				    u64 min_tokens)
{
	int timeout = 1;
	u64 quanta;
	u64 now = ktime_to_ns(ktime_get());

	if (qdisc_is_throttled(q->sch))
		return timeout;

	spin_lock(&rl->spinlock);
	/* Virtual time */
	quanta = QUANTA;

	if (rl->next < now) {
		/* Transmit permitted, so this queue obtains a lease
		 * to transmit from now to now + quanta. */
		rl->next = now + quanta;
		q->tokens += quanta;
		timeout = 0;
	} else {
		/* Transmit not permitted, so set up a timer. */
		qdisc_throttled(q->sch);
		ptb_local_watchdog(q, rl->next - now);
		/* This queue will get to transmit from rl->next to
		 * rl->next + quanta */
		rl->next += quanta;
	}

	spin_unlock(&rl->spinlock);
	return timeout;
}

static u64 l2t_ns(struct ptb_rate_cfg *r, unsigned int len)
{
	return ((u64)len * r->mult) >> r->shift;
}

static struct sk_buff *ptb_dequeue(struct Qdisc *sch)
{
	struct ptb_local *q = qdisc_priv(sch);
	struct ptb_sched *rl = q->rl;
	struct sk_buff *skb = NULL;
	int size;
	s64 toks, req;

	/* This shouldn't even be called, right? */
	if(sch->q.qlen == 0) {
		return NULL;
	}

	skb = qdisc_peek_head(sch);
	size = skb_size(skb);

	/* Cache the CPU of this TX-queue */
	q->cpu = smp_processor_id();
	toks = q->tokens;
	req = l2t_ns(&rl->rate_to_time, size);
	toks -= req;

	if(toks < 0 && ptb_borrow_tokens(rl, q, -toks)) {
		sch->qstats.overlimits++;
		return NULL;
	}

	skb = qdisc_dequeue_head(sch);
	q->tokens -= req;
	sch->q.qlen--;
	qdisc_unthrottled(sch);
	return skb;
}

static const struct nla_policy ptb_policy[TCA_TBF_MAX + 1] = {
	[TCA_TBF_PARMS] = { .len = sizeof(struct tc_tbf_qopt) },
	[TCA_TBF_RTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
	[TCA_TBF_PTAB]	= { .type = NLA_BINARY, .len = TC_RTAB_SIZE },
};

static inline void tbf_precompute_ratedata(struct ptb_rate_cfg *r)
{
	r->shift = 0;
	r->mult = 1;

	if (r->rate_bps > 0) {
		r->shift = 15;
		r->mult = div64_u64(8LLU * NSEC_PER_SEC * (1 << r->shift), r->rate_bps);
	}
}

static int ptb_change(struct Qdisc *sch, struct nlattr *opt)
{
	int err;
	struct ptb_sched *rl = qdisc_priv(sch);
	struct nlattr *tb[TCA_TBF_PTAB + 1];
	struct tc_tbf_qopt *qopt;
	int rate;

	err = nla_parse_nested(tb, TCA_TBF_PTAB, opt, ptb_policy);
	if(err < 0)
		return err;

	err = -EINVAL;
	if (tb[TCA_TBF_PARMS] == NULL)
		goto done;

	qopt = nla_data(tb[TCA_TBF_PARMS]);
	rate = qopt->rate.rate;
	/* convert from bytes/s to b/s */
	rl->rate_to_time.rate_bps = (u64)rate << 3;
	tbf_precompute_ratedata(&rl->rate_to_time);

	rl->rate = rate;
	err = 0;

	printk(KERN_INFO "ptb init: rate %llu b/s, time quantum %lluns\n",
	       rl->rate_to_time.rate_bps, QUANTA);
 done:
	return err;
}

static int ptb_local_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct ptb_local *q = qdisc_priv(sch);
	/* Initialize the sub queue */
	q->sch = sch;
	skb_queue_head_init(&q->list);
	q->waiting = 0;
	q->tokens = 0;
	q->cpu = 0;
	INIT_LIST_HEAD(&q->wait_node);

	/* Virtual time */
	hrtimer_init(&q->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	q->timer.function = ptb_local_timeout;
	return 0;
}

static void ptb_destroy(struct Qdisc *sch)
{
	struct ptb_sched *rl = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	unsigned int ntx;

	if(!rl->qdiscs)
		return;

	for(ntx = 0; ntx < dev->num_tx_queues && rl->qdiscs[ntx]; ntx++)
		qdisc_destroy(rl->qdiscs[ntx]);

	kfree(rl->qdiscs);
	rl->qdiscs = NULL;
}

static void ptb_local_destroy(struct Qdisc *sch)
{
	struct ptb_local *q = qdisc_priv(sch);
	skb_queue_purge(&q->list);
	hrtimer_cancel(&q->timer);
}

static int ptb_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct net_device *dev = qdisc_dev(sch);
	struct Qdisc *qdisc;
	unsigned int i;

	sch->q.qlen = 0;
	memset(&sch->bstats, 0, sizeof(sch->bstats));
	memset(&sch->qstats, 0, sizeof(sch->qstats));

	for(i = 0; i < dev->num_tx_queues; i++) {
		qdisc = netdev_get_tx_queue(dev, i)->qdisc;
		spin_lock_bh(qdisc_lock(qdisc));
		sch->q.qlen	+= qdisc->q.qlen;
		sch->bstats.bytes += qdisc->bstats.bytes;
		sch->bstats.packets	+= qdisc->bstats.packets;
		sch->qstats.qlen += qdisc->qstats.qlen;
		sch->qstats.backlog	+= qdisc->qstats.backlog;
		sch->qstats.drops += qdisc->qstats.drops;
		sch->qstats.requeues += qdisc->qstats.requeues;
		sch->qstats.overlimits += qdisc->qstats.overlimits;
		spin_unlock_bh(qdisc_lock(qdisc));
	}

	return 0;
}

static struct sk_buff *ptb_peek(struct Qdisc *sch)
{
	struct ptb_local *q = qdisc_priv(sch);
	return skb_peek(&q->list);
}

static int ptb_init(struct Qdisc *, struct nlattr *);
static void ptb_attach(struct Qdisc *);

static struct Qdisc_ops ptb_qdisc_ops __read_mostly = {
	.next = NULL,
	.cl_ops = NULL,
	.id = "tbf",
	.priv_size = sizeof(struct ptb_sched),
	.init = ptb_init,
	.destroy = ptb_destroy,
	.change = ptb_change,
	.attach = ptb_attach,
	.dump = ptb_dump,
	.owner = THIS_MODULE,
};

static struct Qdisc_ops ptb_local_ops __read_mostly = {
	.next = NULL,
	.cl_ops = NULL,
	.id = "tbf_local",
	.priv_size = sizeof(struct ptb_local),
	.init = ptb_local_init,
	.destroy = ptb_local_destroy,
	.enqueue = ptb_enqueue,
	.dequeue = ptb_dequeue,
	.peek = ptb_peek,
	.drop = ptb_drop,
	.dump = ptb_dump,
};

static void ptb_attach(struct Qdisc *sch)
{
	struct net_device *dev = qdisc_dev(sch);
	struct ptb_sched *rl = qdisc_priv(sch);
	struct Qdisc *qdisc;
	unsigned int ntx;

	for(ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		qdisc = rl->qdiscs[ntx];
		qdisc = dev_graft_qdisc(qdisc->dev_queue, qdisc);
		if(qdisc)
			qdisc_destroy(qdisc);
	}

	kfree(rl->qdiscs);
	rl->qdiscs = NULL;
}

static int ptb_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct net_device *dev = qdisc_dev(sch);
	struct ptb_sched *rl = qdisc_priv(sch);
	struct ptb_local *q;
	struct netdev_queue *dev_queue;
	struct Qdisc *qdisc;
	unsigned int ntx;

	if(sch->parent != TC_H_ROOT)
		return -EOPNOTSUPP;

	if(!netif_is_multiqueue(dev))
		return -EOPNOTSUPP;

	rl->qdiscs = kcalloc(dev->num_tx_queues, sizeof(struct Qdisc),
						 GFP_KERNEL);

	if(rl->qdiscs == NULL)
		return -ENOMEM;

	if(opt == NULL)
		return -EINVAL;

	spin_lock_init(&rl->spinlock);
	rl->rate = 100;
	rl->tokens = 0;
	rl->max_len = 128 * 1024;
	rl->sch = sch;
	rl->next = ktime_to_ns(ktime_get());

	for(ntx = 0; ntx < dev->num_tx_queues; ntx++) {
		dev_queue = netdev_get_tx_queue(dev, ntx);
		qdisc = qdisc_create_dflt(dev_queue, &ptb_local_ops,
					  TC_H_MAKE(TC_H_MAJ(sch->handle),
						    TC_H_MIN(ntx + 1)));
		if(qdisc == NULL)
			goto err;

		rl->qdiscs[ntx] = qdisc;
		/* Link child to parent */
		q = qdisc_priv(qdisc);
		q->rl = rl;
		q->idx = ntx;
	}

	sch->flags |= TCQ_F_MQROOT;
	return ptb_change(sch, opt);
 err:
	ptb_destroy(sch);
	return -ENOMEM;
}

static int __init ptb_module_init(void)
{
	int ret;
	if((ret = register_qdisc(&ptb_qdisc_ops)))
		return ret;

	if((ret = register_qdisc(&ptb_local_ops))) {
		unregister_qdisc(&ptb_qdisc_ops);
		return ret;
	}

	return 0;
}

static void __exit ptb_module_exit(void)
{
	unregister_qdisc(&ptb_qdisc_ops);
	unregister_qdisc(&ptb_local_ops);
}

module_init(ptb_module_init)
module_exit(ptb_module_exit)
MODULE_LICENSE("GPL");
