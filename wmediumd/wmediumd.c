/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author:	Javier Lopez	<jlopex@cozybit.com>
 *		Javier Cardona	<javier@cozybit.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *	02110-1301, USA.
 */

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <stdint.h>
#include <getopt.h>
#include <signal.h>
#include <event.h>
#include <stdbool.h>
#include <sys/timerfd.h>

#include "wmediumd.h"
#include "probability.h"
#include "mac_address.h"
#include "ieee80211.h"
#include "config.h"
#include "list.h"

struct nl_msg *msg;
struct nl_cb *cb;
struct nl_cache *cache;
struct genl_family *family;

int running = 0;
struct jammer_cfg jam_cfg;
int size;

static int received = 0;
static int sent = 0;
static int dropped = 0;
static int acked = 0;

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARGS(a) a[0],a[1],a[2],a[3],a[4],a[5]

struct wmediumd
{
	int timerfd;

	struct nl_sock *sock;
	struct list_head stations;
};

struct station
{
	char addr[ETH_ALEN];
	struct list_head data_queue;
	struct list_head mgmt_queue;
	struct list_head list;
};

struct frame
{
	struct list_head list;		/* frame queue list */
	struct timespec expires;	/* frame delivery (absolute) */
	bool acked;
	long cookie;
	int tx_rates_count;
	int flags;
	struct hwsim_tx_rate *tx_rates;
	size_t data_len;
	u8 data[0];			/* frame contents */
};


bool timespec_before(struct timespec *t1, struct timespec *t2)
{
	return t1->tv_sec < t2->tv_sec ||
	       (t1->tv_sec == t2->tv_sec && t1->tv_nsec < t2->tv_nsec);
}

void rearm_timer(struct wmediumd *ctx)
{
	struct timespec min_expires;
	struct itimerspec expires = {};
	struct station *station;
	struct frame *frame;

	/*
	 * Iterate over all the interfaces to find the next frame that
	 * will be delivered, and set the timerfd accordingly.
	 */
	list_for_each_entry(station, &ctx->stations, list) {
		frame = list_first_entry(&station->mgmt_queue,
					 struct frame, list);
		if (frame && timespec_before(&frame->expires, &min_expires))
			min_expires = frame->expires;

		frame = list_first_entry(&station->data_queue,
					 struct frame, list);
		if (frame && timespec_before(&frame->expires, &min_expires))
			min_expires = frame->expires;
	}
	expires.it_value = min_expires;
	timerfd_settime(ctx->timerfd, TFD_TIMER_ABSTIME, &expires, NULL);
}

bool frame_is_mgmt(struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *) frame->data;
	return (hdr->frame_control[0] & 0x0c) == 0;
}

void queue_frame(struct wmediumd *ctx, struct station *station,
		 struct frame *frame)
{
	struct timespec now;
	struct list_head *queue;

	/*
	 * To determine a frame's expiration time, we compute the
	 * number of retries we might have to make due to radio conditions
	 * or contention, and add backoff time accordingly.  To that, we
	 * add the expiration time of the previous frame in the queue.
	 */
	queue = frame_is_mgmt(frame) ? &station->mgmt_queue : &station->data_queue;
	list_add_tail(&frame->list, queue);

	/* TODO set expires properly */
	/* TODO compute frame attempts / ack status using per_model */
	/*
	 *
	 * rand = drand48();
	 * for each rate_idx, ct in rateset:
	 *    for each attempt:
	 *      is_ack = rand < get_error_prob(snr, rate_idx, data_len);
	 *      time += airtime + backoff
	 *      if is_ack break
	 */
	frame->tx_rates[0].count = 1;
	frame->tx_rates[1].count = -1;
	frame->flags |= HWSIM_TX_STAT_ACK;

	clock_gettime(CLOCK_MONOTONIC, &now);
	frame->expires = now;
	rearm_timer(ctx);
}

bool is_multicast_ether_addr(const u8 *addr)
{
	return 0x01 & addr[0];
}

void deliver_frame(struct wmediumd *ctx, struct frame *frame)
{
	struct ieee80211_hdr *hdr = (void *) frame->data;
	struct station *station;
	u8 *dest = hdr->addr1;
	u8 *src = hdr->addr2;

	int signal = 35;

	if (frame->flags & HWSIM_TX_STAT_ACK) {
		/* rx the frame on the dest interface */
		list_for_each_entry(station, &ctx->stations, list) {
			if (memcmp(src, station->addr, ETH_ALEN) == 0)
				continue;

			if (is_multicast_ether_addr(dest) ||
			    memcmp(dest, station->addr, ETH_ALEN) == 0) {
				send_cloned_frame_msg(ctx->sock, station->addr,
						      frame->data,
						      frame->data_len,
						      1, signal);
			}
		}
	}

	send_tx_info_frame_nl(ctx->sock, src, frame->flags, signal,
			      frame->tx_rates, frame->cookie);

	free(frame->tx_rates);
	free(frame);
}

void deliver_expired_frames_queue(struct wmediumd *ctx,
				  struct list_head *queue,
				  struct timespec *now)
{
	struct frame *frame, *tmp;

	list_for_each_entry_safe(frame, tmp, queue, list) {
		if (timespec_before(&frame->expires, now)) {
			list_del(&frame->list);
			deliver_frame(ctx, frame);
		} else {
			break;
		}
	}
}

void deliver_expired_frames(struct wmediumd *ctx)
{
	struct timespec now;
	struct station *station;

	clock_gettime(CLOCK_MONOTONIC, &now);
	list_for_each_entry(station, &ctx->stations, list) {
		deliver_expired_frames_queue(ctx, &station->mgmt_queue, &now);
		deliver_expired_frames_queue(ctx, &station->data_queue, &now);
	}
}

/*
 *	Send a tx_info frame to the kernel space.
 */
int send_tx_info_frame_nl(struct nl_sock *sock,
			  u8 *src,
			  unsigned int flags, int signal,
			  struct hwsim_tx_rate *tx_attempts,
			  unsigned long cookie)
{

	msg = nlmsg_alloc();
	if (!msg) {
		printf("Error allocating new message MSG!\n");
		goto out;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family),
		    0, NLM_F_REQUEST, HWSIM_CMD_TX_INFO_FRAME, VERSION_NR);

	int rc;
	rc = nla_put(msg, HWSIM_ATTR_ADDR_TRANSMITTER, ETH_ALEN, src);
	rc = nla_put_u32(msg, HWSIM_ATTR_FLAGS, flags);
	rc = nla_put_u32(msg, HWSIM_ATTR_SIGNAL, signal);
	rc = nla_put(msg, HWSIM_ATTR_TX_INFO,
		     IEEE80211_MAX_RATES_PER_TX *
		     sizeof(struct hwsim_tx_rate), tx_attempts);

	rc = nla_put_u64(msg, HWSIM_ATTR_COOKIE, cookie);

	if(rc!=0) {
		printf("Error filling payload\n");
		goto out;
	}

	nl_send_auto_complete(sock,msg);
	nlmsg_free(msg);
	return 0;
out:
	nlmsg_free(msg);
	return -1;
}

/*
 *	Send a cloned frame to the kernel space.
 */
int send_cloned_frame_msg(struct nl_sock *sock, u8 *dst,
			  char *data, int data_len, int rate_idx, int signal)
{

	msg = nlmsg_alloc();
	if (!msg) {
		printf("Error allocating new message MSG!\n");
		goto out;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family),
		    0, NLM_F_REQUEST, HWSIM_CMD_FRAME, VERSION_NR);

	int rc;

	rc = nla_put(msg, HWSIM_ATTR_ADDR_RECEIVER, ETH_ALEN, dst);
	rc = nla_put(msg, HWSIM_ATTR_FRAME, data_len, data);
	rc = nla_put_u32(msg, HWSIM_ATTR_RX_RATE, 1);
	rc = nla_put_u32(msg, HWSIM_ATTR_SIGNAL, -50);

	if(rc!=0) {
		printf("Error filling payload\n");
		goto out;
	}

	nl_send_auto_complete(sock,msg);
	nlmsg_free(msg);
	return 0;
out:
	nlmsg_free(msg);
	return -1;
}

static
int nl_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(&nlerr->msg);

	fprintf(stderr, "nl: cmd %d, seq %d: %s\n", gnlh->cmd,
		nlerr->msg.nlmsg_seq, strerror(abs(nlerr->error)));

	return NL_SKIP;
}

static struct station *get_station_by_addr(struct wmediumd *ctx, u8 *addr)
{
	struct station *station;
	list_for_each_entry(station, &ctx->stations, list) {
		if (memcmp(station->addr, addr, ETH_ALEN) == 0)
			return station;
	}
	return NULL;
}


/*
 *	Callback function to process messages received from kernel
 */
static int process_messages_cb(struct nl_msg *msg, void *arg)
{
	struct wmediumd *ctx = arg;
	struct nl_sock *sock = ctx->sock;
	struct nlattr *attrs[HWSIM_ATTR_MAX+1];
	/* netlink header */
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	/* generic netlink header*/
	struct genlmsghdr *gnlh = nlmsg_data(nlh);

	struct station *sender;
	struct frame *frame;

	if(gnlh->cmd == HWSIM_CMD_FRAME) {
		/* we get the attributes*/
		genlmsg_parse(nlh, 0, attrs, HWSIM_ATTR_MAX, NULL);
		if (attrs[HWSIM_ATTR_ADDR_TRANSMITTER]) {
			u8 *src = (u8 *) nla_data(attrs[HWSIM_ATTR_ADDR_TRANSMITTER]);

			unsigned int data_len =
				nla_len(attrs[HWSIM_ATTR_FRAME]);
			char* data = (char*)nla_data(attrs[HWSIM_ATTR_FRAME]);
			unsigned int flags =
				nla_get_u32(attrs[HWSIM_ATTR_FLAGS]);
			unsigned int tx_rates_len =
				nla_len(attrs[HWSIM_ATTR_TX_INFO]);
			struct hwsim_tx_rate *tx_rates =
				(struct hwsim_tx_rate*)
				nla_data(attrs[HWSIM_ATTR_TX_INFO]);
			unsigned long cookie = nla_get_u64(attrs[HWSIM_ATTR_COOKIE]);

			received++;

			sender = get_station_by_addr(ctx, src);
			if (!sender)
				goto out;

			frame = malloc(sizeof(*frame) + data_len);
			if (!frame)
				goto out;
			frame->tx_rates = malloc(tx_rates_len);
			if (!frame->tx_rates)
				goto out_free_frame;

			memcpy(frame->data, data, data_len);
			frame->data_len = data_len;
			frame->flags = flags;
			frame->cookie = cookie;
			frame->tx_rates_count =
				tx_rates_len / sizeof(struct hwsim_tx_rate);
			memcpy(frame->tx_rates, tx_rates, tx_rates_len);
			queue_frame(ctx, sender, frame);
		}
	}
out:
	return 0;

out_free_frame:
	free(frame);
	return 0;
}

/*
 *	Send a register message to kernel
 */
int send_register_msg(struct nl_sock *sock)
{
	msg = nlmsg_alloc();
	if (!msg) {
		printf("Error allocating new message MSG!\n");
		return -1;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family_get_id(family),
		    0, NLM_F_REQUEST, HWSIM_CMD_REGISTER, VERSION_NR);
	nl_send_auto_complete(sock,msg);
	nlmsg_free(msg);

	return 0;
}

/*
 *	Signal handler
 */
void kill_handler() {
	running = 0;
}

static void sock_event_cb(int fd, short what, void *data)
{
	struct wmediumd *ctx = data;
	nl_recvmsgs_default(ctx->sock);
}

/*
 *	Init netlink
 */
void init_netlink(struct wmediumd *ctx)
{
	struct nl_sock *sock;

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb) {
		printf("Error allocating netlink callbacks\n");
		exit(EXIT_FAILURE);
	}

	sock = nl_socket_alloc_cb(cb);
	if (!sock) {
		printf("Error allocationg netlink socket\n");
		exit(EXIT_FAILURE);
	}

	ctx->sock = sock;

	genl_connect(sock);
	genl_ctrl_alloc_cache(sock, &cache);

	family = genl_ctrl_search_by_name(cache, "MAC80211_HWSIM");

	if (!family) {
		printf("Family MAC80211_HWSIM not registered\n");
		exit(EXIT_FAILURE);
	}

	nl_cb_set(cb, NL_CB_MSG_IN, NL_CB_CUSTOM, process_messages_cb, ctx);
	nl_cb_err(cb, NL_CB_CUSTOM, nl_err_cb, ctx);
}

/*
 *	Print the CLI help
 */
void print_help(int exval)
{
	printf("wmediumd v%s - a wireless medium simulator\n", VERSION_STR);
	printf("wmediumd [-h] [-V] [-c FILE] [-o FILE]\n\n");

	printf("  -h              print this help and exit\n");
	printf("  -V              print version and exit\n\n");

	printf("  -c FILE         set intput config file\n");
	printf("  -o FILE         set output config file\n\n");

	exit(exval);
}

static void timer_cb(int fd, short what, void *data)
{
	struct wmediumd *ctx = data;
	deliver_expired_frames(ctx);
	rearm_timer(ctx);
}

int main(int argc, char* argv[])
{
	int i;
	int opt, ifaces;
	int fd;
	struct nl_sock *sock;
	struct event ev_cmd;
	struct event ev_timer;
	struct wmediumd ctx;
	struct station *station;

	/* Set stdout buffering to line mode */
	setvbuf (stdout, NULL, _IOLBF, BUFSIZ);

	/* no arguments given */
	if(argc == 1) {
		fprintf(stderr, "This program needs arguments....\n\n");
		print_help(EXIT_FAILURE);
	}

	while((opt = getopt(argc, argv, "hVc:o:")) != -1) {
		switch(opt) {
		case 'h':
			print_help(EXIT_SUCCESS);
			break;
		case 'V':
			printf("wmediumd v%s - a wireless medium simulator "
			       "for mac80211_hwsim\n", VERSION_STR);
			exit(EXIT_SUCCESS);
			break;
		case 'c':
			printf("Input configuration file: %s\n", optarg);
			load_config(optarg);
			break;
		case 'o':
			printf("Output configuration file: %s\n", optarg);
			printf("How many interfaces are active?\n");
			scanf("%d",&ifaces);
			if (ifaces < 2) {
				printf("active interfaces must be at least 2\n");
				exit(EXIT_FAILURE);
			}
				write_config(optarg, ifaces, 0.0);
			break;
		case ':':
			printf("wmediumd: Error - Option `%c' "
			       "needs a value\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		case '?':
			printf("wmediumd: Error - No such option:"
			       " `%c'\n\n", optopt);
			print_help(EXIT_FAILURE);
			break;
		}

	}

	if (optind < argc)
		print_help(EXIT_FAILURE);

	/* Handle kill signals */
	running = 1;
	signal(SIGUSR1, kill_handler);

	INIT_LIST_HEAD(&ctx.stations);
	for (i=0; i < size; i++) {
		station = malloc(sizeof(*station));
		if (!station) {
			fprintf(stderr, "Out of memory!");
			exit(1);
		}
		memcpy(station->addr, get_mac_address(i), ETH_ALEN);
		INIT_LIST_HEAD(&station->data_queue);
		INIT_LIST_HEAD(&station->mgmt_queue);
		list_add_tail(&station->list, &ctx.stations);
	}

	/* init libevent */
	event_init();

	/* init netlink */
	init_netlink(&ctx);
	event_set(&ev_cmd, nl_socket_get_fd(ctx.sock), EV_READ | EV_PERSIST,
		  sock_event_cb, &ctx);
	event_add(&ev_cmd, NULL);

	/* setup timers */
	ctx.timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	event_set(&ev_timer, ctx.timerfd, EV_READ | EV_PERSIST, timer_cb, &ctx);
	event_add(&ev_timer, NULL);

	/* Send a register msg to the kernel */
	if (send_register_msg(ctx.sock)==0)
		printf("REGISTER SENT!\n");

	/* enter libevent main loop */
	event_dispatch();

	/* Free all memory */
	free(ctx.sock);
	free(msg);
	free(cb);
	free(cache);
	free(family);

	return EXIT_SUCCESS;
}
