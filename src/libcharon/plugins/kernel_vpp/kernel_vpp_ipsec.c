/*
 * Copyright 2016-2022 Rubicon Communications, LLC.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/* system */
#include <stdio.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <time.h>

/* this plugin */
#include "kernel_vpp_ipsec.h"

/* strongswan lib */
#include <daemon.h>
#include <threading/mutex.h>
#include <collections/hashtable.h>
#include <processing/jobs/callback_job.h>

#include <tnsrinfra/vec.h>
#include <tnsrinfra/pool.h>
#include <vppmgmt/vpp_mgmt_api.h>

#define PRIO_BASE 100000

/* constants from VPP */

/* encryption algorithms */
#define IPSEC_CRYPTO_ALG_NONE		0
#define IPSEC_CRYPTO_ALG_AES_CBC_128	1
#define IPSEC_CRYPTO_ALG_AES_CBC_192	2
#define IPSEC_CRYPTO_ALG_AES_CBC_256	3
#define IPSEC_CRYPTO_ALG_AES_CTR_128	4
#define IPSEC_CRYPTO_ALG_AES_CTR_192	5
#define IPSEC_CRYPTO_ALG_AES_CTR_256	6
#define IPSEC_CRYPTO_ALG_AES_GCM_128	7
#define IPSEC_CRYPTO_ALG_AES_GCM_192	8
#define IPSEC_CRYPTO_ALG_AES_GCM_256	9
/* DES-CBC not supported
 * #define IPSEC_CRYPTO_ALG_DES_CBC		10
 */
#define IPSEC_CRYPTO_ALG_3DES_CBC	11
#define IPSEC_CRYPTO_ALG_CHACHA20_POLY1305	12

/* integrity algorithms */
#define IPSEC_INTEG_ALG_NONE		0
#define IPSEC_INTEG_ALG_MD5_96		1
#define IPSEC_INTEG_ALG_SHA1_96		2
#define IPSEC_INTEG_ALG_SHA_256_96	3
#define IPSEC_INTEG_ALG_SHA_256_128	4
#define IPSEC_INTEG_ALG_SHA_384_192	5
#define IPSEC_INTEG_ALG_SHA_512_256	6
#define IPSEC_INTEG_ALG_AES_GCM_128	7

/* IPsec policies */
#define IPSEC_POLICY_ACTION_BYPASS	0
#define IPSEC_POLICY_ACTION_DISCARD	1
#define IPSEC_POLICY_ACTION_RESOLVE	2
#define IPSEC_POLICY_ACTION_PROTECT	3
#define IPSEC_POLICY_N_ACTION		4

/* IPsec protocols */
#define IPSEC_PROTOCOL_ESP		0
#define IPSEC_PROTOCOL_AH		1

/*
 * Definitions and helper functions for strongswan plugin
 *
 */

typedef struct private_kernel_vpp_ipsec_t {

	kernel_vpp_ipsec_t public;
	
	mutex_t *mutex;

	rng_t *rng;

} private_kernel_vpp_ipsec_t;

typedef struct sa_entry_t {
	host_t *src;
	host_t *dst;
	ipsec_mode_t mode;
	uint32_t spi;
	uint8_t proto;
	linked_list_t *src_ts, *dst_ts;
	chunk_t enc_key, int_key;
	uint16_t enc_alg, int_alg;
	uint32_t sa_id;
	uint8_t esn;
	uint32_t anti_replay;
	uint8_t outbound;
	/* fields for routed SAs */
	mark_t mark;
	uint32_t tunnel_if_index;
	uint32_t real_if_index;
} sa_entry_t;

typedef struct policy_entry_t {
	uint8_t direction;
	policy_type_t action;
	traffic_selector_t *src_ts, *dst_ts;
	mark_t mark;
	sa_entry_t *sa;
	uint32_t priority;
} policy_entry_t;

static int
kernel_vpp_check_connection(private_kernel_vpp_ipsec_t *this)
{
	int ret;

	this->mutex->lock(this->mutex);
	ret = vmgmt_check_connection();
	this->mutex->unlock(this->mutex);

	if (ret < 0) {
		DBG1(DBG_KNL, "kernel_vpp: No connection to VPP API");
	}

	return ret;
}


/*
 * Definitions and helper functions to invoke calls in vpp library
 *
 */

typedef struct {
	int charonalg;
	int keylen;
	int vppalg;
} vpp_alg;

#define foreach_enc_alg \
_(ENCR_NULL,0,IPSEC_CRYPTO_ALG_NONE)				  \
_(ENCR_AES_CBC,128,IPSEC_CRYPTO_ALG_AES_CBC_128)	  \
_(ENCR_AES_CBC,192,IPSEC_CRYPTO_ALG_AES_CBC_192)	  \
_(ENCR_AES_CBC,256,IPSEC_CRYPTO_ALG_AES_CBC_256)	  \
_(ENCR_AES_CTR,128,IPSEC_CRYPTO_ALG_AES_CTR_128)	  \
_(ENCR_AES_CTR,192,IPSEC_CRYPTO_ALG_AES_CTR_192)	  \
_(ENCR_AES_CTR,256,IPSEC_CRYPTO_ALG_AES_CTR_256)	  \
_(ENCR_AES_GCM_ICV16,160,IPSEC_CRYPTO_ALG_AES_GCM_128)	  \
_(ENCR_AES_GCM_ICV16,224,IPSEC_CRYPTO_ALG_AES_GCM_192)	  \
_(ENCR_AES_GCM_ICV16,288,IPSEC_CRYPTO_ALG_AES_GCM_256)	  \
_(ENCR_3DES,192,IPSEC_CRYPTO_ALG_3DES_CBC)	  \
_(ENCR_CHACHA20_POLY1305,288,IPSEC_CRYPTO_ALG_CHACHA20_POLY1305)	  \


static int
vpp_enc_alg(int alg, int keylen)
{
#define _(s,k,v) if (alg == s && keylen == k) return v;
	foreach_enc_alg
#undef _
	return IPSEC_CRYPTO_ALG_NONE;
}

#define foreach_auth_alg \
_(AUTH_HMAC_MD5_96, 128, IPSEC_INTEG_ALG_MD5_96)			 \
_(AUTH_HMAC_SHA1_96, 160, IPSEC_INTEG_ALG_SHA1_96)		   \
_(AUTH_HMAC_SHA2_256_128, 256, IPSEC_INTEG_ALG_SHA_256_128)  \
_(AUTH_HMAC_SHA2_384_192, 384, IPSEC_INTEG_ALG_SHA_384_192)  \
_(AUTH_HMAC_SHA2_512_256, 512, IPSEC_INTEG_ALG_SHA_512_256)  \
_(AUTH_UNDEFINED, 0, IPSEC_INTEG_ALG_NONE)

static int
vpp_auth_alg(int alg, int keylen)
{
#define _(s,k,v) if (alg == s && keylen == k) return v;
	foreach_auth_alg
#undef _
	return IPSEC_INTEG_ALG_NONE;
}

static int
convert_sa_to_vmgmt(vmgmt_ipsec_sa_t *v,
					kernel_ipsec_sa_id_t *id,
					kernel_ipsec_add_sa_t *data)
{
	int addr_len = 4;

	if (!v || !id || !data) {
		return -1;
	}

	v->sw_if_index = ~0;
	v->spi = ntohl(id->spi);
	v->sa_id = v->spi;
	v->ipsec_proto = IPSEC_PROTOCOL_ESP;
	v->crypto_alg = vpp_enc_alg(data->enc_alg, data->enc_key.len * 8);
	v->crypto_key_len = data->enc_key.len;
	memcpy(v->crypto_key, data->enc_key.ptr, data->enc_key.len);
	v->integ_alg = vpp_auth_alg(data->int_alg, data->int_key.len * 8);
	v->integ_key_len = data->int_key.len;
	memcpy(v->integ_key, data->int_key.ptr, data->int_key.len);
	v->esn = data->esn;
	v->anti_replay = data->replay_window;
	v->tunnel_mode = 0; /* tun protect uses transport mode SAs */
	v->addr_family = id->src->get_family(id->src);
	if (v->addr_family == AF_INET6) {
		addr_len = 16;
	}
	memcpy(v->src_ip, id->src->get_address(id->src).ptr, addr_len);
	memcpy(v->dst_ip, id->dst->get_address(id->dst).ptr, addr_len);
	v->outbound = !(data->inbound);
	v->udp_encap = data->encap;

	if (data->encap) {
		v->udp_src_port = id->src->get_port(id->src);
		v->udp_dst_port = id->dst->get_port(id->dst);
	}
	
	return 0;
}

static void
print_sa_id(kernel_ipsec_sa_id_t *id, const char *msg)
{
	char srcaddr[40], dstaddr[40];
	int af = id->src->get_family(id->src);

	inet_ntop(af, (void *) (id->src->get_address(id->src)).ptr,
			  srcaddr, sizeof(srcaddr));
	inet_ntop(af, (void *) (id->dst->get_address(id->dst)).ptr,
			  dstaddr, sizeof(dstaddr));

	DBG1(DBG_KNL, "kernel_vpp: %s: src addr %s:%d dst addr %s:%d "
					"spi %u proto %u mark val %u mask %x",
		  (msg) ? msg : __func__,
		  srcaddr, id->src->get_port(id->src),
		  dstaddr, id->dst->get_port(id->dst),
		  ntohl(id->spi), (uint16_t) id->proto,
		  id->mark.value, id->mark.mask);
}

static void
print_sa_add(kernel_ipsec_sa_id_t *id, kernel_ipsec_add_sa_t *data,
	     const char *msg)
{
	print_sa_id(id, msg);
	DBG1(DBG_KNL, "kernel_vpp: %s: reqid %u replay_window %u udp_encap %u "
	     "esn %u initiator %u inbound %u update %u",
	     (msg) ? msg : __func__,
	     data->reqid, data->replay_window,
	     ((data->encap) ? 1 : 0),
	     ((data->esn) ? 1 : 0),
	     ((data->initiator) ? 1 : 0),
	     ((data->inbound) ? 1 : 0),
	     ((data->update) ? 1 : 0)
	);
}

/* get_routed_sa_sw_if_index - Given the number of the ipsec interface,
 * find it's sw_if_index
 *
 * a lock must be acquired prior to calling
 */
static u32
get_routed_sa_sw_if_index(private_kernel_vpp_ipsec_t *this, u32 inst_num)
{
	char intf_name[16] = {0};
	u32 sw_if_index;

	snprintf(intf_name, sizeof(intf_name) - 1, "ipip%u", inst_num);

	vmgmt_intf_mark_dirty();
	sw_if_index = vmgmt_intf_get_sw_if_index_by_name(intf_name);

	return sw_if_index;
}

typedef struct {
	private_kernel_vpp_ipsec_t *this;
	kernel_ipsec_sa_id_t id;
	int delete;
	u32 delete_delay;
} vpp_ipsec_sa_expire_t;


static job_requeue_t
vpp_ipsec_sa_expire(vpp_ipsec_sa_expire_t *expire)
{
	private_kernel_vpp_ipsec_t *this = expire->this;
	kernel_ipsec_sa_id_t *id = &expire->id;
	job_requeue_t ret = JOB_REQUEUE_NONE;

	this->mutex->lock(this->mutex);

	DBG1(DBG_KNL, "%s: %s SA (src %H dst %H spi %u)", __func__,
		 (expire->delete) ? "delete" : "rekey",
		 id->src, id->dst, ntohl(id->spi));

	charon->kernel->expire(charon->kernel, id->proto, id->spi, id->dst,
						   (expire->delete != 0));

	/* if this is a rekey, schedule a deletion for later */
	if (!expire->delete) {
		if (expire->delete_delay) {
			ret = JOB_RESCHEDULE(expire->delete_delay);
			DBG1(DBG_KNL, "%s: SA (src %H dst %H spi %u) delete in %u s "
				 "if rekey unsuccessful",
				 __func__, id->src, id->dst, ntohl(id->spi),
				 expire->delete_delay);
		}
		expire->delete = 1;
		expire->delete_delay = 0;
	} else {
		if (id->dst) {
			id->dst->destroy(id->dst);
			id->dst = NULL;
		}
		if (id->src) {
			id->src->destroy(id->src);
			id->src = NULL;
		}
	}

	this->mutex->unlock(this->mutex);

	return ret;
}

static void
schedule_expire(private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
				kernel_ipsec_add_sa_t *data)
{
	callback_job_t *job;
	vpp_ipsec_sa_expire_t *expire;
	u32 job_delay;

	/* bail if there's no time data */
	if (!data->lifetime || 
		(!data->lifetime->time.life  && !data->lifetime->time.rekey)) {
		return;
	}

	/* sanity check times and adjust if needed. rekey should be < lifetime. */
	INIT(expire,
			.this = this,
			.id = {
					.src = id->src->clone(id->src),
					.dst = id->dst->clone(id->dst),
					.spi = id->spi,
					.proto = id->proto,
					.mark = id->mark },
	);

	job_delay = data->lifetime->time.rekey;
	expire->delete_delay =
		data->lifetime->time.life - data->lifetime->time.rekey;

	job = callback_job_create((callback_job_cb_t) vpp_ipsec_sa_expire,
							  expire, (callback_job_cleanup_t) free, NULL);
	lib->scheduler->schedule_job(lib->scheduler, (job_t *) job, job_delay);
}


/*
 * Strongswan plugin interface methods & init
 *
 */

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
		private_kernel_vpp_ipsec_t *this)
{
	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
		private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
		uint8_t protocol, uint32_t *spi)
{
	u_int32_t newspi = 0;

	this->mutex->lock(this->mutex);
	if (!this->rng && !(this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK))) {
		DBG1(DBG_KNL, "kernel_vpp: %s: No RNG available", __func__);
		this->mutex->unlock(this->mutex);
		return FAILED;
	}

	if (!this->rng->get_bytes(this->rng, sizeof(newspi), (u_int8_t *) &newspi)) {
		DBG1(DBG_KNL, "kernel_vpp: %s: No bytes generated", __func__);
		this->mutex->unlock(this->mutex);
		return FAILED;
	}

	if (newspi < 256)
		newspi += 256;

	newspi = htonl(newspi);
	*spi = newspi;

	DBG1(DBG_KNL, "kernel_vpp: allocated SPI %lu", ntohl(newspi));
	this->mutex->unlock(this->mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
		private_kernel_vpp_ipsec_t *this, host_t *src, host_t *dst,
		uint16_t *cpi)
{
	return NOT_SUPPORTED;
}

/*
 * Calculate the dummy SA ID for an IPsec tunnel interface. The legacy
 * ipsec_tunnel_if API used these patterns for the IDs of the initial SAs
 * on a newly created tunnel interface:
 *   (0x80000000 | sw_if_index) for inbound
 *   (0xc0000000 | sw_if_index) for outbound
 */
static u32
ipsec_tunnel_protect_dummy_sa_id(u32 sw_if_index, u8 is_outbound)
{
	if (is_outbound) {
		return (0xc0000000 | sw_if_index);
	}

	return (0x80000000 | sw_if_index);
}

/* Check whether an SA is a dummy SA.
 *
 * Tunnel protect requires setting both an inbound and outbound SA. If the
 * SA in one direction has not been added yet, you cannot apply a tunnel
 * protect configuration. We don't want unencrypted traffic to leak in
 * cleartext, so when we don't have a negotiated SA in one or both directions,
 * we add dummies, which use the IDs that would have been initially
 * assigned by the legacy ipsec_tunnel_id API.
 */
static int
ipsec_tunnel_protect_sa_is_dummy(u32 sa_id, u32 sw_if_index, u8 is_outbound)
{
	if (sa_id == ipsec_tunnel_protect_dummy_sa_id(sw_if_index,
						      is_outbound)) {
		return 1;
	}

	return 0;
}

/* Add a new SA and set it to protect the tunnel interface.
 *
 * One of the existing ones may also need to be deleted:
 * - only one outbound SA can be set on the interface at a time. So delete
 *   the one being replaced.
 * - If a dummy inbound SA was set on the interface, it needs to be replaced
 *   and deleted.
 *
 * Lock must be acquired before this function is called.
 */
static int
ipsec_tunnel_protect_add_sa(u32 sw_if_index, vmgmt_ipsec_sa_t *sa_new)
{
	vmgmt_ipsec_tunnel_protect_t *tp_curr = NULL, tp_new;
	int ret, del_old = 0;
	u32 old_sa_id;

	ret = vmgmt_ipsec_tunnel_protect_get(sw_if_index, &tp_curr);
	if ((ret != 0) || (tp_curr == NULL)) {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: SAs not found: %d",
		     __func__, sw_if_index, ret);
		return ret;
	}

	memcpy(&tp_new, tp_curr, sizeof(tp_new));
	tp_new.sa_in = tnsr_vec_dup(tp_curr->sa_in);

	if (sa_new->outbound) {

		DBG1(DBG_KNL,
		     "kernel_vpp: %s: "
		     "interface %u: replace outbound SA (%u -> %u)",
		     __func__, sw_if_index, tp_new.sa_out, sa_new->sa_id);

		/* Delete old outbound SA ID if it was a dummy */
		old_sa_id = tp_new.sa_out;
		if (ipsec_tunnel_protect_sa_is_dummy (old_sa_id, sw_if_index,
						      1 /* is_outbound */)) {
			del_old = 1;
		}
		tp_new.sa_out = sa_new->sa_id;

	} else {

		/* If only existing inbound SA is a dummy, delete it */
		if (tp_new.sa_in) {
			old_sa_id = tp_new.sa_in[0];
		}
		if ((tnsr_vec_len(tp_new.sa_in) == 1) &&
		    ipsec_tunnel_protect_sa_is_dummy (old_sa_id, sw_if_index,
						      0 /* is_outbound */)) {

			DBG1(DBG_KNL, "kernel_vpp: %s: "
			     "interface %u: replace inbound SA (%u -> %u)",
			     __func__, sw_if_index, tp_new.sa_in[0],
			     sa_new->sa_id);

			del_old = 1;
			tnsr_vec_reset_length(tp_new.sa_in);
		} else {
			DBG1(DBG_KNL, "kernel_vpp: %s: "
			     "interface %u: appending inbound SA %u",
			     __func__, sw_if_index, sa_new->sa_id);
		}

		/* append to inbound SAs */
		tnsr_vec_add1(tp_new.sa_in, sa_new->sa_id);
	}

	ret = vmgmt_ipsec_sa_add(sa_new, NULL);
	if (ret != 0) {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: add SA %u failed: %d",
		     __func__, sw_if_index, sa_new->sa_id, ret);
		return ret;
	}

	ret = vmgmt_ipsec_tunnel_protect_update(&tp_new);
	tnsr_vec_free(tp_new.sa_in);

	if (ret != 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: "
		     "interface %u: ipsec tunnel protect update failed: %d",
		     __func__, sw_if_index, ret);
		return ret;
	}

	if (del_old && (old_sa_id != sa_new->sa_id)) {
		vmgmt_ipsec_sa_t *sa_curr = NULL;

		DBG1(DBG_KNL, "kernel_vpp: %s: "
		     "Interface %u: delete replaced SA %u (%s)",
		     __func__, sw_if_index, old_sa_id,
		     (sa_new->outbound) ? "outbound" : "inbound");

		vmgmt_ipsec_sa_get(old_sa_id, &sa_curr);
		if (sa_curr) {
			DBG1(DBG_KNL, "kernel_vpp: %s: "
			     "Interface %u: SA %u found during deletion of %u",
			     __func__, sw_if_index, sa_curr->sa_id, old_sa_id);
			vmgmt_ipsec_sa_del(sa_curr, 0);
		}
	}

	return 0;

}

/* Adding routed SA
 * The tunnel interface should already exist. It's name will be of the form
 * ipipX where X = id->mark.value - 1. ifindex could possibly be passed in
 * using new interface index field that was added recently.
 *
 * Add the SA and update the tunnel protect associations so the tunnel uses
 * it.
 */
static int
add_routed_sa(private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	      kernel_ipsec_add_sa_t *data)
{
	int ret = -1;
	u32 inst_num, sw_if_index;
	vmgmt_ipsec_sa_t sa_conf;

	inst_num = id->mark.value - 1;

	this->mutex->lock(this->mutex);

	memset(&sa_conf, 0, sizeof(sa_conf));
	convert_sa_to_vmgmt(&sa_conf, id, data);

	sw_if_index = get_routed_sa_sw_if_index(this, inst_num);
	if (sw_if_index  == ~0) {
		goto done;
	}

	ret = ipsec_tunnel_protect_add_sa(sw_if_index, &sa_conf);
	if (ret == 0) {
		schedule_expire(this, id, data);
	}

done:
	this->mutex->unlock(this->mutex);

	return ret;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_add_sa_t *data)
{
	int ret = 0;

	print_sa_add(id, data, __func__);

	if (kernel_vpp_check_connection(this) < 0) {
		return FAILED;
	}

	if (id->mark.value) {
		ret = add_routed_sa(this, id, data);
	}

	if (ret < 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: error adding SA: %d",
		     __func__, ret);
		return FAILED;
	}

	return SUCCESS;
}

/* ts_epoch_to_monotic - convert the last used time to monotonic
 * Parameters:
 *  ts_epoch    Seconds since epoch of last usage
 *  last_used   Pointer to time_t to update with monotonic timestamp
 * Return:
 *  <0		  Error
 *  0		   Success
 *
 * Strongswan wants the last_used timestamp to be a monotonic value. The
 * timestamps are stored as seconds since the epoch. Convert it.
 */
static int
ts_epoch_to_monotonic(time_t ts_epoch, time_t *last_used)
{
	struct timespec mono_time = { 0, };
	time_t secs_since_ts;

	if (!last_used) {
		return -1;
	}

	secs_since_ts = time(NULL) - ts_epoch;

	clock_gettime(CLOCK_MONOTONIC, &mono_time);

	if (ts_epoch == 0) {
		/* no usage yet */
		*last_used = 0;
	} else if (secs_since_ts <= mono_time.tv_sec) {
		*last_used = mono_time.tv_sec - secs_since_ts;
	} else {
		DBG1(DBG_KNL, "Last used timestamp %u appears to be invalid",
			 (unsigned int) ts_epoch);
		*last_used = 0;
	}

	return 0;
}

static int
query_routed_sa(private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
				kernel_ipsec_query_sa_t *data, uint64_t *bytes,
				uint64_t *packets, time_t *time)
{
	int ret = 0;
	time_t ts_last_used = 0;

	this->mutex->lock(this->mutex);

	ret = vmgmt_ipsec_sa_get_counters(ntohl(id->spi), bytes, packets,
					  &ts_last_used);
	this->mutex->unlock(this->mutex);

	ts_epoch_to_monotonic(ts_last_used, time);

	return ret;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_query_sa_t *data, uint64_t *bytes, uint64_t *packets,
		time_t *time)
{
	int ret = 0;

	if (kernel_vpp_check_connection(this) < 0) {
		return FAILED;
	}

	if (id->mark.value) {
		ret = query_routed_sa(this, id, data, bytes, packets, time);
	}
	if (ret < 0)
		return FAILED;

	return SUCCESS;
}

/* Check the SAs for the interface and remove the one being deleted.
 *
 * We would like to maintain the tunnel protect configuration even when
 * an SA has not been negotiated in at least one direction so that packets
 * routed to the interface will not leak unencrypted. Make sure that if
 * the only outbound SA or the last inbound SA is being deleted, that SAs
 * are still set.
 *
 * We used to just bring the tunnel interface down when this happened and
 * not allow it to be manually brought up or down. That was easier, but
 * people do not like it when an interface refuses to be brought up/down on
 * demand.
 *
 * Lock must be acquired before this function is called.
 */
static void
ipsec_tunnel_protect_del_sa(u32 sw_if_index, u32 sa_id)
{
	vmgmt_ipsec_tunnel_protect_t *tp_curr = NULL, tp_new;
	vmgmt_ipsec_sa_t *sa_curr = NULL, sa_copy;
	int ret, replace_old = 0;
	u32 sa_in_index;

	ret = vmgmt_ipsec_tunnel_protect_get(sw_if_index, &tp_curr);
	if ((ret != 0) || (tp_curr == NULL)) {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: SAs not found: %d",
		     __func__, sw_if_index, ret);
		return;
	}

	memcpy(&tp_new, tp_curr, sizeof(tp_new));
	tp_new.sa_in = tnsr_vec_dup(tp_curr->sa_in);

	/* Get existing SA data */
	vmgmt_ipsec_sa_get(sa_id, &sa_curr);
	if (sa_curr) {
		memcpy(&sa_copy, sa_curr, sizeof(sa_copy));
	} else {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: SA %u not found",
		     __func__, sw_if_index, sa_id);
		memset(&sa_copy, 0, sizeof(sa_copy));
		sa_copy.sa_id = sa_id;
		sa_copy.spi = sa_id;
	}

	/* not found on interface, skip interface update and just delete */
	sa_in_index = tnsr_vec_search(tp_new.sa_in, sa_id);
	if ((sa_id != tp_new.sa_out) && (sa_in_index == ~0)) {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: SA %u not protecting",
		     __func__, sw_if_index, sa_id);
		goto del_curr_sa;
	}

	/* if outbound SA being deleted, replace it. */
	if (tp_new.sa_out == sa_id) {

		replace_old = 1;

		sa_copy.sa_id =
			ipsec_tunnel_protect_dummy_sa_id (sw_if_index,
							  1 /* is_outbound */);
		sa_copy.spi = sa_copy.sa_id;
		sa_copy.crypto_alg = 0;
		sa_copy.integ_alg = 0;
		sa_copy.outbound = 1;

		tp_new.sa_out = sa_copy.sa_id;

		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: "
		     "Replace outbound SA (%u -> %u)",
		     __func__, sw_if_index, sa_id, sa_copy.sa_id);

	/* only one inbound SA, replace it */
	} else if (tnsr_vec_len(tp_new.sa_in) == 1) {

		replace_old = 1;

		sa_copy.sa_id =
			ipsec_tunnel_protect_dummy_sa_id (sw_if_index,
							  0 /* is_outbound */);
		sa_copy.spi = sa_copy.sa_id;
		sa_copy.crypto_alg = 0;
		sa_copy.integ_alg = 0;
		sa_copy.outbound = 0;

		tp_new.sa_in[0] = sa_copy.sa_id;

		DBG1(DBG_KNL, "kernel_vpp: %s: interface %u: "
		     "Replace inbound SA (%u -> %u)",
		     __func__, sw_if_index, sa_id, sa_copy.sa_id);
	} else {

		DBG1(DBG_KNL, "kernel_vpp: %s: interface %u: "
		     "Removing inbound SA %u",
		     __func__, sw_if_index, sa_id);

		tnsr_vec_delete(tp_new.sa_in, 1, sa_in_index);
	}

	/* Replacing outbound SA, or only inbound SA, add replacement first */
	if (replace_old) {
		vmgmt_ipsec_sa_add(&sa_copy, NULL);
	}
		

	ret = vmgmt_ipsec_tunnel_protect_update(&tp_new);
	tnsr_vec_free(tp_new.sa_in);

	if (ret != 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: interface %u"
		     "Failed to update SAs: %d",
		     __func__, sw_if_index, ret);
	}

del_curr_sa:
	if (sa_curr) {
		DBG1(DBG_KNL, "kernel_vpp: %s: interface %u: Deleting SA %u",
		     __func__, sw_if_index, sa_id);

		/* Use local copy. Put IDs back in case they were changed */
		sa_copy.sa_id = sa_id;
		sa_copy.spi = sa_id;
		vmgmt_ipsec_sa_del(&sa_copy, 0);
	}

	return;
}

/*
 * Deleting routed SA - remove the SA from the interface tunnel protect
 * associations.
 */
static int
del_routed_sa(private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
	      kernel_ipsec_del_sa_t *data)
{
	int ret = 0;
	u32 inst_num = id->mark.value - 1;
	u32 sw_if_index;

	this->mutex->lock(this->mutex);

	/* maybe update the SAs on the interface */
	sw_if_index = get_routed_sa_sw_if_index(this, inst_num);
	if (sw_if_index  == ~0) {
                DBG1(DBG_KNL,
		     "kernel_vpp: %s: No interface found for tunnel %u",
		     __func__, inst_num);
	} else {
		ipsec_tunnel_protect_del_sa(sw_if_index, ntohl(id->spi));
	}

	this->mutex->unlock(this->mutex);

	return ret;
}

METHOD(kernel_ipsec_t, del_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_del_sa_t *data)
{
	int ret = 0;

	print_sa_id(id, __func__);

	if (kernel_vpp_check_connection(this) < 0) {
		return FAILED;
	}

	if (id->mark.value) {
		ret = del_routed_sa(this, id, data);
	}


	if (ret < 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: SA delete returned %d",
		     __func__, ret);
		return FAILED;
	}

	return SUCCESS;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_update_sa_t *data)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t,
		private_kernel_vpp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

static int
query_routed_policy(private_kernel_vpp_ipsec_t *this,
					kernel_ipsec_policy_id_t *id,
					kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	int ret = -1;
	u32 inst_num, sw_if_index;
	int outbound = 0;
	vmgmt_ipsec_tunnel_protect_t *tp = NULL;
	time_t ts_sa, ts_max = 0;
	u32 *sa_ids = 0, *sa_id;

	inst_num = id->mark.value - 1;

	if (id->dir == POLICY_OUT) {
		outbound = 1;
	} 

	this->mutex->lock(this->mutex);

	sw_if_index = get_routed_sa_sw_if_index(this, inst_num);
	if (sw_if_index  == ~0) {
                DBG1(DBG_KNL,
		     "kernel_vpp: %s: No interface found for tunnel %u",
		     __func__, inst_num);
		goto done;
	}

	ret = vmgmt_ipsec_tunnel_protect_get(sw_if_index, &tp);
	if ((ret != 0) || (tp == NULL)) {
		DBG1(DBG_KNL,
		     "kernel_vpp: %s: interface %u: SAs not found: %d",
		     __func__, sw_if_index, ret);
		goto done;
	}

	if (outbound) {
		tnsr_vec_add1(sa_ids, tp->sa_out);
	} else {
		sa_ids = tnsr_vec_dup(tp->sa_in);
	}

	tnsr_vec_foreach(sa_id, sa_ids) {
		ret = vmgmt_ipsec_sa_get_counters(*sa_id, 0, 0, &ts_sa);
		if (!ret && use_time && (ts_sa > ts_max)) {
			ts_max = ts_sa;
		}
	}

	if (use_time) {
		ts_epoch_to_monotonic(ts_max, use_time);
	}

done:
	tnsr_vec_free(sa_ids);
	this->mutex->unlock(this->mutex);

	return ret;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_query_policy_t *data, time_t *use_time)
{
	int ret;

	ret = query_routed_policy(this, id, data, use_time);
	if (ret < 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: Error querying policy",
				__func__);
		return FAILED;
	}
	
	return SUCCESS;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_policy_id_t *id,
		kernel_ipsec_manage_policy_t *data)
{
	return SUCCESS;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
		private_kernel_vpp_ipsec_t *this)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, bypass_socket, bool,
		private_kernel_vpp_ipsec_t *this, int fd, int family)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
		private_kernel_vpp_ipsec_t *this, int fd, int family, uint16_t port)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, destroy, void,
		private_kernel_vpp_ipsec_t *this)
{
	this->mutex->destroy(this->mutex);
	this->rng->destroy(this->rng);

	vmgmt_disconnect();
	free(this);
}

kernel_vpp_ipsec_t *kernel_vpp_ipsec_create()
{
	private_kernel_vpp_ipsec_t *this;

	INIT(this,
			.public = {
				.interface = {
					.get_features   	= _get_features,
					.get_spi			= _get_spi,
					.get_cpi			= _get_cpi,
					.add_sa		 	= _add_sa,
					.update_sa	  	= _update_sa,
					.query_sa	   	= _query_sa,
					.del_sa			 = _del_sa,
					.flush_sas		  = _flush_sas,
					.add_policy		 = _add_policy,
					.query_policy	   = _query_policy,
					.del_policy		 = _del_policy,
					.flush_policies	 = _flush_policies,
					.bypass_socket	  = _bypass_socket,
					.enable_udp_decap   = _enable_udp_decap,
					.destroy			= _destroy,
				},
			},
			.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
			.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
	);

	if (vmgmt_init("iked_ipsec", 0) < 0) {
		DBG1(DBG_KNL, "Connection to VPP API failed");
	}

	return &this->public;
}

