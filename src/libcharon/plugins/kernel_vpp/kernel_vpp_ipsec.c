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
#include <errno.h>

/* this plugin */
#include "kernel_vpp_ipsec.h"

/* strongswan lib */
#include <daemon.h>
#include <threading/mutex.h>
#include <collections/hashtable.h>
#include <processing/jobs/callback_job.h>

#include <tnsrinfra/vec.h>
#include <tnsrinfra/pool.h>
#include <tnsrinfra/hash.h>
#include <vppmgmt2/vpp_mgmt2_api.h>
#include <vppmgmt2/vpp_mgmt2_ipsec.h>
#include <vppmgmt2/vpp_mgmt2_if.h>
#include <vppmgmt2/vpp_mgmt2_teib.h>

#define PRIO_BASE 100000

/*
 * Definitions and helper functions for strongswan plugin
 *
 */

typedef struct private_kernel_vpp_ipsec_t {

	kernel_vpp_ipsec_t public;
	
	mutex_t *mutex;

	rng_t *rng;

} private_kernel_vpp_ipsec_t;

typedef struct private_kernel_vpp_listener_t {
	kernel_vpp_listener_t public;
} private_kernel_vpp_listener_t;

static private_kernel_vpp_ipsec_t *vpp_ipsec;

/* pool of pending tunnel protect updates
 *
 * Each pool entry contains a vector of tunnel protect update data to apply
 * for an outbound SA after it is installed.
 */
static vapi_type_ipsec_tunnel_protect **pending_tp_pool;

/* hash of outbound SA ID to pool index */
static uword *said2poolidx;


/* Retrieve a vector of pending updates for an SA ID if one exists. */
static vapi_type_ipsec_tunnel_protect **
lookup_pending_tp(u32 sa_id)
{
	vapi_type_ipsec_tunnel_protect **tp_vec = NULL;
	uword *p;

	p = tnsr_hash_get(said2poolidx, sa_id);
	if (p != NULL) {
		tp_vec = tnsr_pool_elt_at_index(pending_tp_pool, *p);
	}

	return tp_vec;
}


/* Add new pending tunnel protect data for an outbound SA */
static int
add_pending_tp(vapi_type_ipsec_tunnel_protect *tp)
{
	vapi_type_ipsec_tunnel_protect **tp_vec;
       
	if (tp == NULL) {
		return -EINVAL;
	}

	tp_vec = lookup_pending_tp(tp->sa_out);
	if (tp_vec == NULL) {
		tnsr_pool_get_zero(pending_tp_pool, tp_vec);
		tnsr_hash_set(said2poolidx, tp->sa_out,
			      tp_vec - pending_tp_pool);
	}

	tnsr_vec_add1(*tp_vec, *tp);

	return 0;
}


/* Delete the pending tunnel protect data for an outbound SA */
static void
del_pending_tp(u32 sa_id)
{
	vapi_type_ipsec_tunnel_protect **tp_vec = lookup_pending_tp(sa_id);
	vapi_type_ipsec_tunnel_protect *tp;

	if (tp_vec == NULL) {
		return;
	}

	tnsr_vec_free(*tp_vec);
	tnsr_hash_unset(said2poolidx, sa_id);
	tnsr_pool_put(pending_tp_pool, tp_vec);
}


/* After an outbound SA has been added, if there were pending tunnel protect
 * updates involving that SA, apply them.
 *
 * This would happen on a rekey because there is a delay in installing an
 * outbound child SA.
 */
static void
process_pending_tp(u32 sa_id)
{
	vapi_type_ipsec_tunnel_protect **tp_vec = lookup_pending_tp(sa_id);
	vapi_type_ipsec_tunnel_protect *tp;

	if (tp_vec == NULL) {
		return;
	}

	tnsr_vec_foreach(tp, *tp_vec) {
		vapi_type_ipsec_tunnel_protect *tp_curr = NULL;
		u32 *sas_in = NULL;
		vmgmt2_error ret;

		/* Lookup existing tunnel protect data & reuase inbound SAs */
		ret = vmgmt2_ipsec_tunnel_protect_get(tp->sw_if_index,
						      &tp->nh, &tp_curr,
						      &sas_in);
		if ((ret != VMGMT2_ERR_OK) || (sas_in == NULL)) {
			DBG1(DBG_KNL,
			     "%s: tunnel protect lookup failed for SA %u",
			     __func__, sa_id);
			continue;
		}

		ret = vmgmt2_ipsec_tunnel_protect_update(tp, sas_in);
		if (ret != VMGMT2_ERR_OK) {
			DBG1(DBG_KNL,
			     "%s: tunnel protect update failed for SA %u",
			     __func__, sa_id);
			continue;
		}
	}

	del_pending_tp(sa_id);
}


static void
destroy_pending_tp(void)
{
	vapi_type_ipsec_tunnel_protect **tp_vec;

	tnsr_hash_free(said2poolidx);
	tnsr_pool_foreach(tp_vec, pending_tp_pool, ({
		tnsr_vec_free(*tp_vec);
	}));
	tnsr_pool_free(pending_tp_pool);
}


static void
init_pending_tp(void)
{
	said2poolidx = tnsr_hash_create(0, sizeof(uword));
}


static int
kernel_vpp_check_connection(private_kernel_vpp_ipsec_t *this)
{
	int ret;

	this->mutex->lock(this->mutex);
	ret = vmgmt2_check_connection();
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
	int ss_alg;
	int keylen;
	int vpp_alg;
} vpp_alg;

static vpp_alg encr_alg_map[] = {
	{ ENCR_NULL, 0, IPSEC_API_CRYPTO_ALG_NONE, },
	{ ENCR_AES_CBC, 128, IPSEC_API_CRYPTO_ALG_AES_CBC_128, },
	{ ENCR_AES_CBC, 192, IPSEC_API_CRYPTO_ALG_AES_CBC_192, },
	{ ENCR_AES_CBC, 256, IPSEC_API_CRYPTO_ALG_AES_CBC_256, },
	{ ENCR_AES_CTR, 128, IPSEC_API_CRYPTO_ALG_AES_CTR_128, },
	{ ENCR_AES_CTR, 192, IPSEC_API_CRYPTO_ALG_AES_CTR_192, },
	{ ENCR_AES_CTR, 256, IPSEC_API_CRYPTO_ALG_AES_CTR_256, },
	{ ENCR_AES_GCM_ICV16, 160, IPSEC_API_CRYPTO_ALG_AES_GCM_128, },
	{ ENCR_AES_GCM_ICV16, 224, IPSEC_API_CRYPTO_ALG_AES_GCM_192, },
	{ ENCR_AES_GCM_ICV16, 288, IPSEC_API_CRYPTO_ALG_AES_GCM_256, },
	{ ENCR_CHACHA20_POLY1305, 288, IPSEC_API_CRYPTO_ALG_CHACHA20_POLY1305, },
};
static int n_encr_algs = sizeof(encr_alg_map)/sizeof(encr_alg_map[0]);

static vpp_alg integ_alg_map[] = {
	{ AUTH_HMAC_MD5_96, 128, IPSEC_API_INTEG_ALG_MD5_96, },
	{ AUTH_HMAC_SHA1_96, 160, IPSEC_API_INTEG_ALG_SHA1_96, },
	{ AUTH_HMAC_SHA2_256_128, 256, IPSEC_API_INTEG_ALG_SHA_256_128, },
	{ AUTH_HMAC_SHA2_384_192, 384, IPSEC_API_INTEG_ALG_SHA_384_192, },
	{ AUTH_HMAC_SHA2_512_256, 512, IPSEC_API_INTEG_ALG_SHA_512_256, },
	{ AUTH_UNDEFINED, 0, IPSEC_API_INTEG_ALG_NONE, },
};
static int n_integ_algs = sizeof(integ_alg_map)/sizeof(integ_alg_map[0]);

static int
vpp_alg_lookup(int alg, int keylen, int is_encr)
{
	vpp_alg *map;
	int i, n;

	if (is_encr) {
		map = encr_alg_map;
		n = n_encr_algs;
	} else {
		map = integ_alg_map;
		n = n_integ_algs;
	}

	for (i = 0; i < n; i++) {
		vpp_alg *algp = map + i;

		if (algp->ss_alg == alg && algp->keylen == keylen)
			return algp->vpp_alg;
	}

	/* We only allow configuration of algs VPP supports, so we should
	 * never reach this point.
	 */
	return -EINVAL;
}

static int
vpp_enc_alg(int alg, int keybits)
{
	int ret = vpp_alg_lookup(alg, keybits, 1 /* is_encr */);

	return (ret == -EINVAL) ? IPSEC_API_CRYPTO_ALG_NONE : ret;
}

static int
vpp_auth_alg(int alg, int keybits)
{
	int ret = vpp_alg_lookup(alg, keybits, 0 /* is_encr */);

	return (ret == -EINVAL) ? IPSEC_API_CRYPTO_ALG_NONE : ret;
}

/* Keys for AES-GCM and chacha20/poly1305 includes 4 bytes of salt for the
 * nonce. Subtract from the key length for these algs
 */
static int
vpp_enc_key_len(int alg, int keybytes)
{
	return (alg == ENCR_AES_GCM_ICV16 || alg == ENCR_CHACHA20_POLY1305) ?
		keybytes - 4 : keybytes;
}

static int
convert_host_to_vapi(vapi_type_address *addr, host_t *host)
{
	if (!addr || !host) {
		return -EINVAL;
	}

	memset(addr, 0, sizeof(*addr));
	addr->af = (host->get_family(host) == AF_INET6) ?
			ADDRESS_IP6 : ADDRESS_IP4;
	memcpy(&addr->un, host->get_address(host).ptr,
	       host->get_address(host).len);

        return 0;
}

static int
convert_sa_to_vapi(vapi_type_ipsec_sad_entry_v3 *sa,
					kernel_ipsec_sa_id_t *id,
					kernel_ipsec_add_sa_t *data)
{
	int addr_len = 4;

	if (!sa || !id || !data) {
		return -EINVAL;
	}

	sa->spi = ntohl(id->spi);
	sa->sad_id = sa->spi;
	sa->protocol = IPSEC_API_PROTO_ESP;

	sa->crypto_algorithm =
		vpp_enc_alg(data->enc_alg, data->enc_key.len * 8);
	sa->crypto_key.length =
		vpp_enc_key_len(data->enc_alg, data->enc_key.len);
	memcpy(sa->crypto_key.data, data->enc_key.ptr, sa->crypto_key.length);
	/* Copy salt if needed */
	if (sa->crypto_key.length &&
	    (sa->crypto_key.length < data->enc_key.len)) {
		memcpy(&sa->salt, data->enc_key.ptr + sa->crypto_key.length,
		       4);
		/* Byte swap salt. It shouldn't be necessary, but the API
		 * message defines it as a u32 instead of a u8[] so libvapi
		 * automatically swaps it. 
		 */
		sa->salt = htonl(sa->salt);
	}

	sa->integrity_algorithm =
		vpp_auth_alg(data->int_alg, data->int_key.len * 8);
	sa->integrity_key.length = data->int_key.len;
	memcpy(sa->integrity_key.data, data->int_key.ptr, data->int_key.len);

	if (data->esn) {
		sa->flags |= IPSEC_API_SAD_FLAG_USE_ESN;
	}
	if (data->replay_window) {
		sa->flags |= IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY;
	}
	if (id->src->get_family(id->src) == AF_INET6) {
		sa->flags |= IPSEC_API_SAD_FLAG_IS_TUNNEL_V6;
		sa->tunnel.src.af = ADDRESS_IP6;
		sa->tunnel.dst.af = ADDRESS_IP6;
		memcpy(&sa->tunnel.src.un.ip6,
		       id->src->get_address(id->src).ptr, 16);
		memcpy(&sa->tunnel.dst.un.ip6,
		       id->dst->get_address(id->dst).ptr, 16);
	} else {
		addr_len = 4;
		sa->tunnel.src.af = ADDRESS_IP4;
		sa->tunnel.dst.af = ADDRESS_IP4;
		memcpy(&sa->tunnel.src.un.ip4,
		       id->src->get_address(id->src).ptr, 4);
		memcpy(&sa->tunnel.dst.un.ip4,
		       id->dst->get_address(id->dst).ptr, 4);
	}
	if (data->inbound) {
		sa->flags |= IPSEC_API_SAD_FLAG_IS_INBOUND;
	}
	if (data->encap) {
		sa->flags |= IPSEC_API_SAD_FLAG_UDP_ENCAP;
		sa->udp_src_port = id->src->get_port(id->src);
		sa->udp_dst_port = id->dst->get_port(id->dst);
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

	DBG1(DBG_KNL, "kernel_vpp: %s: src %s:%d dst %s:%d "
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
	sw_if_index = vmgmt2_if_name_to_index(intf_name,
					      true /* force_refresh */);

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

METHOD(kernel_ipsec_t, add_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_add_sa_t *data)
{
	int ret = 0;
	vapi_type_ipsec_sad_entry_v3 sa_conf;

	print_sa_add(id, data, __func__);

	if (kernel_vpp_check_connection(this) < 0) {
		return FAILED;
	}

	memset(&sa_conf, 0, sizeof(sa_conf));
	convert_sa_to_vapi(&sa_conf, id, data);

	this->mutex->lock(this->mutex);
	ret = vmgmt2_ipsec_sa_add(&sa_conf);
	/* outbound SAs need to be applied after a rekey */
	if (!ret && !data->inbound) {
		process_pending_tp(sa_conf.sad_id);
	}
	this->mutex->unlock(this->mutex);

	if (ret != 0) {
		DBG1(DBG_KNL, "kernel_vpp: %s: error adding SA: %d",
		     __func__, ret);
	} else {
		schedule_expire(this, id, data);
	}

	return (ret == 0) ? SUCCESS : FAILED;
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

	ret = vmgmt2_ipsec_sa_get_counters(ntohl(id->spi), packets, bytes,
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

METHOD(kernel_ipsec_t, del_sa, status_t,
		private_kernel_vpp_ipsec_t *this, kernel_ipsec_sa_id_t *id,
		kernel_ipsec_del_sa_t *data)
{
	int ret = 0;

	print_sa_id(id, __func__);

	if (kernel_vpp_check_connection(this) < 0) {
		return FAILED;
	}

	this->mutex->lock(this->mutex);
	ret = vmgmt2_ipsec_sa_del(ntohl(id->spi));
	this->mutex->unlock(this->mutex);

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
	vapi_type_ipsec_tunnel_protect *tp = NULL;
	time_t ts_sa, ts_max = 0;
	u32 *sas_in = NULL, *sa_ids = NULL, *sa_id;

	inst_num = id->mark.value - 1;

	if (id->dir == POLICY_OUT) {
		outbound = 1;
	} 

	this->mutex->lock(this->mutex);

	sw_if_index = get_routed_sa_sw_if_index(this, inst_num);
	if (sw_if_index  == ~0) {
                DBG1(DBG_KNL, "%s: No interface found for tunnel %u",
		     __func__, inst_num);
		goto done;
	}

	ret = vmgmt2_ipsec_tunnel_protect_get(sw_if_index, NULL, &tp, &sas_in);
	if (ret || !tp || !sas_in) {
		DBG1(DBG_KNL, "%s: interface %u: SAs not found: %d",
		     __func__, sw_if_index, ret);
		goto done;
	}

	if (outbound) {
		tnsr_vec_add1(sa_ids, tp->sa_out);
	} else {
		sa_ids = tnsr_vec_dup(sas_in);
	}

	tnsr_vec_foreach(sa_id, sa_ids) {
		u64 bytes, pkts;

		ret = vmgmt2_ipsec_sa_get_counters(*sa_id, &pkts, &bytes,
						   &ts_sa);
		if (!ret && (ts_sa > ts_max)) {
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

	vmgmt2_disconnect();
	destroy_pending_tp();
	free(this);
}

/* Add or delete TEIB entries as virtual IP addresses are allocated or
 * deallocated.
 *
 * Connections are named after the tunnel interface, which allows us to
 * retrieve the ifindex. 
 */
METHOD(listener_t, assign_vips, bool,
       kernel_vpp_listener_t *this, ike_sa_t *ike_sa, bool assign)
{
	char *if_name = ike_sa->get_name(ike_sa);
	host_t *rhost = ike_sa->get_other_host(ike_sa);
	host_t *vip;
	enumerator_t *vip_enum;
	u32 if_index;
	vapi_type_teib_entry teib;

	vpp_ipsec->mutex->lock(vpp_ipsec->mutex);

	if_index = vmgmt2_if_name_to_index(if_name, true /* force_refresh */);
	if (if_index == ~0) {
		vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);
		return true;
	}

	memset(&teib, 0, sizeof(teib));
	teib.sw_if_index = if_index;
	convert_host_to_vapi(&teib.nh, rhost);

	vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (vip_enum->enumerate(vip_enum, &vip)) {
		vmgmt2_error ret;
		vapi_type_ipsec_tunnel_protect *tp = NULL;
		u32 *sas_in = NULL;

		convert_host_to_vapi(&teib.peer, vip);
		vmgmt2_ipsec_tunnel_protect_get(if_index, &teib.peer, &tp,
						&sas_in);
		if (assign) {
			ret = vmgmt2_teib_entry_add(&teib);
		} else {
			ret = vmgmt2_teib_entry_del(&teib);
			vmgmt2_ipsec_tunnel_protect_del(if_index, &teib.peer,
							0 /* del_sas */);
		}
		DBG1(DBG_KNL, "%s: TEIB entry for VIP %H %s on interface %s "
		     "(local %H remote %H) - status %d",
		     __func__, vip, (assign) ? "added" : "removed", if_name,
		     ike_sa->get_my_host(ike_sa), rhost, ret);
	}
	vip_enum->destroy(vip_enum);
	vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);

	return true;
}

static vapi_type_address *
convert_ike_sa_vips_to_vapi(ike_sa_t *ike_sa)
{
	vapi_type_address *vip_addrs = NULL, *vip_addr;
	host_t *vip;
	enumerator_t *vip_enum;

	vip_enum = ike_sa->create_virtual_ip_enumerator(ike_sa, FALSE);
	while (vip_enum->enumerate(vip_enum, &vip)) {
                tnsr_vec_add2(vip_addrs, vip_addr, 1);
		convert_host_to_vapi(vip_addr, vip);
	}
	vip_enum->destroy(vip_enum);

	return vip_addrs;
}

/* If a new child was installed, its SAs were just added. This might be the
 * first set of SAs or a rekey.
 * In either case, we will change the outbound SA to be the new one that was
 * just added.
 * If there are existing valid (not "dummy") inbound SAs, we will keep those
 * and add the new one. If there are no existing valid inbound SAs, we will
 * just use the new one.
 */
static int
tunnel_protect_child_add(u32 if_index, vapi_type_address *nh,
			 child_sa_t *child_sa)
{
	vapi_type_ipsec_tunnel_protect *tp = NULL;
	vapi_type_ipsec_tunnel_protect tp_new;
	int ret;
	u32 *sa, *sas_in_new = NULL, *sas_in = NULL;
	u32 child_out, child_in;
	vapi_payload_ipsec_sa_v3_details *sa_details;

	ret = vmgmt2_ipsec_tunnel_protect_get(if_index, nh, &tp, &sas_in);
	if ((ret != VMGMT2_ERR_OK) && (ret != VMGMT2_ERR_NO_SUCH_ENTRY)) {
		char addr_str[64];

		memset(addr_str, 0, sizeof(addr_str));
		if (nh != NULL) {
			inet_ntop((nh->af == ADDRESS_IP6) ? AF_INET6 : AF_INET,
				  &nh->un, addr_str, sizeof(addr_str));
		}
		DBG1(DBG_KNL, "%s: interface %u (nh %s) lookup failed (%d)",
		     __func__, if_index, (nh != NULL) ? addr_str : "none",
		     ret);
		return ret;
	}

	child_out = ntohl(child_sa->get_spi(child_sa, FALSE /* inbound */));
	child_in = ntohl(child_sa->get_spi(child_sa, TRUE /* inbound */));

	memset(&tp_new, 0, sizeof(tp_new));
	tp_new.sw_if_index = if_index;
	tp_new.sa_out = child_out;
	if (nh != NULL) {
		memcpy(&tp_new.nh, nh, sizeof(*nh));
	}

	/* On a rekey, the outbound SA probably won't exist at the time the
	 * child transitions to the installed state. If the outbound SA
	 * doesn't exist yet, add the tp data to a queue of pending updates
	 * and keep the existing outbound SA active.
	 */
	sa_details = vmgmt2_ipsec_sa_get(child_out);
	if (sa_details == NULL) {
		DBG1(DBG_KNL,
		     "%s: outbound SA %u not found, adding to update queue ",
		    __func__, child_out);
		add_pending_tp(&tp_new);

		if (tp != NULL) {
			tp_new.sa_out = tp->sa_out;
                } else {
			tp_new.sa_out =
				ipsec_tunnel_protect_dummy_sa_id
                                        (if_index, 1 /* is _outbound */);
		}
		DBG1(DBG_KNL, "%s: using outbound SA %u", __func__,
		     tp_new.sa_out);
	}

	/* If there were existing non-dummy inbound SAs keep them */
	tnsr_vec_foreach(sa, sas_in) {
		if (!ipsec_tunnel_protect_sa_is_dummy(*sa, if_index,
						      0 /* is_outbound */)) {
			tnsr_vec_add1(sas_in_new, *sa);
		}
	}
	/* append new inbound and get rid of any extras */
	tnsr_vec_add1(sas_in_new, child_in);
	if (tnsr_vec_len(sas_in_new) > 4) {
		tnsr_vec_delete(sas_in_new, tnsr_vec_len(sas_in_new) - 4, 0);
	}

	ret = vmgmt2_ipsec_tunnel_protect_update(&tp_new, sas_in_new);
	if (ret != VMGMT2_ERR_OK) {
		DBG1(DBG_KNL,
		     "%s: interface %u: tunnel protect update failed: %d",
		     __func__, if_index, ret);
        }

	tnsr_vec_free(sas_in_new);

	return 0;
}

/* If a child was rekeyed or is about to be deleted, remove it's SAs from the
 * tun protect data for the interface (+ peer if applicable)
 */
static int
tunnel_protect_child_del(u32 if_index, vapi_type_address *nh,
			 child_sa_t *child_sa)
{
	vapi_type_ipsec_tunnel_protect *tp = NULL;
	vapi_type_ipsec_tunnel_protect tp_new;
	int ret;
	u32 *sa, *sas_in_new = NULL, *sas_in = NULL;
	u32 child_out, child_in, child_in_index;

	memset(&tp_new, 0, sizeof(tp_new));
	tp_new.sw_if_index = if_index;
	ret = vmgmt2_ipsec_tunnel_protect_get(if_index, nh, &tp, &sas_in);
	if ((ret != VMGMT2_ERR_OK) && (ret != VMGMT2_ERR_NO_SUCH_ENTRY)) {
		char addr_str[64];

		memset(addr_str, 0, sizeof(addr_str));
		if (nh != NULL) {
			inet_ntop((nh->af == ADDRESS_IP6) ? AF_INET6 : AF_INET,
				  &nh->un, addr_str, sizeof(addr_str));
		}
		DBG1(DBG_KNL, "%s: interface %u (nh %s) lookup failed (%d)",
		     __func__, if_index, (nh != NULL) ? addr_str : "none",
		     ret);
		return ret;
	}

	child_out = ntohl(child_sa->get_spi(child_sa, FALSE /* inbound */));
	child_in = ntohl(child_sa->get_spi(child_sa, TRUE /* inbound */));
	child_in_index = tnsr_vec_search(sas_in, child_in);

	/* If neither child SAs currently protecting, do nothing */
	if ((tp->sa_out != child_out) && (child_in_index == ~0)) {
		return 0;
	}

	/* Outbound:
	 * If this child's SA is protecting, replace with a dummy SA
	 * Else, just keep whatever SA was already in use
	 */
	tp_new.sa_out = (tp->sa_out != child_out) ? tp->sa_out :
		ipsec_tunnel_protect_dummy_sa_id(if_index, 1 /* is_outbound */);
	if (nh != NULL) {
		memcpy(&tp_new.nh, nh, sizeof(*nh));
	}

	/* Inbound:
	 * Keep any existing SAs aside from this child's SA
	 */
	sas_in_new = tnsr_vec_dup(sas_in);
	if (child_in_index != ~0) {
		tnsr_vec_delete(sas_in_new, 1, child_in_index);
	}

	/* If no inbound SAs, use a dummy */
	if (tnsr_vec_len(sas_in_new) == 0) {
		tnsr_vec_add1(sas_in_new,
			      ipsec_tunnel_protect_dummy_sa_id(if_index, 0 /* is _outbound */));
	}

	ret = vmgmt2_ipsec_tunnel_protect_update(&tp_new, sas_in_new);
	if (ret != VMGMT2_ERR_OK) {
		DBG1(DBG_KNL,
		     "%s: interface %u: tunnel protect update failed: %d",
		     __func__, if_index, ret);
        }

	tnsr_vec_free(sas_in_new);

	return 0;
}

static int
tunnel_protect_child_installed(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	char *if_name = ike_sa->get_name(ike_sa);
	u32 if_index = ~0;
	int ret = 0;
	vapi_type_address *vip_addrs, *vip_addr;

	vpp_ipsec->mutex->lock(vpp_ipsec->mutex);

	if_index = vmgmt2_if_name_to_index(if_name, true /* force_refresh */);
	if (if_index == ~0) {
		DBG1(DBG_KNL, "%s: Cannot find interface %s", __func__,
		     if_name);
		vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);
		return -ENOENT;
	}

	vip_addrs = convert_ike_sa_vips_to_vapi(ike_sa);
	vip_addr = vip_addrs;

	/* P2P will update tunnel protect once
	 * P2MP will update once for each vip
	 */
	do {
		ret = tunnel_protect_child_add(if_index, vip_addr, child_sa);
		if ((vip_addr == NULL) || (ret != 0)) {
			break;
		}
		vip_addr++;
	} while (vip_addr < tnsr_vec_end(vip_addrs));

	vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);
	tnsr_vec_free(vip_addrs);

	return ret;
}

static int
tunnel_protect_child_deleting(ike_sa_t *ike_sa, child_sa_t *child_sa)
{
	char *if_name = ike_sa->get_name(ike_sa);
	u32 if_index = ~0;
	int ret = 0;
	vapi_type_address *vip_addrs, *vip_addr;

	vpp_ipsec->mutex->lock(vpp_ipsec->mutex);

	if_index = vmgmt2_if_name_to_index(if_name, true /* force_refresh */);
	if (if_index == ~0) {
		DBG1(DBG_KNL, "%s: Cannot find interface %s", __func__,
		     if_name);
		vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);
		return -ENOENT;
	}

	vip_addrs = convert_ike_sa_vips_to_vapi(ike_sa);
	vip_addr = vip_addrs;

	/* P2P will update tunnel protect once
	 * P2MP will update once for each vip
	 */
	do {
		ret = tunnel_protect_child_del(if_index, vip_addr, child_sa);
		if ((vip_addr == NULL) || (ret != 0)) {
			break;
		}
		vip_addr++;
	} while (vip_addr < tnsr_vec_end(vip_addrs));

	/* Delete any pending tp updates for the outbound SA */
	del_pending_tp(ntohl(child_sa->get_spi(child_sa, FALSE /* inbound */)));

	vpp_ipsec->mutex->unlock(vpp_ipsec->mutex);
	tnsr_vec_free(vip_addrs);

	return ret;
}

METHOD(listener_t, child_state_change, bool,
       private_kernel_vpp_listener_t *this, ike_sa_t *ike_sa,
       child_sa_t *child_sa, child_sa_state_t state)
{
	DBG1(DBG_KNL, "%s: child sa %s state %N -> %N : local %H remote %H "
		      "inbound spi %u outbound spi %u",
	     __func__, child_sa->get_name(child_sa),
	     child_sa_state_names, child_sa->get_state(child_sa),
	     child_sa_state_names, state,
	     ike_sa->get_my_host(ike_sa), ike_sa->get_other_host(ike_sa),
	     ntohl(child_sa->get_spi(child_sa, TRUE /* inbound */)),
	     ntohl(child_sa->get_spi(child_sa, FALSE /* inbound */)));

	switch (state) {
	case CHILD_INSTALLED:
		tunnel_protect_child_installed(ike_sa, child_sa);
		break;
	case CHILD_REKEYED:
	case CHILD_DELETING:
	case CHILD_DESTROYING:
		tunnel_protect_child_deleting(ike_sa, child_sa);
		break;
	default:
		break;
	}

	return true;
}

kernel_vpp_listener_t *kernel_vpp_listener_create()
{
	private_kernel_vpp_listener_t *this;

	INIT(this,
		.public = {
			.listener = {
				.assign_vips = _assign_vips,
				.child_state_change = _child_state_change,
			},
		},
	);

	charon->bus->add_listener(charon->bus, &this->public.listener);

	return &this->public;
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

	if (vmgmt2_init("ss_kernel_vpp") < 0) {
		DBG1(DBG_KNL, "Connection to VPP API failed");
	}

	vpp_ipsec = this;
	init_pending_tp();
	kernel_vpp_listener_create();

	return &this->public;
}
