/*
 * Copyright (C) 2009 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#include "cred_encoding.h"

#include <stdint.h>

#include <utils/linked_list.h>
#include <utils/hashtable.h>
#include <threading/rwlock.h>

typedef struct private_cred_encoding_t private_cred_encoding_t;

/**
 * Private data of an cred_encoding_t object.
 */
struct private_cred_encoding_t {

	/**
	 * Public cred_encoding_t interface.
	 */
	cred_encoding_t public;

	/**
	 * cached encodings, a table for each encoding_type_t, containing chunk_t*
	 */
	hashtable_t *cache[CRED_ENCODING_MAX];

	/**
	 * Registered encoding fuctions, cred_encoder_t
	 */
	linked_list_t *encoders;

	/**
	 * lock to access cache/encoders
	 */
	rwlock_t *lock;
};

/**
 * See header.
 */
bool cred_encoding_args(va_list args, ...)
{
	va_list parts, copy;
	bool failed = FALSE;

	va_start(parts, args);

	while (!failed)
	{
		cred_encoding_part_t current, target;
		chunk_t *out, data;

		/* get the part we are looking for */
		target = va_arg(parts, cred_encoding_part_t);
		if (target == CRED_PART_END)
		{
			break;
		}
		out = va_arg(parts, chunk_t*);

		va_copy(copy, args);
		while (!failed)
		{
			current = va_arg(copy, cred_encoding_part_t);
			if (current == CRED_PART_END)
			{
				failed = TRUE;
				break;
			}
			data = va_arg(copy, chunk_t);
			if (current == target)
			{
				*out = data;
				break;
			}
		}
		va_end(copy);
	}
	va_end(parts);
	return !failed;
}

/**
 * hashtable hash() function
 */
static u_int hash(void *key)
{
	return (uintptr_t)key;
}

/**
 * hashtable equals() function
 */
static bool equals(void *key1, void *key2)
{
	return key1 == key2;
}

/**
 * Implementation of cred_encoding_t.get_cache
 */
static bool get_cache(private_cred_encoding_t *this, cred_encoding_type_t type,
					  void *cache, chunk_t *encoding)
{
	chunk_t *chunk;

	if (type >= CRED_ENCODING_MAX || type < 0)
	{
		return FALSE;
	}
	this->lock->read_lock(this->lock);
	chunk = this->cache[type]->get(this->cache[type], cache);
	if (chunk)
	{
		*encoding = *chunk;
	}
	this->lock->unlock(this->lock);
	return !!chunk;
}

/**
 * Implementation of cred_encoding_t.encode
 */
static bool encode(private_cred_encoding_t *this, cred_encoding_type_t type,
				   void *cache, chunk_t *encoding, ...)
{
	enumerator_t *enumerator;
	va_list args, copy;
	cred_encoder_t encode;
	bool success = FALSE;
	chunk_t *chunk;

	if (type >= CRED_ENCODING_MAX || type < 0)
	{
		return FALSE;
	}
	this->lock->read_lock(this->lock);
	if (cache)
	{
		chunk = this->cache[type]->get(this->cache[type], cache);
		if (chunk)
		{
			*encoding = *chunk;
			this->lock->unlock(this->lock);
			return TRUE;
		}
	}
	va_start(args, encoding);
	enumerator = this->encoders->create_enumerator(this->encoders);
	while (enumerator->enumerate(enumerator, &encode))
	{
		va_copy(copy, args);
		success = encode(type, encoding, copy);
		va_end(copy);
		if (success)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);
	this->lock->unlock(this->lock);
	va_end(args);

	if (success && cache)
	{
		chunk = malloc_thing(chunk_t);
		*chunk = *encoding;
		this->lock->write_lock(this->lock);
		chunk = this->cache[type]->put(this->cache[type], cache, chunk);
		this->lock->unlock(this->lock);
		if (chunk)
		{
			free(chunk->ptr);
			free(chunk);
		}
	}
	return success;
}

/**
 * Implementation of cred_encoding_t.cache
 */
static void cache(private_cred_encoding_t *this, cred_encoding_type_t type,
				  void *cache, chunk_t encoding)
{
	chunk_t *chunk;

	if (type >= CRED_ENCODING_MAX || type < 0)
	{
		return free(encoding.ptr);
	}
	chunk = malloc_thing(chunk_t);
	*chunk = encoding;
	this->lock->write_lock(this->lock);
	chunk = this->cache[type]->put(this->cache[type], cache, chunk);
	this->lock->unlock(this->lock);
	/* free an encoding already associated to the cache */
	if (chunk)
	{
		free(chunk->ptr);
		free(chunk);
	}
}

/**
 * Implementation of cred_encoding_t.clear_cache
 */
static void clear_cache(private_cred_encoding_t *this, void *cache)
{
	cred_encoding_type_t type;
	chunk_t *chunk;

	this->lock->write_lock(this->lock);
	for (type = 0; type < CRED_ENCODING_MAX; type++)
	{
		chunk = this->cache[type]->remove(this->cache[type], cache);
		if (chunk)
		{
			chunk_free(chunk);
			free(chunk);
		}
	}
	this->lock->unlock(this->lock);
}

/**
 * Implementation of cred_encoding_t.add_encoder
 */
static void add_encoder(private_cred_encoding_t *this, cred_encoder_t encoder)
{
	this->lock->write_lock(this->lock);
	this->encoders->insert_last(this->encoders, encoder);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of cred_encoding_t.remove_encoder
 */
static void remove_encoder(private_cred_encoding_t *this, cred_encoder_t encoder)
{
	this->lock->write_lock(this->lock);
	this->encoders->remove(this->encoders, encoder, NULL);
	this->lock->unlock(this->lock);
}

/**
 * Implementation of cred_encoder_t.destroy.
 */
static void destroy(private_cred_encoding_t *this)
{
	cred_encoding_type_t type;

	for (type = 0; type < CRED_ENCODING_MAX; type++)
	{
		/* We explicitly do not free remaining encodings. All creds should
		 * have gone now, and they are responsible for cleaning out their
		 * cache entries. Not flushing here allows the leak detective to
		 * complain if a credential did not flush cached encodings. */
		this->cache[type]->destroy(this->cache[type]);
	}
	this->encoders->destroy(this->encoders);
	this->lock->destroy(this->lock);
	free(this);
}

/**
 * See header
 */
cred_encoding_t *cred_encoding_create()
{
	private_cred_encoding_t *this = malloc_thing(private_cred_encoding_t);
	cred_encoding_type_t type;

	this->public.encode = (bool(*)(cred_encoding_t*, cred_encoding_type_t type, void *cache, chunk_t *encoding, ...))encode;
	this->public.get_cache = (bool(*)(cred_encoding_t*, cred_encoding_type_t type, void *cache, chunk_t *encoding))get_cache;
	this->public.cache = (void(*)(cred_encoding_t*, cred_encoding_type_t type, void *cache, chunk_t encoding))cache;
	this->public.clear_cache = (void(*)(cred_encoding_t*, void *cache))clear_cache;
	this->public.add_encoder = (void(*)(cred_encoding_t*, cred_encoder_t encoder))add_encoder;
	this->public.remove_encoder = (void(*)(cred_encoding_t*, cred_encoder_t encoder))remove_encoder;
	this->public.destroy = (void(*)(cred_encoding_t*))destroy;

	for (type = 0; type < CRED_ENCODING_MAX; type++)
	{
		this->cache[type] = hashtable_create(hash, equals, 8);
	}
	this->encoders = linked_list_create();
	this->lock = rwlock_create(RWLOCK_TYPE_DEFAULT);

	return &this->public;
}

