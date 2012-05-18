/*
 * Copyrigth (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include "tkm_nonceg.h"

typedef struct private_tkm_nonceg_t private_tkm_nonceg_t;

/**
 * Private data of a tkm_nonceg_t object.
 */
struct private_tkm_nonceg_t {

	/**
	 * Public tkm_nonceg_t interface.
	 */
	tkm_nonceg_t public;

};

METHOD(nonce_gen_t, get_nonce, bool,
	private_tkm_nonceg_t *this, size_t size, u_int8_t *buffer)
{
	// TODO: Request nonce from TKM and fill it into buffer.
	return TRUE;
}

METHOD(nonce_gen_t, allocate_nonce, bool,
	private_tkm_nonceg_t *this, size_t size, chunk_t *chunk)
{
	*chunk = chunk_alloc(size);
	return get_nonce(this, chunk->len, chunk->ptr);
}

METHOD(nonce_gen_t, destroy, void,
	private_tkm_nonceg_t *this)
{
	free(this);
}

/*
 * Described in header.
 */
tkm_nonceg_t *tkm_nonceg_create()
{
	private_tkm_nonceg_t *this;

	INIT(this,
		.public = {
			.nonce_gen = {
				.get_nonce = _get_nonce,
				.allocate_nonce = _allocate_nonce,
				.destroy = _destroy,
			},
		},
	);

	return &this->public;
}
