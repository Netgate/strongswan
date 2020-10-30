/*
 * Copyright 2016-2018 Rubicon Communications, LLC.
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

#include <library.h>
#include <kernel/kernel_ipsec.h>

#include <stdio.h>

typedef struct kernel_vpp_ipsec_t {
	kernel_ipsec_t interface;
} kernel_vpp_ipsec_t;

kernel_vpp_ipsec_t *kernel_vpp_ipsec_create();

