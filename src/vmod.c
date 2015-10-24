/*-
 * Copyright (c) 2015 UPLEX Nils Goroll Systemoptimierung
 * All rights reserved
 *
 * Author: Geoffrey Simmons <geoffrey.simmons@uplex.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdarg.h>

#include "vcl.h"
#include "vrt.h"
#include "vas.h"
#include "vsa.h"
#include "cache/cache.h"
#include "cache/cache_director.h"
#include "cache/cache_backend.h"
#include "vapi/vsl.h"

#include "vcc_if.h"

static void
errmsg(VRT_CTX, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (ctx->method == VCL_MET_INIT) {
		AN(ctx->msg);
		VSB_vprintf(ctx->msg, fmt, args);
		VRT_handling(ctx, VCL_RET_FAIL);
	}
	else {
		AN(ctx->vsl);
		VSLbv(ctx->vsl, SLT_VCL_Error, fmt, args);
	}
	va_end(args);
}

static int
check(VRT_CTX, VCL_BACKEND be, VCL_PROBE probe, VCL_STRING port)
{
	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(be, DIRECTOR_MAGIC);
	CHECK_OBJ_NOTNULL(probe, VRT_BACKEND_PROBE_MAGIC);
	AN(port);

	if (be->resolve != NULL) {
		errmsg(ctx, "vmod oob_probe error: "
		       "%s is a cluster director, not a backend", be->vcl_name);
		return 0;
	}
	return 1;
}

static struct suckaddr *
get_suckaddr(VCL_STRING host, VCL_STRING port, int family)
{
	struct addrinfo hints, *res = NULL;
	struct suckaddr *sa = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = family;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return NULL;
	if (res->ai_next != NULL)
		return NULL;
	sa = VSA_Malloc(res->ai_addr, res->ai_addrlen);
	AN(sa);
	assert(VSA_Get_Proto(sa) == family);
	freeaddrinfo(res);
	return sa;
}

static void
insert_probe(struct backend *bp, VCL_PROBE probe, struct suckaddr *sa4,
	     struct suckaddr *sa6)
{
	struct tcp_pool *tpool;

	if (bp->probe != NULL)
		VBP_Remove(bp);
	tpool = VBT_Ref(sa4, sa6);
	AN(tpool);
	VBP_Insert(bp, probe, tpool);
	AN(bp->probe);
}

VCL_VOID
vmod_port(VRT_CTX, VCL_BACKEND be, VCL_PROBE probe, VCL_STRING port)
{
	struct backend *bp;
	struct suckaddr *sa4 = NULL, *sa6 = NULL;

	if (!check(ctx, be, probe, port))
		return;

	CAST_OBJ_NOTNULL(bp, be->priv, BACKEND_MAGIC);
	assert(bp->ipv4_addr != NULL || bp->ipv6_addr != NULL);

	if (bp->ipv4_addr != NULL)
		sa4 = get_suckaddr(bp->ipv4_addr, port, AF_INET);
	if (bp->ipv6_addr != NULL)
		sa6 = get_suckaddr(bp->ipv6_addr, port, AF_INET6);
	if (sa4 == NULL && sa6 == NULL) {
		errmsg(ctx, "vmod oob_probe error: "
		       "Bad port specification: %s", port);
		return;
	}
	insert_probe(bp, probe, sa4, sa6);
}

VCL_VOID
vmod_addr(VRT_CTX, VCL_BACKEND be, VCL_PROBE probe, VCL_STRING host,
		VCL_STRING port)
{
	struct backend *bp;
	struct suckaddr *sa4 = NULL, *sa6 = NULL;

	if (!check(ctx, be, probe, port))
		return;
	AN(host);

	CAST_OBJ_NOTNULL(bp, be->priv, BACKEND_MAGIC);

	sa4 = get_suckaddr(host, port, AF_INET);
	sa6 = get_suckaddr(host, port, AF_INET6);
	if (sa4 == NULL && sa6 == NULL) {
		errmsg(ctx, "vmod oob_probe error: "
		       "Cannot resolve %s:%s as a unique IPv4 or IPv6 address",
		       host, port);
		return;
	}
	insert_probe(bp, probe, sa4, sa6);
}

VCL_STRING
vmod_version(VRT_CTX __attribute__((unused)))
{
	return VERSION;
}
