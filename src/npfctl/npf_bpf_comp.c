/*-
 * Copyright (c) 2010-2020 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * BPF byte-code generation for NPF rules.
 *
 * Overview
 *
 *	Each NPF rule is compiled into a BPF micro-program.  There is a
 *	BPF byte-code fragment for each higher-level filtering logic,
 *	e.g. to match L4 protocol, IP/mask, etc.  The generation process
 *	combines multiple BPF-byte code fragments into one program.
 *
 * Basic case
 *
 *	Consider a basic case where all filters should match.  They
 *	are expressed as logical conjunction, e.g.:
 *
 *		A and B and C and D
 *
 *	Each test (filter) criterion can be evaluated to true (match) or
 *	false (no match) and the logic is as follows:
 *
 *	- If the value is true, then jump to the JUMP_OK value.
 *
 *	- If the value is false, then jump to the JUMP_FAIL value.
 *
 *	JUMP_OK and JUMP_FAIL are "magic" values which mark a jump as
 *	unresolved.  Every unresolved JUMP_OK is tracked on the "OK list"
 *	and every unresolved JUMP_FAIL on the "fail list"; as soon as it
 *	is known what a criterion's success or failure should actually
 *	lead to, the relevant list is "sealed": every jump on it is
 *	patched to the given target and the list is emptied again.
 *
 *	Since each criterion in the conjunction is simply followed by the
 *	next, the OK list is sealed to the start of the next criterion as
 *	soon as it begins.  The fail list is left pending, since a
 *	failure of any criterion should skip the rest of the conjunction;
 *	it accumulates across criteria and is only sealed once the final
 *	target is known, i.e. by npfctl_bpf_complete() (to the "return
 *	failure" instruction) or earlier by an enclosing group (see
 *	below).  npfctl_bpf_complete() likewise seals the OK list to a
 *	"return success" instruction that it appends right before it.
 *
 *	Therefore, if all filter criteria will match, then the first
 *	instruction will be reached, indicating a successful match of the
 *	rule.  Otherwise, if any of the criteria will not match, it will
 *	take the failure path and the rule will not be matching.
 *
 * Grouping
 *
 *	Filters can have groups, which have an effect of logical
 *	disjunction, e.g.:
 *
 *		A and B and (C or D)
 *
 *	Within a group, the roles are reversed: the fail list is sealed
 *	to the start of the next alternative as soon as it begins (a
 *	failed alternative simply tries the next one), while the OK list
 *	accumulates across every alternative (a match on any one of them
 *	means the whole group matches) and is left pending for whatever
 *	follows the group.  Since the OK list must not be conflated with
 *	whatever fail list was already pending for the rule from before
 *	the group started, npfctl_bpf_group_enter() sets it aside and
 *	npfctl_bpf_group_exit() restores it once the group's own fail
 *	list -- what's left after every alternative but the last has been
 *	tried -- has been sealed to a "return failure" instruction
 *	appended right there.  A negated group ("not (C or D)") simply
 *	swaps the two lists before doing so: any alternative matching
 *	should then fail the group, and only exhausting every alternative
 *	without a match should let it succeed.
 */

#include <sys/cdefs.h>
__RCSID("$NetBSD$");

#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <err.h>
#include <assert.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#define	__FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <net/bpf.h>

#include "npfctl.h"

/*
 * Note: clear X_EQ_L4OFF when register X is invalidated i.e. it stores
 * something other than L4 header offset.  Generally, when BPF_LDX is used.
 */
#define	FETCHED_L3		0x01
#define	CHECKED_L4_PROTO	0x02
#define	X_EQ_L4OFF		0x04

/*
 * A pending, unresolved jump: the index of the BPF instruction and
 * which of its fields (jt, jf or, for BPF_JA, k) holds the marker.
 */
typedef struct {
	unsigned		insn;
	uint8_t			which;
} bpf_patch_t;
#define	PATCH_JT		0
#define	PATCH_JF		1
#define	PATCH_K			2

/* A growable list of pending jumps (the "OK list" / "fail list"). */
typedef struct {
	bpf_patch_t *		items;
	size_t			len;
	size_t			alen;
} patch_list_t;

struct npf_bpf {
	/*
	 * BPF program code, the allocated length (in bytes), the number
	 * of logical blocks and the flags.
	 */
	struct bpf_program	prog;
	size_t			alen;
	unsigned		nblocks;
	sa_family_t		af;
	uint32_t		flags;

	/*
	 * Indicators whether we are inside the group and whether this
	 * group is implementing inverted logic, and the block number at
	 * the start of the group.
	 */
	unsigned		ingroup;
	bool			invert;
	unsigned		gblock;

	/* Track inversion (excl. mark). */
	uint32_t		invflags;

	/*
	 * Pending JUMP_OK / JUMP_FAIL sites; see the "Grouping" comment
	 * above.  saved_faillist is where npfctl_bpf_group_enter() sets
	 * aside the rule's own (pre-group) fail list while a group's
	 * alternatives build up one of their own.
	 */
	patch_list_t		oklist;
	patch_list_t		faillist;
	patch_list_t		saved_faillist;

	/* BPF marks, allocated length and the real length. */
	uint32_t *		marks;
	size_t			malen;
	size_t			mlen;
};

/*
 * NPF success and failure values to be returned from BPF.
 */
#define	NPF_BPF_SUCCESS		((u_int)-1)
#define	NPF_BPF_FAILURE		0

/*
 * Magic values marking an unresolved jump; see the "OK list" / "fail
 * list" description above.  Note: these double as the longest jump
 * offset in BPF, since the offset is one byte -- see patch_to().
 *
 * CAUTION: within a single multi-instruction criterion (e.g. matching
 * several words of an IPv6 address), only the branch that determines
 * the criterion's *overall* success or failure may use these markers.
 * A branch that merely continues on to more instructions of the very
 * same criterion (e.g. "this word matched, check the next one") must
 * instead be a plain, literal jump to that next instruction: were it
 * marked JUMP_OK, it would eventually be resolved exactly like the
 * criterion's real, final success and could jump out past the
 * remaining instructions on a partial match (see npfctl_bpf_cidr()
 * and the port range case in npfctl_bpf_ports() for examples).
 */
#define	JUMP_OK			0xfe
#define	JUMP_FAIL		0xff

/* Reduce re-allocations by expanding in 64 byte blocks. */
#define	ALLOC_MASK		(64 - 1)
#define	ALLOC_ROUND(x)		(((x) + ALLOC_MASK) & ~ALLOC_MASK)

#ifndef IPV6_VERSION
#define	IPV6_VERSION		0x60
#endif

npf_bpf_t *
npfctl_bpf_create(void)
{
	return ecalloc(1, sizeof(npf_bpf_t));
}

static void
list_add(patch_list_t *list, unsigned insn, uint8_t which)
{
	if (list->len == list->alen) {
		list->alen = list->alen ? list->alen * 2 : 8;
		list->items = erealloc(list->items,
		    list->alen * sizeof(bpf_patch_t));
	}
	list->items[list->len].insn = insn;
	list->items[list->len].which = which;
	list->len++;
}

/* Concatenate 'src' onto the end of 'dst' and empty 'src' out. */
static void
merge_list(patch_list_t *dst, patch_list_t *src)
{
	for (size_t i = 0; i < src->len; i++) {
		list_add(dst, src->items[i].insn, src->items[i].which);
	}
	free(src->items);
	memset(src, 0, sizeof(*src));
}

/*
 * patch_to: resolve every pending jump on 'list' to the given target
 * (a BPF instruction index) and empty the list back out.
 */
static void
patch_to(npf_bpf_t *ctx, patch_list_t *list, unsigned target)
{
	struct bpf_program *bp = &ctx->prog;

	for (size_t i = 0; i < list->len; i++) {
		const unsigned insn = list->items[i].insn;
		const unsigned off = target - insn - 1;

		if (off >= JUMP_OK) {
			errx(EXIT_FAILURE, "BPF generation error: "
			    "the number of instructions is over the limit");
		}
		struct bpf_insn *ip = &bp->bf_insns[insn];
		switch (list->items[i].which) {
		case PATCH_JT:
			ip->jt = off;
			break;
		case PATCH_JF:
			ip->jf = off;
			break;
		case PATCH_K:
			ip->k = off;
			break;
		}
	}
	list->len = 0;
}

/* Seal the OK list to the current end of the program (a match here). */
static void
seal_ok(npf_bpf_t *ctx)
{
	patch_to(ctx, &ctx->oklist, ctx->prog.bf_len);
}

/* Seal the fail list to the current end of the program (a miss here). */
static void
seal_fail(npf_bpf_t *ctx)
{
	patch_to(ctx, &ctx->faillist, ctx->prog.bf_len);
}

/*
 * seal_prev: called at the start of every criterion.  Outside of a
 * group (or for the first alternative of one), the new criterion is
 * ANDed with whatever came before, so the OK list is sealed to here.
 * For a later alternative within a group, it is ORed with the
 * previous ones instead, so the fail list is sealed to here.
 */
static void
seal_prev(npf_bpf_t *ctx)
{
	if (ctx->ingroup && ctx->nblocks > ctx->gblock) {
		seal_fail(ctx);
	} else {
		seal_ok(ctx);
	}
}

static void
add_insns(npf_bpf_t *ctx, struct bpf_insn *insns, size_t count)
{
	struct bpf_program *bp = &ctx->prog;
	size_t offset, len, reqlen;
	const unsigned base = bp->bf_len;

	/* Note: bf_len is the count of instructions. */
	offset = bp->bf_len * sizeof(struct bpf_insn);
	len = count * sizeof(struct bpf_insn);

	/* Ensure the memory buffer for the program. */
	reqlen = ALLOC_ROUND(offset + len);
	if (reqlen > ctx->alen) {
		bp->bf_insns = erealloc(bp->bf_insns, reqlen);
		ctx->alen = reqlen;
	}

	/* Add the code block. */
	memcpy((uint8_t *)bp->bf_insns + offset, insns, len);
	bp->bf_len += count;

	/* Track any JUMP_OK / JUMP_FAIL markers on the OK / fail list. */
	for (unsigned i = 0; i < count; i++) {
		const unsigned idx = base + i;
		struct bpf_insn *insn = &bp->bf_insns[idx];

		if (BPF_CLASS(insn->code) != BPF_JMP) {
			continue;
		}
		if (BPF_OP(insn->code) == BPF_JA) {
			/* BPF_JA is only ever used to indicate failure. */
			if (insn->k == JUMP_OK) {
				list_add(&ctx->oklist, idx, PATCH_K);
			} else if (insn->k == JUMP_FAIL) {
				list_add(&ctx->faillist, idx, PATCH_K);
			}
			continue;
		}
		if (insn->jt == JUMP_OK) {
			list_add(&ctx->oklist, idx, PATCH_JT);
		} else if (insn->jt == JUMP_FAIL) {
			list_add(&ctx->faillist, idx, PATCH_JT);
		}
		if (insn->jf == JUMP_OK) {
			list_add(&ctx->oklist, idx, PATCH_JF);
		} else if (insn->jf == JUMP_FAIL) {
			list_add(&ctx->faillist, idx, PATCH_JF);
		}
	}
}

static void
add_bmarks(npf_bpf_t *ctx, const uint32_t *m, size_t len)
{
	size_t reqlen, nargs = m[1];

	if ((len / sizeof(uint32_t) - 2) != nargs) {
		errx(EXIT_FAILURE, "invalid BPF block description");
	}
	reqlen = ALLOC_ROUND(ctx->mlen + len);
	if (reqlen > ctx->malen) {
		ctx->marks = erealloc(ctx->marks, reqlen);
		ctx->malen = reqlen;
	}
	memcpy((uint8_t *)ctx->marks + ctx->mlen, m, len);
	ctx->mlen += len;
}

static void
done_block(npf_bpf_t *ctx, const uint32_t *m, size_t len)
{
	add_bmarks(ctx, m, len);
	ctx->nblocks++;
}

struct bpf_program *
npfctl_bpf_complete(npf_bpf_t *ctx)
{
	struct bpf_program *bp = &ctx->prog;

	/* No instructions (optimised out). */
	if (!bp->bf_len)
		return NULL;

	/* A match: seal the OK list to a "return success" here. */
	seal_ok(ctx);
	struct bpf_insn insns_ok[] = {
		BPF_STMT(BPF_RET+BPF_K, NPF_BPF_SUCCESS),
	};
	add_insns(ctx, insns_ok, __arraycount(insns_ok));

	/* No match: seal the fail list to a "return failure" here. */
	seal_fail(ctx);
	struct bpf_insn insns_fail[] = {
		BPF_STMT(BPF_RET+BPF_K, NPF_BPF_FAILURE),
	};
	add_insns(ctx, insns_fail, __arraycount(insns_fail));

	assert(ctx->oklist.len == 0);
	assert(ctx->faillist.len == 0);

	return &ctx->prog;
}

const void *
npfctl_bpf_bmarks(npf_bpf_t *ctx, size_t *len)
{
	*len = ctx->mlen;
	return ctx->marks;
}

void
npfctl_bpf_destroy(npf_bpf_t *ctx)
{
	free(ctx->prog.bf_insns);
	free(ctx->marks);
	free(ctx->oklist.items);
	free(ctx->faillist.items);
	free(ctx->saved_faillist.items);
	free(ctx);
}

/*
 * npfctl_bpf_group_enter: begin a logical group.  It merely uses logical
 * disjunction (OR) for comparisons within the group.
 */
void
npfctl_bpf_group_enter(npf_bpf_t *ctx, bool invert)
{
	assert(ctx->gblock == 0);

	ctx->gblock = ctx->nblocks;
	ctx->invert = invert;
	ctx->ingroup++;

	/*
	 * The group's alternatives build up a fail list of their own
	 * (sealed between alternatives); set aside whatever was already
	 * pending for the rule's own failure path until we exit again.
	 */
	ctx->saved_faillist = ctx->faillist;
	memset(&ctx->faillist, 0, sizeof(ctx->faillist));
}

void
npfctl_bpf_group_exit(npf_bpf_t *ctx)
{
	assert(ctx->ingroup);
	ctx->ingroup--;

	/* If there are no blocks or only one - nothing to do. */
	if (!ctx->invert && (ctx->nblocks - ctx->gblock) <= 1) {
		merge_list(&ctx->faillist, &ctx->saved_faillist);
		ctx->gblock = 0;
		return;
	}

	if (ctx->invert) {
		/*
		 * Negated group: any alternative matching should fail
		 * the group, and only exhausting every alternative
		 * without a match should let it succeed.  Swap the
		 * accumulated lists to reflect that.
		 */
		patch_list_t tmp = ctx->oklist;
		ctx->oklist = ctx->faillist;
		ctx->faillist = tmp;
	}

	/*
	 * No alternative matched: seal the group's own fail list to a
	 * "return failure" appended here.  The OK list (any alternative
	 * matching) is left pending for whatever follows the group.
	 */
	seal_fail(ctx);
	struct bpf_insn insns_ret[] = {
		BPF_STMT(BPF_RET+BPF_K, NPF_BPF_FAILURE),
	};
	add_insns(ctx, insns_ret, __arraycount(insns_ret));

	/* Restore the rule's own fail list for whatever follows. */
	ctx->faillist = ctx->saved_faillist;
	memset(&ctx->saved_faillist, 0, sizeof(ctx->saved_faillist));
	ctx->gblock = 0;
}

static void
fetch_l3(npf_bpf_t *ctx, sa_family_t af, unsigned flags)
{
	unsigned ver;

	switch (af) {
	case AF_INET:
		ver = IPVERSION;
		break;
	case AF_INET6:
		ver = IPV6_VERSION >> 4;
		break;
	case AF_UNSPEC:
		ver = 0;
		break;
	default:
		abort();
	}

	/*
	 * The memory store is populated with:
	 * - BPF_MW_IPVER: IP version (4 or 6).
	 * - BPF_MW_L4OFF: L4 header offset.
	 * - BPF_MW_L4PROTO: L4 protocol.
	 */
	if ((ctx->flags & FETCHED_L3) == 0 || (af && ctx->af == 0)) {
		const uint8_t jt = ver ? JUMP_OK : JUMP_FAIL;
		const uint8_t jf = ver ? JUMP_FAIL : JUMP_OK;
		const bool ingroup = ctx->ingroup != 0;
		const bool invert = ctx->invert;

		/*
		 * L3 block cannot be inserted in the middle of a group.
		 * In fact, it never is.  Check and start the group after.
		 */
		if (ingroup) {
			assert(ctx->nblocks == ctx->gblock);
			npfctl_bpf_group_exit(ctx);
		}

		/*
		 * A <- IP version; A == expected-version?
		 * If no particular version specified, check for non-zero.
		 */
		struct bpf_insn insns_af[] = {
			BPF_STMT(BPF_LD+BPF_W+BPF_MEM, BPF_MW_IPVER),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ver, jt, jf),
		};
		add_insns(ctx, insns_af, __arraycount(insns_af));
		ctx->flags |= FETCHED_L3;
		ctx->af = af;

		/*
		 * A match here just continues into whatever this call's
		 * caller (or, if it adds nothing more of its own, whatever
		 * criterion follows next) emits right after we return.
		 */
		seal_ok(ctx);

		if (af) {
			uint32_t mwords[] = { BM_IPVER, 1, af };
			add_bmarks(ctx, mwords, sizeof(mwords));
		}
		if (ingroup) {
			npfctl_bpf_group_enter(ctx, invert);
		}

	} else if (af && af != ctx->af) {
		errx(EXIT_FAILURE, "address family mismatch");
	}

	if ((flags & X_EQ_L4OFF) != 0 && (ctx->flags & X_EQ_L4OFF) == 0) {
		/* X <- IP header length */
		struct bpf_insn insns_hlen[] = {
			BPF_STMT(BPF_LDX+BPF_MEM, BPF_MW_L4OFF),
		};
		add_insns(ctx, insns_hlen, __arraycount(insns_hlen));
		ctx->flags |= X_EQ_L4OFF;
	}
}

static void
bm_invert_checkpoint(npf_bpf_t *ctx, const unsigned opts)
{
	uint32_t bm = 0;

	if (ctx->ingroup && ctx->invert) {
		const unsigned seen = ctx->invflags;

		if ((opts & MATCH_SRC) != 0 && (seen & MATCH_SRC) == 0) {
			bm = BM_SRC_NEG;
		}
		if ((opts & MATCH_DST) != 0 && (seen & MATCH_DST) == 0) {
			bm = BM_DST_NEG;
		}
		ctx->invflags |= opts & (MATCH_SRC | MATCH_DST);
	}
	if (bm) {
		uint32_t mwords[] = { bm, 0 };
		add_bmarks(ctx, mwords, sizeof(mwords));
	}
}

/*
 * npfctl_bpf_ipver: match the IP version.
 */
void
npfctl_bpf_ipver(npf_bpf_t *ctx, sa_family_t af)
{
	seal_prev(ctx);
	fetch_l3(ctx, af, 0);
}

/*
 * npfctl_bpf_proto: code block to match IP version and L4 protocol.
 */
void
npfctl_bpf_proto(npf_bpf_t *ctx, unsigned proto)
{
	seal_prev(ctx);

	struct bpf_insn insns_proto[] = {
		/* A <- L4 protocol; A == expected-protocol? */
		BPF_STMT(BPF_LD+BPF_W+BPF_MEM, BPF_MW_L4PROTO),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, proto, JUMP_OK, JUMP_FAIL),
	};
	add_insns(ctx, insns_proto, __arraycount(insns_proto));

	uint32_t mwords[] = { BM_PROTO, 1, proto };
	done_block(ctx, mwords, sizeof(mwords));
	ctx->flags |= CHECKED_L4_PROTO;
}

/*
 * npfctl_bpf_cidr: code block to match IPv4 or IPv6 CIDR.
 *
 * => IP address shall be in the network byte order.
 */
void
npfctl_bpf_cidr(npf_bpf_t *ctx, unsigned opts, sa_family_t af,
    const npf_addr_t *addr, const npf_netmask_t mask)
{
	const uint32_t *awords = (const uint32_t *)addr;
	unsigned nwords, length, maxmask, off;

	assert(((opts & MATCH_SRC) != 0) ^ ((opts & MATCH_DST) != 0));
	assert((mask && mask <= NPF_MAX_NETMASK) || mask == NPF_NO_NETMASK);

	switch (af) {
	case AF_INET:
		maxmask = 32;
		off = (opts & MATCH_SRC) ?
		    offsetof(struct ip, ip_src) :
		    offsetof(struct ip, ip_dst);
		nwords = sizeof(struct in_addr) / sizeof(uint32_t);
		break;
	case AF_INET6:
		maxmask = 128;
		off = (opts & MATCH_SRC) ?
		    offsetof(struct ip6_hdr, ip6_src) :
		    offsetof(struct ip6_hdr, ip6_dst);
		nwords = sizeof(struct in6_addr) / sizeof(uint32_t);
		break;
	default:
		abort();
	}

	seal_prev(ctx);

	/* Ensure address family. */
	fetch_l3(ctx, af, 0);

	length = (mask == NPF_NO_NETMASK) ? maxmask : mask;

	/* CAUTION: BPF operates in host byte-order. */
	for (unsigned i = 0; i < nwords; i++) {
		const unsigned woff = i * sizeof(uint32_t);
		uint32_t word = ntohl(awords[i]);
		uint32_t wordmask;

		if (length >= 32) {
			/* The mask is a full word - do not apply it. */
			wordmask = 0;
			length -= 32;
		} else if (length) {
			wordmask = 0xffffffff << (32 - length);
			length = 0;
		} else {
			/* The mask became zero - skip the rest. */
			break;
		}

		/* A <- IP address (or one word of it) */
		struct bpf_insn insns_ip[] = {
			BPF_STMT(BPF_LD+BPF_W+BPF_ABS, off + woff),
		};
		add_insns(ctx, insns_ip, __arraycount(insns_ip));

		/* A <- (A & MASK) */
		if (wordmask) {
			struct bpf_insn insns_mask[] = {
				BPF_STMT(BPF_ALU+BPF_AND+BPF_K, wordmask),
			};
			add_insns(ctx, insns_mask, __arraycount(insns_mask));
		}

		/*
		 * A == expected-IP-word?  A match on any word but the
		 * last one just continues on to the next word (a plain
		 * literal jump, not JUMP_OK -- see the CAUTION comment
		 * near its definition); a mismatch on any word fails the
		 * whole match right away.
		 */
		const uint8_t jt = length ? 0 : JUMP_OK;
		struct bpf_insn insns_cmp[] = {
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, word, jt, JUMP_FAIL),
		};
		add_insns(ctx, insns_cmp, __arraycount(insns_cmp));
	}

	uint32_t mwords[] = {
		(opts & MATCH_SRC) ? BM_SRC_CIDR: BM_DST_CIDR, 6,
		af, mask, awords[0], awords[1], awords[2], awords[3],
	};
	bm_invert_checkpoint(ctx, opts);
	done_block(ctx, mwords, sizeof(mwords));
}

/*
 * npfctl_bpf_ports: code block to match TCP/UDP port range.
 *
 * => Port numbers shall be in the network byte order.
 */
void
npfctl_bpf_ports(npf_bpf_t *ctx, unsigned opts, in_port_t from, in_port_t to)
{
	const unsigned sport_off = offsetof(struct udphdr, uh_sport);
	const unsigned dport_off = offsetof(struct udphdr, uh_dport);
	unsigned off;

	/* TCP and UDP port offsets are the same. */
	assert(sport_off == offsetof(struct tcphdr, th_sport));
	assert(dport_off == offsetof(struct tcphdr, th_dport));
	assert(ctx->flags & CHECKED_L4_PROTO);

	assert(((opts & MATCH_SRC) != 0) ^ ((opts & MATCH_DST) != 0));
	off = (opts & MATCH_SRC) ? sport_off : dport_off;

	seal_prev(ctx);

	/* X <- IP header length */
	fetch_l3(ctx, AF_UNSPEC, X_EQ_L4OFF);

	struct bpf_insn insns_fetch[] = {
		/* A <- port */
		BPF_STMT(BPF_LD+BPF_H+BPF_IND, off),
	};
	add_insns(ctx, insns_fetch, __arraycount(insns_fetch));

	/* CAUTION: BPF operates in host byte-order. */
	from = ntohs(from);
	to = ntohs(to);

	if (from == to) {
		/* Single port case. */
		struct bpf_insn insns_port[] = {
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, from, JUMP_OK, JUMP_FAIL),
		};
		add_insns(ctx, insns_port, __arraycount(insns_port));
	} else {
		/*
		 * Port range case: A >= from just continues on to check
		 * A <= to (a plain literal jump, not JUMP_OK); either
		 * comparison failing fails the whole range check.  If the
		 * range is reversed (from > to, invalid), the two can
		 * never both hold and the check naturally always fails.
		 */
		struct bpf_insn insns_range[] = {
			BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, from, 0, JUMP_FAIL),
			BPF_JUMP(BPF_JMP+BPF_JGT+BPF_K, to, JUMP_FAIL, JUMP_OK),
		};
		add_insns(ctx, insns_range, __arraycount(insns_range));
	}

	uint32_t mwords[] = {
		(opts & MATCH_SRC) ? BM_SRC_PORTS : BM_DST_PORTS, 2, from, to
	};
	done_block(ctx, mwords, sizeof(mwords));
}

/*
 * npfctl_bpf_tcpfl: code block to match TCP flags.
 */
void
npfctl_bpf_tcpfl(npf_bpf_t *ctx, uint8_t tf, uint8_t tf_mask)
{
	const unsigned tcpfl_off = offsetof(struct tcphdr, th_flags);
	const bool usingmask = tf_mask != tf;

	seal_prev(ctx);

	/* X <- IP header length */
	fetch_l3(ctx, AF_UNSPEC, X_EQ_L4OFF);

	if ((ctx->flags & CHECKED_L4_PROTO) == 0) {
		/*
		 * A <- L4 protocol; A == TCP?  If not, this criterion is
		 * vacuously satisfied (JUMP_OK) and the flags below are
		 * not checked at all.
		 *
		 * Note: the TCP flag matching might be without 'proto tcp'
		 * when using a plain 'stateful' rule.  In such case it also
		 * handles other protocols, thus no strict TCP check.
		 */
		struct bpf_insn insns_tcp[] = {
			BPF_STMT(BPF_LD+BPF_W+BPF_MEM, BPF_MW_L4PROTO),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, JUMP_OK),
		};
		add_insns(ctx, insns_tcp, __arraycount(insns_tcp));
	}

	struct bpf_insn insns_tf[] = {
		/* A <- TCP flags */
		BPF_STMT(BPF_LD+BPF_B+BPF_IND, tcpfl_off),
	};
	add_insns(ctx, insns_tf, __arraycount(insns_tf));

	if (usingmask) {
		/* A <- (A & mask) */
		struct bpf_insn insns_mask[] = {
			BPF_STMT(BPF_ALU+BPF_AND+BPF_K, tf_mask),
		};
		add_insns(ctx, insns_mask, __arraycount(insns_mask));
	}

	struct bpf_insn insns_cmp[] = {
		/* A == expected-TCP-flags? */
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, tf, JUMP_OK, JUMP_FAIL),
	};
	add_insns(ctx, insns_cmp, __arraycount(insns_cmp));

	uint32_t mwords[] = { BM_TCPFL, 2, tf, tf_mask };
	done_block(ctx, mwords, sizeof(mwords));
}

/*
 * npfctl_bpf_icmp: code block to match ICMP type and/or code.
 * Note: suitable for both the ICMPv4 and ICMPv6.
 */
void
npfctl_bpf_icmp(npf_bpf_t *ctx, int type, int code)
{
	const u_int type_off = offsetof(struct icmp, icmp_type);
	const u_int code_off = offsetof(struct icmp, icmp_code);

	assert(ctx->flags & CHECKED_L4_PROTO);
	assert(offsetof(struct icmp6_hdr, icmp6_type) == type_off);
	assert(offsetof(struct icmp6_hdr, icmp6_code) == code_off);
	assert(type != -1 || code != -1);

	seal_prev(ctx);

	/* X <- IP header length */
	fetch_l3(ctx, AF_UNSPEC, X_EQ_L4OFF);

	if (type != -1) {
		struct bpf_insn insns_type[] = {
			BPF_STMT(BPF_LD+BPF_B+BPF_IND, type_off),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, type, JUMP_OK, JUMP_FAIL),
		};
		add_insns(ctx, insns_type, __arraycount(insns_type));

		uint32_t mwords[] = { BM_ICMP_TYPE, 1, type };
		done_block(ctx, mwords, sizeof(mwords));

		if (code != -1) {
			/* Type matched: continue on to check the code too. */
			seal_ok(ctx);
		}
	}

	if (code != -1) {
		struct bpf_insn insns_code[] = {
			BPF_STMT(BPF_LD+BPF_B+BPF_IND, code_off),
			BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, code, JUMP_OK, JUMP_FAIL),
		};
		add_insns(ctx, insns_code, __arraycount(insns_code));

		uint32_t mwords[] = { BM_ICMP_CODE, 1, code };
		done_block(ctx, mwords, sizeof(mwords));
	}
}

#define	SRC_FLAG_BIT	(1U << 31)

/*
 * npfctl_bpf_table: code block to match source/destination IP address
 * against NPF table specified by ID.
 */
void
npfctl_bpf_table(npf_bpf_t *ctx, unsigned opts, unsigned tid)
{
	const bool src = (opts & MATCH_SRC) != 0;

	seal_prev(ctx);

	struct bpf_insn insns_table[] = {
		BPF_STMT(BPF_LD+BPF_IMM, (src ? SRC_FLAG_BIT : 0) | tid),
		BPF_STMT(BPF_MISC+BPF_COP, NPF_COP_TABLE),
		BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0, JUMP_FAIL, JUMP_OK),
	};
	add_insns(ctx, insns_table, __arraycount(insns_table));

	uint32_t mwords[] = { src ? BM_SRC_TABLE: BM_DST_TABLE, 1, tid };
	bm_invert_checkpoint(ctx, opts);
	done_block(ctx, mwords, sizeof(mwords));
}
