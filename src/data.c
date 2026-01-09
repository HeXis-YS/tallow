/*
 * data.h - IP block sshd login abuse
 *
 * (C) Copyright 2019 Intel Corporation
 * Authors:
 *     Auke Kok <sofar@foo-projects.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 3
 * of the License.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <malloc.h>

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "data.h"

struct block_struct *blocks;
struct pattern_struct *patterns;
struct filter_struct *filters;
struct whitelist_struct *whitelist;

void filter_add(const char *filter)
{
	struct filter_struct *h = filters;

	/* filter duplicates */
	while (h) {
		if (strcmp(h->filter, filter) == 0)
			return;

		h = h->next;
	}

	struct filter_struct *f = calloc(1, sizeof(struct filter_struct));
	if (!f) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	f->filter = strdup(filter);

	dbg("Adding filter: %s\n", f->filter);

	h = filters;
	if (!h) {
		filters = f;
	} else {
		while (h->next)
			h = h->next;
		h->next = f;
	}
}

void pattern_add(const char *pattern, int ban, double score)
{
	struct pattern_struct *p = calloc(1, sizeof(struct pattern_struct));
	if (!p) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	p->pattern = strdup(pattern);
	p->instant_block = ban;
	p->weight = score;

	PCRE2_UCHAR pcre_err[256];
	int err = 0;
	PCRE2_SIZE erroff = 0;

	p->re = pcre2_compile(
		(PCRE2_SPTR)pattern,
		PCRE2_ZERO_TERMINATED,
		0, // options
		&err,
		&erroff,
		NULL // compile context
	);

	if (!p->re) {
		pcre2_get_error_message(err, pcre_err, sizeof(pcre_err));
		fprintf(stderr, "PCRE2 compilation failed. Offset %zu: %s\n",
			(size_t)erroff, (char *)pcre_err);
		exit(EXIT_FAILURE);
	}

	p->md = pcre2_match_data_create_from_pattern(p->re, NULL);
	if (!p->md) {
		perror("pcre2_match_data_create_from_pattern()");
		exit(EXIT_FAILURE);
	}

	dbg("Adding pattern: %s %d %lf\n", pattern, ban, score);

	struct pattern_struct *h = patterns;
	if (!h) {
		patterns = p;
	} else {
		while (h->next)
			h = h->next;
		h->next = p;
	}
}

void whitelist_add(const char *ip)
{
	struct whitelist_struct *w = calloc(1, sizeof(struct whitelist_struct));

	if (!w) {
		perror("calloc()");
		exit(EXIT_FAILURE);
	}

	w->ip = strdup(ip);

	size_t l = strlen(ip);
	if ((ip[l-1] == '.') || (ip[l-1] == ':'))
		w->len = l;
	else
		w->len = -1;

	struct whitelist_struct *h = whitelist;
	if (!h) {
		whitelist = w;
	} else {
		while (h->next)
			h = h->next;
		h->next = w;
	}
}

bool whitelist_find(const char *ip)
{
	struct whitelist_struct *w = whitelist;
	while (w) {
		if (w->len > 0) {
			if (!strncmp(w->ip, ip, w->len))
				return (true);
		} else {
			if (!strcmp(w->ip, ip))
				return (true);
		}
		w = w->next;
	}

	return (false);
}

void prune(int expires)
{
	struct block_struct *s = blocks;
	struct block_struct *p;
	struct timeval tv;

	(void) gettimeofday(&tv, NULL);
	p = NULL;

	while (s) {
		/*
		 * Expire all records, but if they are blocked, make sure to
		 * expire them *before* the ipset rule expires, otherwise
		 * you might get an IP to bypass checks.
		 */
		time_t age = tv.tv_sec - s->time.tv_sec;
		if ((age > expires) ||
		    ((s->blocked) && (age > expires / 2))) {
			dbg("Expired record for %s\n", s->ip);
			if (p) {
				p->next = s->next;
				free(s->ip);
				free(s);
				s = p->next;
				continue;
			} else {
				blocks = s->next;
				free(s->ip);
				free(s);
				s = blocks;
				p = NULL;
				continue;
			}
		}
		p = s;
		s = s->next;
	}

	/* return some memory */
	malloc_trim(0);
}
