/*
 * Part of DNS zone file validator `validns`.
 *
 * Copyright 2011-2014 Anton Berezin <tobez@tobez.org>
 *                2017 Casper Gielen <cgielen+validns@uvt.nl>
 * Modified BSD license.
 * (See LICENSE file in the distribution.)
 *
 */
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"
#include "textparse.h"
#include "mempool.h"
#include "carp.h"
#include "rr.h"

static struct rr *caa_parse(char *name, long ttl, int type, char *s)
{
	struct rr_caa *rr = getmem(sizeof(*rr));

	rr->flags = extract_integer(&s, "CAA flag", NULL);
	if (rr->flags != 0 && rr->flags != 128)
		return bitch("unknown flag value %d", rr->flags);
	rr->property = extract_label(&s, "CAA property", 0);
	rr->value = extract_text(&s, "CAA property");
	if ((strcmp(rr->property, "issue")     != 0) \
	&&  (strcmp(rr->property, "issuewild") != 0) \
	&&  (strcmp(rr->property, "iodef")     != 0)) {
		return bitch("unkown CAA property %s", rr->property);
	}
	if (*s) {
		return bitch("garbage after valid caa data");
	}

	return store_record(type, name, ttl, rr);
}

static char* caa_human(struct rr *rrv)
{
	RRCAST(caa);
    char s[1024];

    snprintf(s, 1024, "%d %s \"%s\"",
	     rr->flags, rr->property, rr->value.data);
    return quickstrdup_temp(s);
}

static struct binary_data caa_wirerdata(struct rr *rrv)
{
	RRCAST(caa);

    return compose_binary_data("1db", 1,
		rr->flags, rr->property, rr->value);
}

/*
 *  *rrv ? ik snap niet waar die variabele goed voor is.
static void *caa_validate(struct rr *rrv)
	todo: parse 
	if ((strcmp(rr->property, "issue") == 0) \
	||  (strcmp(rr->property, "issuewild") == 0) ) {

	} else if(strcmp(rr->property, "iodef") == 0) {
		if ((strcmp(rr->value, "mailto:") != 0) \
		||  (strcmp(rr->value, "http://")   != 0) \
		||  (strcmp(rr->value, "https://")  != 0) )
			return bitch("only mailto: and http(s): links are supported");
	} else {
}
*/

struct rr_methods caa_methods = { caa_parse, caa_human, caa_wirerdata, NULL, NULL  };
