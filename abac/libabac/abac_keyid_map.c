/* abac_keyid_map.c */


#include "abac.h"
#include "abac_util.h"
#include "uthash.h"

/*
 * A mapping entry that maps key to valus (both char *s).  These can be hashed
 * because of the UT_hash_handle - see uthash.h.
 */
struct abac_keyid_mapping_t {
    char *key;
    char *value;
    UT_hash_handle hh;
};

/* 
 * A map from keyids -> nicknames and nicknames to keys.  These are managed by
 * the libabac reference counting system, hence the refcount
 */
struct abac_keyid_map_t {
    abac_keyid_mapping_t *keys;		/* Key to nickname map */
    abac_keyid_mapping_t *nicknames;	/* Nickname to key map */
    int refcount;
};

/*
 * Create a new mapping entry from key(k) to value (v).  It must be freed using
 * abac_keyid_mapping_free.
 */
abac_keyid_mapping_t *abac_keyid_mapping_new(char *k, char *v) {
    abac_keyid_mapping_t *m = NULL;

    if ( !k || ! v) return NULL;
    m = abac_xmalloc(sizeof(abac_keyid_mapping_t));
    m->key = abac_xstrdup(k);
    m->value = abac_xstrdup(v);

    return m;
}

/*
 * Free the given mapping.  These are not reference counted, so free the key
 * and value, and then the mapping memory
 */
void abac_keyid_mapping_free(abac_keyid_mapping_t *m) {
    if ( m->key ) free(m->key);
    if ( m->value ) free(m->value);
    free(m);
}

/*
 * Create a new keyid map.  These are reference counted and must be freed using
 * abac_keyid_map_free.
 */
abac_keyid_map_t *abac_keyid_map_new() {
    abac_keyid_map_t *m = abac_xmalloc(sizeof(abac_keyid_map_t));

    m->keys = NULL;
    m->nicknames = NULL;
    m->refcount = 1;
    return m;
}

/* 
 * Make a new, independent copy of the old keymap. This allocates new memory
 * with a new reference count.  abac_keyid_map_free must be called on it.
 */
abac_keyid_map_t *abac_keyid_map_clone(abac_keyid_map_t *old) {
    abac_keyid_map_t *m = abac_xmalloc(sizeof(abac_keyid_map_t));
    abac_keyid_mapping_t *me = NULL;

    m->keys = NULL;
    m->nicknames = NULL;
    m->refcount = 1;

    for ( me = old->keys; me ; me = me->hh.next) 
	abac_keyid_map_add_nickname(m, me->key, me->value);

    return m;
}

/* 
 * Add a reference to the old map and return it.  The reference count has been
 * incremented, so the underlying memory will not be freed until
 * abac_keyid_map_free is called once for each reference.
 */
abac_keyid_map_t *abac_keyid_map_dup(abac_keyid_map_t *old) {
    old->refcount ++;
    return old;
}

/*
 * Free the reference-counted map m.  Decrement the reference count.  If and
 * only if the reference count is 0 or less, delete all the associated memory.
 */
void abac_keyid_map_free(abac_keyid_map_t *m) {
    abac_keyid_mapping_t *me = NULL;

    if ( --m->refcount > 0) return;

    while ( (me = m->keys) ) {
	HASH_DEL(m->keys, me);
	abac_keyid_mapping_free(me);
    }
    while ( (me = m->nicknames) ) {
	HASH_DEL(m->nicknames, me);
	abac_keyid_mapping_free(me);
    }
    free(m);
}

/*
 * Return the nickname associated with this keyid, if nay.  The caller is
 * responsible for freeing the returned string.
 */
char *abac_keyid_map_key_to_nickname(abac_keyid_map_t *m, char *key) {
    abac_keyid_mapping_t *me = NULL;

    if ( !key || !m) return 0;
    HASH_FIND_STR(m->keys, key, me);

    if ( me ) return abac_xstrdup(me->value);
    else return NULL;
}

/*
 * Return the keyid associated with this nickname, if nay.  The caller is
 * responsible for freeing the returned string.
 */
char *abac_keyid_map_nickname_to_key(abac_keyid_map_t *m, char *nick) {
    abac_keyid_mapping_t *me = NULL;

    if ( !nick || !m ) return 0;
    HASH_FIND_STR(m->nicknames, nick, me);

    if ( me ) return abac_xstrdup(me->value);
    else return NULL;
}

/*
 * Remove this keyid from both mappings.
 */
int abac_keyid_map_remove_keyid(abac_keyid_map_t *m, char *key) {
    abac_keyid_mapping_t *me = NULL;
    abac_keyid_mapping_t *nne = NULL;

    HASH_FIND_STR(m->keys, key, me);
    if ( !me ) return 0;
    HASH_FIND_STR(m->nicknames, me->value, nne);
    /* delete from keys */
    HASH_DEL(m->keys, me);
    abac_keyid_mapping_free(me);
    /* If we found a nickname, delete that too */
    if ( nne ) { 
	HASH_DEL(m->nicknames, nne);
	abac_keyid_mapping_free(nne);
    }
    return 1;
}

/*
 * If this keyid is not mapped to a nickname, add a mapping from key to
 * nickname.  If the nickname is already assigned to a key, disambiguate it by
 * adding trailing numbers.  If more than 1000 tries are made to disambiguate,
 * give up.
 */
int abac_keyid_map_add_nickname(abac_keyid_map_t *m, char *key, char *nick) {
    abac_keyid_mapping_t *me = NULL;
    char *name = NULL;
    char *p = NULL;
    int i =0;

    if ( !key || !nick) return 0;
    if ( (p = abac_keyid_map_key_to_nickname(m, key))) {
	free(p);
	return 0;
    }

    if ( !(name = abac_xmalloc(strlen(nick)+10))) return 0;
    sprintf(name, "%s", nick);

    while (abac_keyid_map_nickname_to_key(m, name) && i < 1000) 
	sprintf(name, "%s%05d", nick, i++);

    if ( i < 1000 ) {
	me = abac_keyid_mapping_new(key, name);
	HASH_ADD_KEYPTR(hh, m->keys, me->key, strlen(me->key), me);
	me = abac_keyid_mapping_new(name, key);
	HASH_ADD_KEYPTR(hh, m->nicknames, me->key, strlen(me->key), me);
    }
    free(name);
    return (i < 1000);
}

/*
 * Merge the mappings in src to the mappings in dest.  If overwrite is true,
 * src mappings always overwrite dest mappings, otherwise the dest mappings
 * remain.  Calls abac_keyid_map_add_nickname internally, so nicknames in src
 * that are also in dest are disambiguated.
 */
void abac_keyid_map_merge(abac_keyid_map_t *dest, abac_keyid_map_t *src, 
	int overwrite) {
    abac_keyid_mapping_t *me = NULL;
    if ( !dest || !src ) return;

    for (me = src->keys; me; me = me->hh.next) {
	char *n = abac_keyid_map_key_to_nickname(dest, me->key);
	if ( n ) {
	    free(n);
	    if ( overwrite) {
		abac_keyid_map_remove_keyid(dest,me->key);
		abac_keyid_map_add_nickname(dest, me->key, me->value);
	    }
	} else {
	    abac_keyid_map_add_nickname(dest, me->key, me->value);
	}
    }
}

/*
 * Utility function to identify separator characters in a role.
 */
static int is_sep(char *c) {
    switch (*c) {
	case ' ':
	case '.':
	    return 1;
	default:
	    return 0;
    }
}

/*
 * Break s into sections by separator characters (see is_sep) and copy them
 * into a return value.  If lookup finds a replacement for a section, the
 * replacement is used, otherwise the original string is used.  Using different
 * lookup functions implements expand_key and expand_name.  In either case, the
 * caller is responsible for freeing the returned value.
 */
static char *abac_keyid_map_replace(abac_keyid_map_t *m, char *s, 
	char *(*lookup)(abac_keyid_map_t *, char *)) {
    int lim = strlen(s);
    int i; 
    int sz = 0;
    char *rv = NULL;
    char *start = s;
    char old = '\0';
    char *repl = NULL;
    char *newrv = NULL;
    int newlen = 0;

    for ( i = 0; i < lim; i++ ) {
	if ( is_sep(s+i) ) {
	    old = s[i];
	    s[i] = '\0';
	   
	    if ( !(repl = lookup(m, start)) ) repl = start;

	    newlen = strlen(repl)+1;

	    if ( !(newrv = abac_xrealloc(rv, sz + newlen +1)) ) {
		if ( rv ) free(rv);
		return NULL;
	    } else {
		rv = newrv;
		if (sz == 0 ) 
		    rv[0] = '\0';
		sz += newlen;
	    }
	    strncat(rv, repl, newlen);
	    rv[sz-1] = old;
	    rv[sz] = '\0';
	    s[i] = old;
	    start = s+i+1;
	}
    }
    if ( start != s+i ) {
	if ( !(repl = lookup(m, start)) ) repl = start;

	newlen = strlen(repl);

	if ( !(newrv = abac_xrealloc(rv, sz + newlen +1)) ) {
	    if ( rv ) free(rv);
	    return NULL;
	} else {
	    rv = newrv;
	    if ( sz == 0) 
		rv[0] = '\0';
	    sz += newlen;
	}
	strncat(rv, repl, newlen);
    }
    return rv;
}

/*
 * Break s up into sections and replace any keyids that have nicknames with
 * those nicknames.  The caller is responsible for freeing the return value.
 */
char *abac_keyid_map_expand_key(abac_keyid_map_t *m, char *s) {
    return abac_keyid_map_replace(m , s, abac_keyid_map_key_to_nickname);
}

/*
 * Break s up into sections and replace any nicknames that have keyids with
 * those keyids.  The caller is responsible for freeing the return value.
 */
char *abac_keyid_map_expand_nickname(abac_keyid_map_t *m, char *s) {
    return abac_keyid_map_replace(m , s, abac_keyid_map_nickname_to_key);
}
