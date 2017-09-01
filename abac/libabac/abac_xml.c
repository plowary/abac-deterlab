/* abac_xml.c, specifically for GENI */

/* in xml, rc in general is, 1 is good, 0 or -1 is bad */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#ifndef XMLSEC_NO_XSLT
#include <libxslt/xslt.h>
#include <libxslt/security.h>
#endif /* XMLSEC_NO_XSLT */

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/base64.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/list.h>

#include <openssl/sha.h>

#include "abac.h"
#include "abac_util.h"
#include "abac_list.h"

extern int abac_verifier_load_id_chars(abac_list_t*, char*, abac_keyid_map_t *); 
extern void abac_get_sha_from_nake_pem(char *npem, char **sha1);
extern void abac_split(char *string, char *delim, char **ret, int *num);

/* from Ted's reader */

/* for accessing GENI privilege credentials */
#define GENI_signed_credential "signed-credential"
#define GENI_credential "credential"
#define GENI_type "type"
#define GENI_serial "serial"
#define GENI_owner_gid "owner_gid"
#define GENI_owner_urn "owner_urn"
#define GENI_target_gid "target_gid"
#define GENI_target_urn "target_urn"
#define GENI_uuid "uuid"
#define GENI_expires "expires"
#define GENI_privileges "privileges"
#define GENI_privilege "privilege"
#define GENI_name "name"
#define GENI_can_delegate "can_delegate"
#define GENI_x509_certificate "X509Certificate"

/* for accessing GENI abac credentials. signed-credential, credential, type and
 * expires are present as well.  */
#define GENI_abac "abac"
#define GENI_rt0 "rt0"
#define GENI_version "version"

/* maximum credential stringlen */
#define CREDLEN 1024
/* Maximum version len */
#define VERSIONLEN 256

/* These templates are given in defines so that they can initialize the
 * specialization structures. */

/* XML template for a new RT0 v1.0 credential.  Fill in the RT0 to store (XML
 * escaped) and the expiration time (formated using strftime_format and
 * strftime). */
#define template_v10 "<signed-credential>\n"\
"    <credential xml:id=\"ref0\">\n"\
"	<type>abac</type>\n"\
"	<version>1.0</version>\n"\
"	<expires>%s</expires>\n"\
"	<rt0>%s</rt0>\n"\
"    </credential>\n"\
"    <signatures>\n"\
"	<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"\
"	    <SignedInfo>\n"\
"		<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"\
"		<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"\
"		<Reference URI=\"#ref0\">\n"\
"		    <Transforms>\n"\
"			<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"\
"		    </Transforms>\n"\
"		    <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"\
"		    <DigestValue/>\n"\
"		</Reference>\n"\
"	    </SignedInfo>\n"\
"	    <SignatureValue/>\n"\
"	    <KeyInfo>\n"\
"	      <KeyValue/>\n"\
"		<X509Data>\n"\
"		    <X509Certificate/>\n"\
"		    <X509SubjectName/>\n"\
"		    <X509IssuerSerial/>\n"\
"		</X509Data>\n"\
"	    </KeyInfo>\n"\
"	</Signature>\n"\
"    </signatures>\n"\
"</signed-credential>"

/* XML template for a new RT0 v1.1 credential.  Fill in the RT0 to store (XML
 * escaped) and the expiration time (formated using strftime_format and
 * strftime). */
#define template_v11 "<signed-credential>\n"\
"    <credential xml:id=\"ref0\">\n"\
"	<type>abac</type>\n"\
"	<serial/>\n"\
"	<owner_gid/>\n"\
"	<target_gid/>\n"\
"	<uuid/>\n"\
"	<expires>%s</expires>\n"\
"	<abac>\n"\
"	    <rt0>\n"\
"		<version>1.1</version>\n"\
"		%s\n"\
"	    </rt0>\n"\
"	</abac>\n"\
"    </credential>\n"\
"    <signatures>\n"\
"	<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"\
"	    <SignedInfo>\n"\
"		<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n"\
"		<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"\
"		<Reference URI=\"#ref0\">\n"\
"		    <Transforms>\n"\
"			<Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"\
"		    </Transforms>\n"\
"		    <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"\
"		    <DigestValue/>\n"\
"		</Reference>\n"\
"	    </SignedInfo>\n"\
"	    <SignatureValue/>\n"\
"	    <KeyInfo>\n"\
"	      <KeyValue/>\n"\
"		<X509Data>\n"\
"		    <X509Certificate/>\n"\
"		    <X509SubjectName/>\n"\
"		    <X509IssuerSerial/>\n"\
"		</X509Data>\n"\
"	    </KeyInfo>\n"\
"	</Signature>\n"\
"    </signatures>\n"\
"</signed-credential>"

/* Forward declarations of functions to parse and generate rt0 elements in
 * various formats */
xmlChar *encode_rt0_xml_v10(abac_attribute_t *);
xmlChar *encode_rt0_xml_v11(abac_attribute_t *);
xmlChar **parse_rt0_xml_v10(xmlNodePtr, abac_keyid_map_t *);
xmlChar **parse_rt0_xml_v11(xmlNodePtr, abac_keyid_map_t *);

/* Structure that specializes XML parsing */
typedef struct {
    /* Version to use these functions for */
    char *version;  
    /* Convert an ABAC attribute into an rt0 element */
    xmlChar *(*rt0_to_xml)(abac_attribute_t *);
    /* Convert an rt0 element into a list of RT0 strings */
    xmlChar **(*xml_to_rt0)(xmlNodePtr, abac_keyid_map_t *);
    /* The overall template to generate this version of credential */
    char *out_template;
} GENI_xml_processing_t;

/* The processing specializations */
GENI_xml_processing_t xml_proc[] = {
    { "GENIv1.0", encode_rt0_xml_v10, parse_rt0_xml_v10, template_v10},
    { "1.0", encode_rt0_xml_v10, parse_rt0_xml_v10, template_v10},
    { "GENIv1.1", encode_rt0_xml_v11, parse_rt0_xml_v11, template_v11},
    { "1.1", encode_rt0_xml_v11, parse_rt0_xml_v11, template_v11},
    { NULL, NULL, NULL},
};

/* Query funtion to convert a processing version into the functions above */
GENI_xml_processing_t *get_xml_processing(char *ver) {
    int i ;

    for (i = 0; xml_proc[i].version; i++) {
	if (!strcmp(xml_proc[i].version, ver))
	    return &xml_proc[i];
    }
    return NULL;
}


/* Convert a SHA1 hash to text for printing or use in strings.  keyid is the
 * hash (SHA_DIGEST_LENGTH bytes long) and text is the output string (at least
 * 2 * SHA_DIGEST_LENGTH +1 bytes long).  The caller is responsible for
 * allocating and deallocating each of them. */
static void sha1_to_text(xmlChar *keyid, xmlChar *text) {
    int i = 0;

    for (i=0; i < SHA_DIGEST_LENGTH; i++) 
	snprintf((char *) text+2*i, 3, "%02x", keyid[i] & 0xff);
}

/*
 * Returns the content pointer of the XML_TEXT node that is the child of the
 * node passed in.  Node must point to an XML_ELEMENT node.  the return value
 * is still part of node's XML document, so treat it as read only. */
static xmlChar *get_element_content(xmlNodePtr node) {
    xmlNodePtr text = NULL;

    if ( node->type != XML_ELEMENT_NODE ) return NULL;
    if ( !( text = node->children) ) return NULL;
    if ( text->type != XML_TEXT_NODE ) return NULL;
    return text->content;
}

/*Find the XML element named field that is a at or below node in the XML
 * document and return a copy of the base64 decoded content of its content.
 * For example, find key day in a signature and return it base64decoded.  buf
 * is allocated and its length is returned in len.  Any values for buf and len
 * are ignored and overwritten. */
static int get_base64_field(xmlNodePtr node, xmlChar *field, 
	xmlChar **buf, int *len) {
    xmlChar *txt = NULL;

    *buf = NULL;

    if ( !(node = xmlSecFindNode(node, field, xmlSecDSigNs)))
	goto fail;

    if ( !(txt = get_element_content(node))) 
	    goto fail;
    
    *len = strlen((char *) txt);
    if ( !(*buf = malloc(*len))) 
	goto fail;

    if ( (*len = xmlSecBase64Decode(txt, *buf, *len)) < 0 ) 
	goto fail;

    return 1;
fail:
    if ( *buf) free(*buf);
    *len = 0;
    return 0;
}
/* Construct an ASN.1 header for a field of type h that is len bytes long.
 * Mosttly this creates the proper length encoding under ASN.1's length
 * encoding rules. buf will contain the new header (and the caller is
 * responsible for making sure it is at least 6 bytes long, though fewer are
 * usually used.  The length of the constructed header is returned. This is
 * used in creating a key hash from key data.*/
static int make_asn1_header(char h, size_t len, xmlChar *buf) {
    if ( len > 0x00ffffff) {
	buf[0] = h;
	buf[1] = 0x84;
	buf[2] = (len >> 24) & 0xff;
	buf[3] = (len >> 16) & 0xff;
	buf[4] = (len >> 8) & 0xff;
	buf[5] = (len) & 0xff;
	return 6;
    } else if ( len > 0x0000ffff ) {
	buf[0] = h;
	buf[1] = 0x83;
	buf[2] = (len >> 16) & 0xff;
	buf[3] = (len >> 8) & 0xff;
	buf[4] = (len) & 0xff;
	return 5;
    } else if ( len > 0x000000ff ) {
	buf[0] = h;
	buf[1] = 0x82;
	buf[2] = (len >> 8) & 0xff;
	buf[3] = (len) & 0xff;
	return 4;
    } else if ( len > 0x80 ) {
	buf[0] = h;
	buf[1] = 0x81;
	buf[2] = (len) & 0xff;
	return 3;
    } else {
	buf[0] = h;
	buf[1] = (len) & 0xff;
	return 2;
    }
}

/* Find the RSA key parameters in the KeyInfo section of the XML document
 * pointed to by doc, construct the ASN.1 encoding of that key and SHA1 hash
 * it.    This gives the standard keyid of that key.  keyid will be the binary
 * encoding of that (the bits of the hash)  sha1_to_text will turn it to text.
 * keyid must be at least SHA_DIGEST_LENGTH bytes long, and the caller is
 * responsible for it. This routine returns 1 on success and 0 on failure. */
static int get_keyid_from_keyinfo(xmlDocPtr doc, xmlChar *keyid) {
    xmlNodePtr root = NULL; /* XML document root */
    xmlNodePtr node = NULL; /* Scratch XML node */

    xmlChar b0[20];	    /* Header for the sequence */
    xmlChar b1[20];	    /* Header for the modulus */
    xmlChar b2[20];	    /* Header for the exponent */
    int l0 = 0;		    /* Header length for the sequence */
    int l1 = 0;		    /* Header length for the modulus */
    int l2 = 0;		    /* Header length for the exponent */

    xmlChar *modBuf = NULL; /* Bytes of the modulus */
    xmlChar *expBuf = NULL; /* Bytes of the exponent */
    int modLen = 0;	    /* Length of the modulus */
    int expLen = 0;	    /* Length of the exponent */

    SHA_CTX sha;	    /* SHA1 hash context */

    int rv = 0;		    /* return value */

    if ( !SHA1_Init(&sha)) goto fail;

    if ( !doc || !(root = xmlDocGetRootElement(doc)) ) 
	goto fail;

    /* Find the KeyInfo section to be the root of later searches */
    if ( !(node = xmlSecFindNode(root, 
		    xmlSecNodeKeyInfo, xmlSecDSigNs)))
	goto fail;

    /* Get the binary for the modulus and exponent */
    if ( !get_base64_field(node, (xmlChar *) "Modulus", &modBuf, &modLen)) 
	goto fail;
    if ( !get_base64_field(node, (xmlChar *) "Exponent", &expBuf, &expLen)) 
	goto fail;

    /* Construct the headers for modulus and exponent.  Another weird fact
     * about ASN.1 is that all the integers are signed, so if either the
     * modulus or exponent has the high order bit of its first byte set, the
     * ASN.1 encoding has a 0 byte prepended.  This code appends the 0 byte to
     * the header, which results in the same hash. */
    if ( modBuf[0] & 0x80 ) {
	l1 = make_asn1_header(0x02, modLen +1, b1);
	b1[l1++] = '\0';
    } else {
	l1 = make_asn1_header(0x02, modLen, b1);
    }

    if ( expBuf[0] & 0x80 ) {
	l2 = make_asn1_header(0x02, expLen +1, b2);
	b2[l2++] = '\0';
    } else {
	l2 = make_asn1_header(0x02, expLen, b2);
    }

    /* Sequence header: have to do it after we know the lengths of the inner
     * headers. */
    l0 = make_asn1_header(0x30, modLen + expLen + l1 + l2, b0);
    /* Hash it all up in parts */
    SHA1_Update(&sha, b0, l0);
    SHA1_Update(&sha, b1, l1);
    SHA1_Update(&sha, modBuf, modLen);
    SHA1_Update(&sha, b2, l2);
    SHA1_Update(&sha, expBuf, expLen);
    SHA1_Final(keyid, &sha);
    rv = 1;
fail:

    if (modBuf) free(modBuf);
    if (expBuf) free(expBuf);
    return rv;
}

/* Check the signature of either kind of credential - it'll work for basically
 * any signed XML. Returns true if the signature checks and false otherwise.
 * Takes a pointer to the XML document to check.  Similar to the examples at
 * http://www.aleksey.com/xmlsec/api/xmlsec-examples.html */
static int check_signature(xmlDocPtr doc) {
    xmlNodePtr root = NULL;	    /* Root XML node */
    xmlNodePtr node = NULL;	    /* Scratch XML node */
    xmlSecKeyInfoCtxPtr keyCtx = NULL;/* Key info context.  Used to parse
					 KeyInfo */
    xmlSecKeysMngrPtr keyMan = NULL;/* Key manager - used because we have
				       certificated. */
    xmlSecKeyPtr key = NULL;	    /* The key extracted */
    xmlSecDSigCtxPtr dsigCtx = NULL;/* Signature context */
    int rv = 0;			    /* Return value */

    if ( doc && !(root = xmlDocGetRootElement(doc)) ) 
	goto fail;

    /* Find the KeyInfo section to pull the keys out. */
    if ( !(node = xmlSecFindNode(root, 
		    xmlSecNodeKeyInfo, xmlSecDSigNs)))
	goto fail;

    /* Create and initialize key, key manager, and context */
    if ( !(key = xmlSecKeyCreate() ) )
	    goto fail;
    if ( !(keyMan = xmlSecKeysMngrCreate()) ) 
	goto fail;

    if ( xmlSecCryptoAppDefaultKeysMngrInit(keyMan) < 0)
	goto fail;

    if ( !(keyCtx = xmlSecKeyInfoCtxCreate(keyMan)) ) 
	goto fail;

    /* Do not check certificate signatures */
    keyCtx->flags |= XMLSEC_KEYINFO_FLAGS_X509DATA_DONT_VERIFY_CERTS;

    /* Gather up the key data */
    if ( xmlSecKeyInfoNodeRead(node, key, keyCtx) < 0 ) 
	goto fail;

    /* Set up the signature context and attack the keys */
    if ( !(dsigCtx = xmlSecDSigCtxCreate(NULL)))
	goto fail;

    dsigCtx->signKey = key;
    key = NULL;

    /* find the Signature section */
    if ( !(node = xmlSecFindNode(root, 
		    xmlSecNodeSignature, xmlSecDSigNs)))
	goto fail;

    /* Check it */
    if ( (rv = xmlSecDSigCtxVerify(dsigCtx, node)) < 0 ) 
	goto fail;

    /* Strangely xmlSecDSigCtxVerify can return success even if the status is
     * bad.  Check the status in the context explicitly and override the result
     * above if necessary.*/
    if ( dsigCtx->status != xmlSecDSigStatusSucceeded) 
	goto fail;

/*??? .. valgrind said leaking without these */
    if ( keyMan) xmlSecKeysMngrDestroy(keyMan);
    if ( keyCtx ) xmlSecKeyInfoCtxDestroy(keyCtx);
    if ( dsigCtx) xmlSecDSigCtxDestroy(dsigCtx);

    return 1;
fail:
    if ( keyMan) xmlSecKeysMngrDestroy(keyMan);
    if ( keyCtx ) xmlSecKeyInfoCtxDestroy(keyCtx);
    if ( key ) xmlSecKeyDestroy(key);
    if ( dsigCtx) xmlSecDSigCtxDestroy(dsigCtx);
    return 0;
}

/* Extract a sha from PEM blob */
static void extract_owner_sha1(xmlChar *pem, xmlChar **sha1) {
    abac_get_sha_from_nake_pem((char *) pem, (char **)sha1); 
}
static void extract_target_sha1(xmlChar *pem, xmlChar **sha1) {
    abac_get_sha_from_nake_pem((char *) pem,(char **)sha1); 
}

static int is_time_separator(char *c) {
    return (*c == '\0' || *c == 'T');
}

static int is_tz_separator(char *c) {
    return (*c == '\0' || *c == 'Z' || *c == '-' || *c=='+' );
}

static int parse_ISO_time(xmlChar *expires, struct tm *out) {
    /* Parse an ISO 8601 formatted datetime.  Strptime isn't nearly smart
     * enough to handle this without help.  ISO 8061 has a demented range of
     * valid formats.  We parse this into "basic" format dates and times,
     * separated by the T that splits a timestamp.  A "basic" format date only
     * has the digits necessary for that representation.  Once the whole thing
     * is cannonicalized, we call strptime on it.
     *
     * Return 0 on error.
     */

#define DATELEN 8
#define TIMELEN 6
#define ZONELEN 5
/* 1 for the terminal \0 */
#define PARSABLELEN DATELEN + TIMELEN + ZONELEN + 1

    char *timeSep = NULL;
    char *tzSep = NULL;
    char *c = NULL;
    int tot = 0;
    char parsable[PARSABLELEN];

    for (timeSep = (char *) expires; !is_time_separator(timeSep); timeSep++)
	;
    if (*timeSep == '\0') return 0;
    for (tzSep = timeSep+1; !is_tz_separator(tzSep); tzSep++)
	;

    /* Found our markers, parse it into the parsable array */
    /* Copy exactly DATELEN digits into parsable (%Y%m%d). */
    tot = 0;
    for ( c = (char *) expires; c != timeSep; c++ ) {
	if (isdigit(*c)) {
	    if ( tot >= DATELEN) return 0;
	    parsable[tot++] = *c;
	}
    }
    if ( tot != DATELEN ) return 0;

    /* Copy exactly TIMELEN digits into parsable (%H%M%S) after the date. */
    tot = 0;
    for ( c = (char *) timeSep+1; c != tzSep; c++ ) {
	if (isdigit(*c)) {
	    /* Only copy the first TIMELEN.  If the stamp includes fractions of
	     * a second, ignore 'em. */
	    if ( tot >= TIMELEN) break;
	    parsable[DATELEN + tot++] = *c;
	}
    }
    if ( tot != TIMELEN ) return 0;
    /* null-terminate parsable */
    parsable[DATELEN+TIMELEN] = '\0';

    /* If no timezone is given or Z is given, copy a GMT offset into parsable,
     * otherwise parse ZONELEN digits or +/- into parsable after the DATE and
     * TIME. */
    if ( *tzSep == 'Z' || *tzSep == '\0' ) {
	strncat(parsable, "+0000", ZONELEN);
    }
    else {
	tot = 0;
	for ( c = (char *) tzSep; *c != '\0'; c++ ) {
	    if (isdigit(*c) || *c == '+' || *c == '-') {
		if ( tot >= ZONELEN) return 0;
		parsable[DATELEN + TIMELEN + tot++] = *c;
	    }
	}
	if ( tot != ZONELEN ) return 0;
    }
    /* null-terminate parsable */
    parsable[DATELEN+TIMELEN+ZONELEN] = '\0';
    return ( strptime(parsable, "%Y%m%d%H%M%S%z", out) != NULL );
}

/* Parse the content of the expires field and compare it to the time passed in
 * n.  If expires is earlier, return false, else true.  If n is null, compare
 * it to the current time. */
static int check_GENI_expires(xmlChar *expires, struct tm *n) {
    struct tm tv;   /* Parsed expires field */
    time_t now;	    /* Now in seconds since the epoch */
    time_t exp;	    /* expires in seconds since the epoch */

    if (n) now = mktime(n);
    else time(&now);

    if ( !parse_ISO_time(expires, &tv)) return 0;
    exp = timegm(&tv);

    return difftime(exp, now) > 0.0;
}

/* Convert a parsed privilege in a GENI privilege string into one or more ABAC
 * creds.  Rules are as in http://groups.geni.net/geni/wiki/TIEDCredentials .
 * keyid is  the issuer's keyid, text_owner is the owners keyid (XXX:a
 * placeholder) text_target is the target's keyid (XXX: a placeholder), priv is
 * the privilege being assigned, and delegate is true if it can be delegated.
 * carray is the output array of character strings that currently has *nc
 * entries in it.  If nc has nothing in it, insert the "speaks_for" delegation
 * rules.  Then add the privilege specific rules. On failure ***carray and its
 * contents are freed and *nc is set to zero.*/
static void add_privilege_credential_string(xmlChar *text_keyid, xmlChar *text_owner, 
	xmlChar *text_target, xmlChar *priv, int delegate, xmlChar ***carray,
	int *nc) {
    xmlChar **rv = *carray;	/* Local pointer to the array of strings */
    xmlChar **newrv = NULL;	/* Used to realloc the array of strings */
    int ncred = *nc;		/* Local copy of the number of creds in rv */
    int newc = (delegate) ? 3 : 1;  /* Number of new creds to add */
    int base = ncred;		/* First new credential index.  This advances
				   as we add creds to rv. */
    int i = 0;			/* Scratch */

    /* If rv is empty, add the speaks_for rules */
    if (base == 0 ) newc += 2;

    /* Resize rv */
    if (!(newrv = realloc(rv, (base + newc) * sizeof(xmlChar *))))
	goto fail;

    for ( i = base; i < base +newc; i ++) { 
	newrv[i] = NULL;
    }

    /* So fail works */
    rv = newrv;
    ncred = base + newc;

    /* Add speaks_for rules  if needed */
    if ( base == 0 ) {
	if ( !(rv[base] = malloc(CREDLEN))) goto fail;
	snprintf((char *) rv[base], CREDLEN, 
		"%s.speaks_for_%s <- %s.speaks_for_%s",
		text_keyid, text_owner, text_owner, text_owner);
	base++;
	if ( !(rv[base] = malloc(CREDLEN))) goto fail;
	snprintf((char *) rv[base], CREDLEN, 
		"%s.speaks_for_%s <- %s",
		text_keyid, text_owner, text_owner);
	base++;
    }

    /* The assignemnt of priv.  Always happens */
    if ( !(rv[base] = malloc(CREDLEN))) goto fail;
    snprintf((char *) rv[base], CREDLEN, 
	    "%s.%s_%s <- %s.speaks_for_%s",
	    text_keyid, priv, text_target, text_keyid, text_owner);
    base++;
    /* Add delegation rules */
    if ( delegate ) {
	if ( !(rv[base] = malloc(CREDLEN))) goto fail;
	snprintf((char *) rv[base], CREDLEN, 
		"%s.%s_%s <- %s.can_delegate_%s_%s.%s_%s",
		text_keyid, priv, text_target, text_keyid, priv, 
		text_target, priv, text_target);
	base++;
	if ( !(rv[base] = malloc(CREDLEN))) goto fail;
	snprintf((char *) rv[base], CREDLEN, 
		"%s.can_delegate_%s_%s <- %s",
		text_keyid, priv, text_target, text_owner);
	base++;
    }
    /* And return new values */
    *carray = rv;
    *nc = ncred;
    return;
fail:
    if ( rv ) {
	/* Delete all the allocations, ours or not, and clear the caller's 
	 * variables */
	for (i = 0; i < ncred; i++) 
	    if (rv[i]) free(rv[i]);
	free(rv);
    }
    *carray = NULL;
    *nc = 0;
}


/* Grab the issuer x509 blob */
static xmlChar *get_issuer(xmlDocPtr doc) {
    xmlNodePtr root = NULL;         /* Root XML node */
    xmlNodePtr node = NULL;         /* Scratch XML node */
    xmlNodePtr x509ptr = NULL;      /* XML X509Certificate node */
    xmlChar *pem=NULL;

    if (!(root = xmlDocGetRootElement(doc)) )
        goto fail;

    /* Find the KeyInfo section to be the root of later searches */
    if ( !(node = xmlSecFindNode(root,
                    xmlSecNodeKeyInfo, xmlSecDSigNs)))
        goto fail;

    if ( !(node = xmlSecFindNode(node,
                    xmlSecNodeX509Data, xmlSecDSigNs)))
        goto fail;

    /* Find the X509Certificate from KeyInfo section */
    if ( (x509ptr = xmlSecFindNode(node, xmlSecNodeX509Certificate, 
		    xmlSecDSigNs))) {
        pem=get_element_content(x509ptr);
        } else {
            goto fail;
    }
    return pem;
fail:
    return NULL;
}

/* Parse a GENI privilege credential (that has already had its signature
 * checked) and return the RT0 strings that the credential is encoded as.  The
 * return value is an array of strings, zero-terminated (like argv) that holds
 * the RT0 strings.  It is NULL on failure. */
static xmlChar **parse_privilege(xmlDocPtr doc, abac_list_t* ctxt_id_certs, 
	abac_keyid_map_t *km) {
    xmlNodePtr root = NULL;	/* XML root node */
    xmlNodePtr node = NULL;	/* XML scratch node */
    xmlNodePtr owner = NULL;	/* XML owner_gid node */
    xmlNodePtr expires = NULL;	/* XML expires node */
    xmlNodePtr target = NULL;	/* XML target_gid node */
    xmlNodePtr privs = NULL;	/* XML privileges node */
    xmlNodePtr priv = NULL;	/* XML privilege node - used to iterate */
    xmlChar keyid[SHA_DIGEST_LENGTH];	/* Issuer key SHA1 */
    xmlChar text_keyid[2*SHA_DIGEST_LENGTH+1];/* Issuer keyid as text */
    xmlChar *owner_sha1 = NULL;         /* owner gid as text */
    xmlChar *target_sha1 = NULL;        /* target gid as text */
    xmlChar **newrv = NULL;	/* Used to realloc rv to add the NULL
				   terminator*/
    xmlChar **rv = NULL;	/* return value */
    int ncred = 0;		/* number of creds in rv, incase we need to
				   deallocate it */
    int i = 0;			/* scratch */

    if ( doc && !(root = xmlDocGetRootElement(doc)) ) 
	goto fail;

    /* Get the issuer keyid */
    if ( !get_keyid_from_keyinfo(doc, keyid)) 
	goto fail;
    sha1_to_text(keyid, text_keyid);

    /* Find the various fields of interest */
    if ( !(node = xmlSecFindNode(root, (xmlChar *) GENI_credential, NULL)))
	goto fail;

    /* Make sure this is not expired */
    if ( !(expires = xmlSecFindNode(node, (xmlChar *) GENI_expires, NULL)))
	goto fail;

    if ( !check_GENI_expires(get_element_content(expires), NULL))
	goto fail;

    /* owner and target will be X.509 pem files from which we need to
     * extract keyids for add_privilege_credential_string.  */
    if ( !(owner = xmlSecFindNode(node, (xmlChar *) GENI_owner_gid, NULL)))
	goto fail;
    extract_owner_sha1(get_element_content(owner),&owner_sha1);

    if ( !(target = xmlSecFindNode(node, (xmlChar *) GENI_target_gid, NULL)))
	goto fail;
    extract_target_sha1(get_element_content(target),&target_sha1);

    /* extract issuer pem */
    xmlChar *issuer_ptr=get_issuer(doc);

    if ( !(privs = xmlSecFindNode(node, (xmlChar *) GENI_privileges, NULL)))
	goto fail;

    /* Iterate through the privileges, parsing out names and can_delegate and
     * generating the strings from it. */
    for (priv = privs->children; priv; priv = priv->next) {
	/* reinitialized every time around */
	xmlNodePtr n = NULL;
	xmlChar *name = NULL;
	int delegate = -1;

	/* Ignore wayward text and other gook */
	if ( priv->type != XML_ELEMENT_NODE) 
	    continue;

	/* Ignore things that are not privilege nodes */
	if ( strcmp((char *) priv->name, (char *) GENI_privilege) ) 
	    continue;

	/* looking for name and can_delegate */
	for (n = priv->children; n; n = n->next) {
	    if ( n->type != XML_ELEMENT_NODE ) 
		continue;
	    if ( !strcmp((char *) n->name, (char *) GENI_name)) {
		name = get_element_content(n);
		continue;
	    }
	    if ( !strcmp((char *) n->name, (char *) GENI_can_delegate)) {
		xmlChar *boolean = get_element_content(n);

		if ( !strcmp((char *) boolean, "true") ||
			!strcmp((char *) boolean, "1") ) {
		    delegate = 1;
		} else if ( !strcmp((char *) boolean, "false") ||
			!strcmp((char *) boolean, "0") ) {
		    delegate = 0;
		} else {
		    fprintf(stderr, "Unknown delegation value %s", boolean);
		}
	    }
	}
	/* Found both name and can_delegate, add the RT0 to rv and ncred */
	if ( name && delegate != -1 ) {
	    add_privilege_credential_string(text_keyid, 
		    (xmlChar *) owner_sha1, (xmlChar *) target_sha1, name,
		    delegate, &rv, &ncred);
	    if ( !rv ) goto fail;
	}
    }

    /* Add the terminating NULL */
    if (!(newrv = realloc(rv, sizeof(xmlChar*)*(ncred+1))))
	goto fail;

    newrv[ncred] = NULL;
    /* able to extract some RT0s, load issuer credential as side-effect */
    if(ncred !=1) {
        /* load  issuer_ptr */ 
        if(issuer_ptr && abac_verifier_load_id_chars(ctxt_id_certs, 
		    (char *) issuer_ptr, NULL) != 0 /*ABAC_CERT_SUCCESS*/)
            goto fail;
    }
    return newrv;

fail:
    /* Throw away all of rv if there's an error */
    if ( rv ) {
	for (i = 0; i < ncred; i++) 
	    if (rv[i]) free(rv[i]);
	free(rv);
    }
    return NULL;
}

/*
 * If n has a child that is an element named name, return a pointer to it,
 * other wise return NULL.
 */
static xmlNodePtr get_direct_child(xmlNodePtr n, xmlChar *name) {
    xmlNodePtr c = NULL;

    if ( !n ) return NULL;

    for (c = n->children; c; c = c->next) {
	if ( c->type != XML_ELEMENT_NODE ) 
	    continue;
	if ( !strcmp((char *) c->name, (char *) name)) 
	    return c;
    }
    return NULL;
}

/*
 * Convert a version 1.0 rt0 section to an RT0 string, returned in an array of
 * strings.  This is just allocating the array and copying the string.  RT0 1.0
 * has no structure.
 */
xmlChar **parse_rt0_xml_v10(xmlNodePtr n, abac_keyid_map_t *km) {
    xmlChar *txt;
    xmlChar **rv = NULL;

    /* read the RT0 and return it */
    if ( !(txt = get_element_content(n)) ) return NULL;

    if ( !(rv = malloc(2 * sizeof(xmlChar *)))) return NULL;
    if (!(rv[0] = malloc(strlen((char *) txt)+1))) {
	free(rv);
	return NULL;
    }
    strcpy((char *) rv[0], (char *) txt);
    rv[1] = NULL;
    return rv;
}

/* Return the length of the string pointed to by rn, ignoring whitespace */
static int role_len(xmlChar *rn) {
    xmlChar *p;
    int len = 0;

    for (p = rn; *p; p++) 
	if ( !isspace(*p) ) len++;
    return len;
}

/* Return the length of the RT0 string represented bt the RT0 1.1 term.  That
 * term looks like:
 * <head>
 *  <ABACprincipal><keyid>...</keyid><mnemonic>...</menmonic></ABACprincipal>
 *  <role>...</role>
 *  <linking_role>...</linking_role>
 * </head>
 * The container can be either a head or a tail, and the role and linking_role
 * are optional.  The result is the number of non whitespace characters in the
 * keyid, role, and linking_role fields (if present) plus a dot to separate
 * each field.
 */
static int term_len(xmlNodePtr n) {
    int len = 0;
    xmlNodePtr c = NULL;/* Scratch */

    for (c = n->children; c; c = c->next) {
	if ( c->type != XML_ELEMENT_NODE ) 
	    continue;
	if ( !strcmp((char *) c->name, "ABACprincipal")) {
	    xmlNodePtr k = get_direct_child(c, (xmlChar *)"keyid");
	    if ( !k ) return -1;
	    len += role_len(get_element_content(k));
	} else if (!strcmp((char *) c->name, "role")) {
	    len += role_len(get_element_content(c)) +1;
	} else if (!strcmp((char *) c->name, "linking_role")) {
	    len += role_len(get_element_content(c)) +1;
	}
    }
    return len;
}

/* Copy non-whitespace characters from rn to dest.  Return the final vaue of
 * dest, but no guarantees are made about it.  The caller must make sure there
 * is enough space in dest.
 */
static xmlChar *role_copy(xmlChar *rn, xmlChar *dest) {
    while (*rn) {
	if (!isspace(*rn)) *dest++ = *rn;
	rn++;
    }
    return dest;
}

/* Turn the contents of the node pointer into a dotted string representation of
 * the RT0 term.  For example
 * <tail>
 *  <ABACprincipal><keyid>P</keyid><mnemonic>...</menmonic></ABACprincipal>
 *  <role>r2</role>
 *  <linking_role>r1</linking_role>
 * </tail>
 * becomes P.r1.r2.
 * In addition, if there is a mnemonic in the ABACPrincipal field, add it to
 * the keyid_map (if there is a map).
 */
static xmlChar *term_copy(xmlNodePtr n, xmlChar *dest, abac_keyid_map_t *km) {
    xmlNodePtr p = get_direct_child(n, (xmlChar *)"ABACprincipal");
    xmlNodePtr k = NULL;
    xmlNodePtr m = NULL;
    xmlChar *ks = NULL;
    xmlChar *ms = NULL;

    if ( !p ) return NULL;
    if ( !(k = get_direct_child(p, (xmlChar *)"keyid"))) return NULL;
    if ( !(ks = get_element_content(k))) return NULL;
    if ( !(dest = role_copy(ks, dest))) return NULL;
    /* If there's a mnemonic string, add the mapping from keyid to mnemonic to
     * the keymap */
    if ( (m = get_direct_child(p, (xmlChar *)"mnemonic"))) {
	if ( (ms = get_element_content(m))) {
	    abac_keyid_map_remove_keyid(km, (char *) ks);
	    abac_keyid_map_add_nickname(km, (char *) ks, (char *) ms);
	}
    }
    if ( (p = get_direct_child(n, (xmlChar *)"linking_role"))) {
	*dest++ = '.';
	if ( !(dest = role_copy(get_element_content(p), dest))) return NULL;
    }
    if ( (p = get_direct_child(n, (xmlChar *)"role"))) {
	*dest++ = '.';
	if ( !(dest = role_copy(get_element_content(p), dest))) return NULL;
    }
    return dest;
}

/*
 * Append at most sz characters from a to d and advance d by sz characters.  No
 * checking is done.
 */
static xmlChar *append_and_move(xmlChar *d, xmlChar *a, int sz) {
    int i = 0; 
    for ( i = 0; i < sz && a[i] != '\0'; i++) 
	*d++ = a[i];
    return d;
}

/*
 * Parse a structured RT0 v 1.1 xml into an RT0 string.  For example
 * <head>
 *  <ABACprincipal><keyid>A</keyid><mnemonic>...</menmonic></ABACprincipal>
 *  <role>r</role>
 * </head>
 * <tail>
 *  <ABACprincipal><keyid>B</keyid><mnemonic>...</menmonic></ABACprincipal>
 *  <role>r2</role>
 *  <linking_role>r1</linking_role>
 * </tail>
 * <tail>
 *  <ABACprincipal><keyid>C</keyid><mnemonic>...</menmonic></ABACprincipal>
 *  <role>r2</role>
 * </tail>
 *
 * Converts to A.r<-B.r1.r2 & C.r2
 */
xmlChar **parse_rt0_xml_v11(xmlNodePtr n, abac_keyid_map_t *km) {
    int len = 3;    /* Length of the RT0 string we're building. Initially 3 for
		       the <- and end-of-string */
    int heads = 0;  /* number of tails so far */
    int tails = 0;  /* number of tails so far */
    xmlNodePtr c = NULL;/* Scratch */
    xmlChar **rv = NULL;
    xmlChar *d = NULL;

    /* Compute the length of the new string and make sure we have a head and at
     * least one tail.
     */
    if ( !n ) return NULL;

    for (c = n->children; c; c = c->next) {
	if ( c->type != XML_ELEMENT_NODE ) 
	    continue;
	if ( !strcmp((char *) c->name, "head") ) {
	    len += term_len(c);
	    heads ++;
	} else if (!strcmp((char *) c->name, "tail")) {
	    len += term_len(c);
	    /* if more than one tail, add space for " & " */
	    if ( tails++) len += 3; 
	}
    }
    if ( heads != 1 || tails < 1) return NULL;

    /* Allocate the return value */
    if ( !(rv = malloc(2 * sizeof(xmlChar *)))) return NULL;
    if (!(rv[0] = malloc(len)) ) {
	free(rv);
	return NULL;
    }
    rv[1] = NULL;

    /* Translate term by term */
    d = rv[0];
    if ( !( c = get_direct_child(n, (xmlChar *)"head"))) goto fail;
    if ( !(d = term_copy(c, d, km))) goto fail;
    d = append_and_move(d, (xmlChar *)"<-", 2);
    tails = 0;
    for (c = n->children; c; c = c->next) {
	if ( c->type != XML_ELEMENT_NODE ) 
	    continue;
	if ( !strcmp((char *) c->name, "tail") ) {
	    /* if more than one tail, add " & " */
	    if ( tails++) 
		d = append_and_move(d, (xmlChar *)" & ", 3);
	    if ( !(d = term_copy(c, d, km))) goto fail;
	}
    }
    *d++ = '\0';
    return rv;

fail:
    free(rv[0]);
    free(rv);
    return NULL;
} 
/*
 * Parse an ABAC credential (that has had its signature checked.  Make sure it
 * has not expired and that its version is one we know.  Return the RT0 it
 * encodes as the only entry in an NULL-terminated array of strings (just like
 * parse_privilege). On failure return NULL.  In addition to parsing the
 * certificate, we add the issuer's identity from the signature to the
 * controlling context, if any.  ctxt_id_certs is the list of certificates to
 * which the new certificate is added.
 */
xmlChar **parse_abac(xmlDocPtr doc, abac_list_t *ctxt_id_certs, abac_keyid_map_t *km) {
    xmlNodePtr root = NULL;	/* XML root node */
    xmlNodePtr node = NULL;	/* XML credential node */
    xmlNodePtr rt0 = NULL;	/* XML rt0 node */
    xmlNodePtr expires = NULL;	/* XML expires node */
    xmlNodePtr version = NULL;	/* XML version node */
    xmlChar keyid[SHA_DIGEST_LENGTH];/* issuer SHA1 hash */
    xmlChar text_keyid[2*SHA_DIGEST_LENGTH+1];/* Issuer keyid in text */
    xmlChar **rv = NULL;	/* return value */
    xmlChar *issuer_ptr=NULL;	/* Issuer certificate to add to ctxt_id_certs */
    GENI_xml_processing_t *proc = NULL; /* Specialization for version number */
    int ncred = 0;		/* number of creds in rv */
    int i = 0;			/* Scratch (used only in fail:)  */

    if ( doc && !(root = xmlDocGetRootElement(doc)) ) 
	goto fail;

    /* Get the issuer keyid */
    if ( !get_keyid_from_keyinfo(doc, keyid)) 
	goto fail;
    sha1_to_text(keyid, text_keyid);
    /* get the various nodes of interest */
    if ( !(node = xmlSecFindNode(root, (xmlChar *) GENI_credential, NULL)))
	goto fail;
    if ( !(expires = get_direct_child(node, (xmlChar *) GENI_expires)))
	goto fail;
    if ( !check_GENI_expires(get_element_content(expires), NULL))
	goto fail;

    if ( !(rt0 = get_direct_child(node, (xmlChar *) GENI_rt0))) {
	if ( !(rt0 = get_direct_child(node, (xmlChar *) GENI_abac))) 
	    goto fail;
	if ( !(rt0 = get_direct_child(rt0, (xmlChar *) GENI_rt0))) 
	    goto fail;
    }

    /* There are two places to look for a version.  The credential node and the
     * rt0 node that is a child of the credential node.  The version element is
     * only under the credential in the misdefined GENI abac v1.0. */
    if ( !(version = get_direct_child(node, (xmlChar *) GENI_version))) {
	if ( !(version = get_direct_child(rt0, (xmlChar *) GENI_version))) 
	    goto fail;
    }


    /* Pick parsing specialization based on the version.  If we can't resolve a
     * processor, this is an unknown version. */
    if ( !(proc = get_xml_processing((char *) get_element_content(version))))
	goto fail;

    /* read the RT0 and return it */
    if ( !(rv = proc->xml_to_rt0(rt0, km)) ) goto fail;
    ncred=1;

    /* extract issuer pem and insert */
    issuer_ptr=get_issuer(doc);
    if( issuer_ptr && 
	    abac_verifier_load_id_chars(ctxt_id_certs, (char *)issuer_ptr, 
		NULL) != ABAC_CERT_SUCCESS) {
        goto fail;
    }

    return rv;
fail:
    if ( rv ) {
	for (i = 0; i < ncred; i++) 
	    if (rv[i]) free(rv[i]);
	free(rv);
    }
    return NULL;
}

/* Check and parse a GENI credential.  Return the new RT0 rules in a
 * NULL-terminated array of strings.  If the signature or parsing fails, return
 * NULL. Demultiplexed to parse_privilege or parse_abac to do the parsing and
 * uses check_signature to confirm the sig. If ctxt_id_certs is a list of
 * identities known to a context.  If it is not NULL and identity certs appear
 * (as they do in GENI credentials) add them to that list, which adds them to
 * the ABAC context. */
char **read_credential(abac_list_t *ctxt_id_certs, char *infile, 
	char **in_xml, abac_keyid_map_t *km) {
    xmlChar **xml = (xmlChar **) in_xml;    /* Cast */
    xmlDocPtr doc = xmlParseFile(infile);   /* Parse the document */
    xmlNodePtr node = NULL;		    /* XML scratch node */
    xmlChar *text = NULL;		    /* Text of the type field */
    xmlChar **rv = NULL;		    /* return value from parse_* */

    if ( !check_signature(doc) ) 
	goto fail;
    /* Parse out the type field */
    if ( !(node = xmlDocGetRootElement(doc)) ) 
	goto fail;
    if ( !(node = xmlSecFindNode(node, (xmlChar *) GENI_credential, NULL)))
	goto fail;
    if ( !(node = xmlSecFindNode(node, (xmlChar *) GENI_type, NULL)))
	goto fail;

    if ( !(text = get_element_content(node)) ) 
	goto fail;

    /* Demux on type */
    if ( !strcmp((char *) text, "privilege")) {
	rv = parse_privilege(doc, ctxt_id_certs, km);
    } else if ( !strcmp((char *) text, "abac")) {
	rv = parse_abac(doc, ctxt_id_certs, km);
    } else { 
	goto fail;
    }
    int len=0;
    xmlDocDumpMemoryEnc(doc, xml, &len, "UTF-8");
    if(len == 0)
       goto fail;

fail:
    xmlFreeDoc(doc);
    return (char **) rv;
}


/* format for dates in <expires> */
char *strftime_fmt = "%FT%TZ";
#define EXPIRESLEN 20

/* Return a copy of str with > < and & replaced by &gt; &lt; and &amp; for
 * embedding in XML.  Caller is responsible for deallocating the return value
 * using xmlFree().
 */
static xmlChar *minimal_xml_escaping(xmlChar *str) {
    /* A quickie translation table with the character to escape, the output
     * string and the length of the output in it. The table is initialized with
     * the three translations we want. */
    static struct esc {
	xmlChar c;
	xmlChar *esc;
	int l;
    } escapes[] = {
	{ (xmlChar) '<', (xmlChar *) "&lt;", 4 }, 
	{ (xmlChar) '>', (xmlChar *) "&gt;", 4},
	{ (xmlChar) '&', (xmlChar *) "&amp;", 5},
	{ (xmlChar) '\0', NULL, 0 },
    };

    xmlChar *rv = NULL;	    /* Return value */
    xmlChar *p = NULL;	    /* Scratch (walking str) */
    xmlChar *q = NULL;	    /* Scratch (walking rv) */
    struct esc *e = NULL;   /* Scratch for walking escapes */
    int len = 0;	    /* Length of rv */

    /* Walk str and calculate how long the escaped version is */
    for ( p = str; *p ; p++) {
	int foundit = 0;
	for ( e = escapes; !foundit && e->c ; e++ ) {
	    if ( *p == e->c ) {
		len += e->l;
		foundit = 1;
	    }
	}
	if ( !foundit ) len++;
    }
    /* Allocate the new string */
    q = rv = (xmlChar *) xmlMalloc(len+1);
    /* copy str to rv, escaping when necessary */
    for ( p = str; *p ; p++) {
	int foundit = 0;
	for ( e = escapes; !foundit && e->c ; e++ ) {
	    if ( *p == e->c ) {
		strncpy((char *) q, (char *) e->esc, e->l);
		q += e->l;
		foundit = 1;
	    }
	}
	if ( !foundit ) *q++ = *p;
    }
    /* terminate rv */
    *q = '\0';
    return rv;
}

xmlChar *encode_rt0_xml_v10(abac_attribute_t *a) {
    return minimal_xml_escaping((xmlChar *)abac_attribute_role_string(a));
}

/* Template to create a head element in structured XML for RT0 (v1.1).  All
 * heads are a single role element. There aer versions with and without
 * mnemonics. */
static char *head_template = 
"<head>\n"
"   <ABACprincipal><keyid>%s</keyid></ABACprincipal>\n"
"   <role>%s</role>\n"
"</head>\n";

static char *head_template_w_mnemonic = 
"<head>\n"
"   <ABACprincipal><keyid>%s</keyid><mnemonic>%s</mnemonic></ABACprincipal>\n"
"   <role>%s</role>\n"
"</head>\n";

/* Templates to create a tail in structured XML  based on how many of
 * principal, role, and linking role are present. There are variants with
 * and without mnomonics. */
static char *tail_template[] = {
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid></ABACprincipal>\n"
"</tail>\n",
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid></ABACprincipal>\n"
"   <role>%s</role>\n"
"</tail>\n",
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid></ABACprincipal>\n"
"   <role>%s</role>\n"
"   <linking_role>%s</linking_role>\n"
"</tail>\n",
};
static char *tail_template_w_mnemonic[] = {
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid><mnemonic>%s</mnemonic></ABACprincipal>\n"
"</tail>\n",
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid><mnemonic>%s</mnemonic></ABACprincipal>\n"
"   <role>%s</role>\n"
"</tail>\n",
"<tail>\n"
"   <ABACprincipal><keyid>%s</keyid><mnemonic>%s</mnemonic></ABACprincipal>\n"
"   <role>%s</role>\n"
"   <linking_role>%s</linking_role>\n"
"</tail>\n",
};

/* These three functions are variations on the theme of printing out the XML
 * representation of tail roles in the XML credential.  They're separated out
 * to make reading encode_rt0_xml_v11 a little easier.  Each prints the role
 * (r) into the string tmp, adding mnemonic annotations from km if present.  Sz
 * is the number of bytes remaining in the overall string, and is always
 * smaller than the size of tmp.  The only differences are which templates are
 * used and how many strings are inserted.  The length of the generated string
 * is returned.
 */
static int encode_principal_role(abac_role_t *r, char *tmp,  int sz,
	abac_keyid_map_t *km) {
    xmlChar *p = minimal_xml_escaping((xmlChar *) abac_role_principal(r));
    char *nick = NULL;
    int ts = 0;

    if ( km ) 
	nick = abac_keyid_map_key_to_nickname(km, (char *)p);

    if (nick) {
	ts = snprintf(tmp, sz, tail_template_w_mnemonic[0], p, nick);
	free(nick);
	nick = NULL;
    }
    else {
	ts = snprintf(tmp, sz, tail_template[0], p);
    }
    free(p);
    return ts;
}

static int encode_single_role(abac_role_t *r, char *tmp,  int sz,
	abac_keyid_map_t *km) {
    xmlChar *p = minimal_xml_escaping((xmlChar*)abac_role_principal(r));
    xmlChar *ro = minimal_xml_escaping((xmlChar *)abac_role_role_name(r));
    char *nick = NULL;
    int ts = 0;

    if ( km ) 
	nick = abac_keyid_map_key_to_nickname(km, (char *)p);

    if (nick) {
	ts = snprintf(tmp, sz, tail_template_w_mnemonic[0], 
		p, nick, ro);
	free(nick);
	nick = NULL;
    }
    else {
	ts = snprintf(tmp, sz, tail_template[1], p, ro);
    }
    free(p);
    free(ro);
    return ts;
}

static int encode_linking_role(abac_role_t *r, char *tmp,  int sz,
	abac_keyid_map_t *km) {
    xmlChar *p = minimal_xml_escaping((xmlChar *)abac_role_principal(r));
    xmlChar *ro = minimal_xml_escaping((xmlChar*)abac_role_role_name(r));
    xmlChar *li = minimal_xml_escaping((xmlChar*)abac_role_linking_role(r));
    char *nick = NULL;	    
    int ts = 0;

    if ( km ) 
	nick = abac_keyid_map_key_to_nickname(km, (char *) p);

    if (nick) {
	ts = snprintf(tmp, sz, tail_template_w_mnemonic[2], 
		p, nick, ro, li);
	free(nick);
	nick = NULL;
    }
    else {
	ts = snprintf(tmp, sz, tail_template[2], p, ro, li);
    }
    free(p);
    free(ro);
    free(li);
    return ts;
}

/* Convert the given attribute to the RT0 structured XML representation used by
 * version 1.1 credentials.
 */
xmlChar *encode_rt0_xml_v11(abac_attribute_t *a) {
    int htlen = strlen(head_template_w_mnemonic);    /* head template length */
    int ttlen = strlen(tail_template_w_mnemonic[2]); /* length of the longest
							tail template */
    /* Size of the string we'll need - start with a head template and string */
    int sz = strlen(abac_attribute_get_head(a)) + htlen;
    /* Number of tails in the sttribute */
    int ntails = abac_attribute_get_ntails(a);
    char *princ_role[2];    /* Used to split the head role */
    char *copy = abac_xstrdup(abac_attribute_get_head(a)); /* splitting */
    int npr = 2;	    /* Number of parts in the head role */
    abac_keyid_map_t *km = (a) ? abac_attribute_get_keyid_map(a) : NULL;
    char *nick = NULL;	    /* Mnemonic name */
    char *tmp = NULL;	    /* A temporary to build each tail element */
    char *rv = NULL;	    /* The return value */
    int i;		    /* Scratch */

    /* Add the tail lengths to the total length (assume all tails will need the
     * largest template for slop). */
    for ( i = 0 ; i < ntails; i++)
	sz += strlen(abac_attribute_get_tail_n(a, i)) + ttlen;

    /* Get the rv and scratch string.  Since tmp is as long as the whole
     * string, it's big enough for any substring */
    if ( !(rv = (char *) xmlMalloc(sz)) ) goto fail;
    if ( !(tmp = (char *) xmlMalloc(sz)) ) goto fail;

    abac_split(copy, ".", princ_role, &npr);
    if ( npr != 2) 
	goto fail;

    if ( km ) 
	nick = abac_keyid_map_key_to_nickname(km, princ_role[0]);
    /* Put the head in */
    if ( nick ) {
	sz -= snprintf(rv, sz, head_template_w_mnemonic, princ_role[0], 
		nick, princ_role[1]);
	free(nick);
	nick = NULL;
    } else {
	sz -= snprintf(rv, sz, head_template, princ_role[0], princ_role[1]);
    }

    /* done with the copy */
    free(copy);

    char *tail;
    for ( i = 0 ; i < ntails; i++) {
	/* Make a role for each tail and use those functions to write out the
	 * structures for the different kinds of role. */
        tail=abac_attribute_get_tail_n(a,i);
	abac_role_t *r = abac_role_from_string(tail);
	int ts = -1;

	if ( !r )
	    goto fail;

	if ( abac_role_is_principal(r))
	    ts = encode_principal_role(r, tmp, sz, km);
	else if (abac_role_is_role(r))
	    ts = encode_single_role(r, tmp, sz, km);
	else if (abac_role_is_linking(r))
	    ts = encode_linking_role(r, tmp, sz, km);

	abac_role_free(r);
	if ( ts < 0 ) 
	    goto fail;

	strncat(rv, tmp, sz);
	sz -= ts;
    }
    free(tmp);
    return (xmlChar *) rv;

fail:
    if (rv ) free(rv);
    if (tmp) free(tmp);
    return NULL;
}

/* Make an new GENI abac credential with the rt0 rule that expires secs from
 * now.  cert is the PEM encoded X.509 of the issuer's certificate as a string.
 * certlen is the length of cert.  Returns the XML. Caller is responsible for
 * freeing it. */
char *make_credential(abac_attribute_t *attr, int secs, char *in_cert, 
	int in_certlen) {
    xmlSecByte *cert = (xmlSecByte *) in_cert; /* Cast of certificate */
    xmlSecSize certlen = (xmlSecSize) in_certlen; /* Cast of len */
    xmlDocPtr doc = NULL;	/* parsed XML document */
    xmlNodePtr root = NULL;	/* Root of the document */
    xmlNodePtr signNode = NULL;	/* <Signature> element */
    xmlSecDSigCtxPtr dsigCtx = NULL;  /* Signing context */
    xmlChar *rt0_xml = NULL;	/* attr's RT0 as xml */
    xmlChar *rv = NULL;		/* return value */
    time_t exp;			/* expriation time (seconds since epoch) */
    struct tm exp_tm;		/* expiration for formatting */
    char estr[EXPIRESLEN+1];	/* String with formatted expiration */
    char *temp = NULL;		/* populated XML template */
    int len = 0;		/* length of the populated template (temp) */

    GENI_xml_processing_t *proc = get_xml_processing(
	    abac_attribute_get_output_format(attr));

    if ( !proc ) goto fail;
    if ( !(rt0_xml = proc->rt0_to_xml(attr))) goto fail;

    /* Calculate the length of the populated template and allocate it */
    len = strlen((char *) proc->out_template)+EXPIRESLEN+
	strlen((char *) rt0_xml)+1;

    if ( !(temp = malloc(len)) )
	goto fail;

    /* format expiration */
    time(&exp);
    exp += secs;
    gmtime_r(&exp, &exp_tm);

    if (strftime(estr, EXPIRESLEN+1, strftime_fmt, &exp_tm) == 0 ) 
	goto fail;

    /* Populate template with  expiration and escaped rt0 */
    snprintf(temp, len, proc->out_template, estr, (char *) rt0_xml);

    /* parse the populated template */
    if ( !(doc = xmlParseMemory(temp, len))) 
	goto fail;

    if (!(root = xmlDocGetRootElement(doc)) )
	goto fail;

    /* Find the signature element for the Signing call */
    signNode = xmlSecFindNode(root, xmlSecNodeSignature, xmlSecDSigNs);

    /* Create the context */
    if ( !(dsigCtx = xmlSecDSigCtxCreate(NULL))) 
	goto fail;

    /* Assign the key (a PEM key) */
    if (!(dsigCtx->signKey = xmlSecCryptoAppKeyLoadMemory(cert, certlen,
		    xmlSecKeyDataFormatPem, NULL, NULL, NULL)) )
	goto fail;

    /* Load the certificate */
    if ( xmlSecCryptoAppKeyCertLoadMemory(dsigCtx->signKey, cert, certlen,
		xmlSecKeyDataFormatPem) < 0)
	goto fail;

    /* Sign it */
    if ( xmlSecDSigCtxSign(dsigCtx, signNode) < 0)
	goto fail;

    /* Store the signed credential to rv */
    xmlDocDumpMemoryEnc(doc, &rv, &len, "UTF-8");
fail:
    /* clean up */
    if (dsigCtx) 
	xmlSecDSigCtxDestroy(dsigCtx);
    if ( doc) xmlFreeDoc(doc);
    if (rt0_xml) xmlFree(rt0_xml);
    if ( temp) free(temp);
    return (char *) rv;
}


/******** helper functions used by libabac **********************/

/* Function to disable libXML2's debugging */
static void _nullGenericErrorFunc(void* ctxt, const char* msg, ...) { return; }

/* Straight off http://www.aleksey.com/xmlsec/api/xmlsec-examples.html .
 * Voodoo.  But call it. */
int init_xmlsec() {
    /* Init xmlsec library */
    if(xmlSecInit() < 0) {
        fprintf(stderr, "Error: xmlsec initialization failed.\n");
        return(-1);
    }

    /* Check loaded library version */
    if(xmlSecCheckVersion() != 1) {
        fprintf(stderr,
		"Error: loaded xmlsec library version is not compatible.\n");
        return(-1);
    }

    /* Load default crypto engine if we are supporting dynamic
     * loading for xmlsec-crypto libraries. Use the crypto library
     * name ("openssl", "nss", etc.) to load corresponding 
     * xmlsec-crypto library.
     */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
    if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
        fprintf(stderr, "Error: unable to load default xmlsec-crypto library. "
		"Make sure\n" 
		"that you have it installed and check shared libraries path\n"
		"(LD_LIBRARY_PATH) envornment variable.\n");
        return(-1);     
    }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

    /* Init crypto library */
    if(xmlSecCryptoAppInit(NULL) < 0) {
        fprintf(stderr, "Error: crypto initialization failed.\n");
        return(-1);
    }

    /* Init xmlsec-crypto library */
    if(xmlSecCryptoInit() < 0) {
        fprintf(stderr, "Error: xmlsec-crypto initialization failed.\n");
        return(-1);
    }
    /* Turn off the built in debugging */
    xmlThrDefSetGenericErrorFunc(NULL, _nullGenericErrorFunc);
    xmlSetGenericErrorFunc(NULL, _nullGenericErrorFunc);

    return 0;
}

int deinit_xmlsec() {
  /* no op for now */
    return 0;
}


/* parse the xml blob and extract keyid,
   caller should be freeing this if not 
   needed anymore */ 
char *get_keyid_from_xml(char *xml) {
    xmlDocPtr doc=xmlParseMemory(xml,strlen(xml));
    xmlChar keyid[SHA_DIGEST_LENGTH];   /* Issuer key SHA1 */
    xmlChar text_keyid[2*SHA_DIGEST_LENGTH+1];/* Issuer keyid as text */
    char *ret=NULL;

    /* Get the issuer keyid */
    if ( !get_keyid_from_keyinfo(doc, keyid))
        goto fail;
    sha1_to_text(keyid, text_keyid);
    ret=strdup((char *)text_keyid);
fail:
    xmlFreeDoc(doc);
    return ret;
}

/* parse xml and get the expected expiration time and returns 
 * (expiration time-current time)
 */
long get_validity_from_xml(char *xml) {
    xmlDocPtr doc=xmlParseMemory(xml,strlen(xml));
    xmlNodePtr node = NULL;                 /* XML scratch node */
    xmlNodePtr expires = NULL;  /* XML expires node */
    struct tm tv;   /* Parsed expires field */
    time_t now;     /* Now in seconds since the epoch */
    time_t exp;     /* expires in seconds since the epoch */
    long dtime=0;

    if ( !(node = xmlDocGetRootElement(doc)) )
        goto fail;

    if ( !(expires = xmlSecFindNode(node, (xmlChar *) GENI_expires, NULL)))
        goto fail;

    xmlChar *etime=get_element_content(expires);
    time(&now);

    if ( !parse_ISO_time(etime, &tv)) return 0;
    exp = timegm(&tv);
    dtime=difftime(exp, now);

fail:
    xmlFreeDoc(doc);
    return dtime;
}

/* parse xml structure and extract the attribute rules */
char **get_rt0_from_xml(abac_list_t *ctxt_id_certs,char *xml, abac_keyid_map_t *km) {
    xmlDocPtr doc=xmlParseMemory(xml,strlen(xml));
    xmlNodePtr node = NULL;                 /* XML scratch node */
    xmlChar *text = NULL;                   /* Text of the type field */
    xmlChar **rv = NULL;                    /* return value from parse_* */
    
    if ( !check_signature(doc) )
        goto fail;
    /* Parse out the type field */
    if ( !(node = xmlDocGetRootElement(doc)) )
        goto fail;
    if ( !(node = xmlSecFindNode(node, (xmlChar *) GENI_credential, NULL)))
        goto fail;
    if ( !(node = xmlSecFindNode(node, (xmlChar *) GENI_type, NULL)))
        goto fail;

    if ( !(text = get_element_content(node)) )
        goto fail;

    /* Demux on type */
    if ( !strcmp((char *) text, "privilege")) {
        rv = parse_privilege(doc, ctxt_id_certs, km);
    } else if ( !strcmp((char *) text, "abac")) {
        rv = parse_abac(doc, ctxt_id_certs, km);
    } else {
        goto fail;
    }
fail:
    xmlFreeDoc(doc);
    return (char **)rv;
}


