/* abac_xml.h */
#ifndef __ABAC_XML_H__
#define __ABAC_XML_H__

extern void read_cert(char *filename, char **buf, int *len);
extern char *make_credential(abac_attribute_t* rt0, int secs, char* cert, 
	int certlen);
extern void fatal(const char *str);

extern int init_xmlsec();
extern int deinit_xmlsec();
extern char **read_credential(abac_list_t *id_certs, char *infile, char **xml,
	abac_keyid_map_t *);

extern char **get_rt0_from_xml(abac_list_t *id_certs,char *xml,
	abac_keyid_map_t *);
extern char *get_keyid_from_xml(char *xml);
extern long get_validity_from_xml(char *xml);

#endif /* __ABAC_XML_H__ */


