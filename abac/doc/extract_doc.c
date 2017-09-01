/***
   extract_doc.c,

   This program extracts API doc from abac.hh 
   This program assume abac.hh is local
  
rules:
1) Enclosed lines within slashes with triple stars(/***,***SLASH/) need 
to be extracted
2) line start with 'f', add a new line
3) Enclosed lines with tripple stars and 2 i's (/*ii**. **ii*SLASH/)
are internal functions, no need to put in API file
   
   cc extract_doc.c

***/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *sstr="/***";
char *estr="***/";
char *prestr="/***PRE";
char *poststr="/***POST";

void extract_p(FILE *in, FILE* out, char *match)
{
    rewind(in);
    int yes=0;
    char *line=NULL;
    size_t num=0;
    int n=strlen(match);
    int nn=strlen(estr);
    while(getline(&line,&num,in) != -1) {
       if(!yes) {
          if(strncmp(match,line,n)==0) {
            yes=1;
            free(line); line=NULL;
            continue;
            } else {
                free(line);
                line=NULL;
          }
          }else {
              if(strncmp(estr,line, nn)==0) {
                yes=0;
                free(line);
                line=NULL;
                break;
                } else {
                   fprintf(out,"%s",line);
                   free(line);
                   line=NULL;
              }
       }
    }
}

void extract(FILE* in, FILE* out, FILE *cout)
{
    int yes=0;
    char *line=NULL;
    size_t num=0;
    int n=strlen(sstr);
    int nn=strlen(estr);
    while(getline(&line,&num,in) != -1) {
       if(!yes) {
          if(strncmp(sstr,line, n)==0) {
            yes=1;
            free(line); line=NULL;
            continue;
            } else {
                fprintf(cout,"%s",line);
                free(line);
                line=NULL;
          }
          }else {
              if(strncmp(estr,line, nn)==0) {
                yes=0;
                free(line);
                line=NULL;
                continue;
                } else {
                   if(line[0]=='f') {
                       line[0]=' ';
                       fprintf(out,"\n");
                   }
                   if(line[0]=='A') fprintf(out,"\n");
                   fprintf(out,"%s",line);
                   free(line);
                   line=NULL;
              }
       }
    }
}

int main()
{
   char *selfname="extract_doc.c";
   char *filename="abac.hh";
   char *docname="API";
   char *codename="ABAC.hh";

   FILE *dfp=fopen(selfname,"r");
   FILE *fp=fopen(filename,"r");
   FILE *ofp=fopen(docname,"w");
   FILE *cfp=fopen(codename,"w");
   if(fp && dfp && ofp && cfp ) {
       extract_p(dfp,ofp,prestr);
       extract(fp,ofp,cfp);
       extract_p(dfp,ofp,poststr);
       fclose(fp);
       fclose(dfp);
       fclose(ofp);
       fclose(cfp);
   }
   return 0;
}

/***PRE
C++ API

(see bottom for notes on C, Perl, Python and Java)

ABAC::abac_chunk_t
   Structure, represents a blob of memory
   used to load/return Identity credentials and Attribute certificates
     -unsigned char *data
     -int len
***/


/***POST
C API

The C API is nearly identical to the C++ API. Due to lack of namespaces,
all function names are preceeded by abac_. Furthermore, the parameter
representing the object must be passed explicitly. Each of the C++ calls
are appended with a matching C routine call. The C function declaration 
can be found in abac.h

Examples:

    C++:    head.role_name()
    C:      abac_role_name(head)
    or 
    C++:    ctxt.load_attribute_file("test_attr.der")
    C:      abac_context_load_attribute_file(ctxt, "test_attr.der")

Instead of copy constructors, the C API uses _dup.  Therefore,
to copy a role use abac_role_dup(m_role), 
to copy a context use abac_context_dup(m_ctxt),
to copy a ID use abac_id_dup(m_id) 
and to copy an attribute use abac_attribute_dup(m_attr)

abac_context_query() and abac_context_credentials() return
NULL-terminated arrays of Credential objects (abac_credential_t * in C).
When you are done with them, you must free the whole array at once using
abac_context_credentials_free().

PERL, PYTHON AND JAVA API

The Perl, Python and Java APIs are even more similar to the C++ API. The main
changes are the use of native types instead of C/C++ types.

    - native strings instead of char *

    Java:
        - String instead of char * 
        - Context::query returns a vector of Credentials:
            credentials = ctxt.query(role, principal)
            success if credentials' size is > 0

    Perl:
        - arrayref instead of vector
        - string instead of chunk_t
        - Context::query returns a list of two elements:
            my ($success, $credentials) = $ctxt->query($role, $principal)
            $success is a boolean
            $credentials is an arrayref of Credential objects

    Python:
        - tuple instead of vector
        - bytearray instead of chunk_t (>= 2.6)
        - string instead of chunk_t (< 2.6)
        - Context::query returns a tuple with two elements:
            (success, credentials) = ctxt.query(role, principal)
            success is a boolean
            credentials is a tuple of Credential objects

***/
