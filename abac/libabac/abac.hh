#ifndef __ABAC_HH__
#define __ABAC_HH__

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace ABAC {
    extern "C" {
        #include "abac.h"
    }

    class Attribute;
    class ID;
    class Role;
    class Credential;

/***
ABAC::Context
    An ABAC Context
***/
    class Context {
        public:
/***
f  Context()
     default constructor
     (C:abac_context_new)
f  Context(const Context &)
     copy constructor, used for cloning the context
     (C:abac_context_dup)
f  ~Context()
     default destructor
     (C:abac_context_free)
***/
            Context() { m_ctx = abac_context_new(); }
            Context(const Context &context) { m_ctx = abac_context_dup(context.m_ctx); }
            ~Context() { abac_context_free(m_ctx); }

/***
f  int load_id_file(char *)
     load identity certificate from an id file
     (C:abac_context_load_id_file)
f  int load_id_chunk(abac_chunk_t)
     load id certificate from an chunk
     (C:abac_context_load_id_chunk)
f  int load_id_id(ID&)
     load id certificate from an existing ID
     (C:abac_context_load_id_id)
f  int load_attribute_file(char *)
     load attribute certificate from an id file. 
     (C:abac_context_load_attribute_file)
f  int load_attribute_chunk(abac_chunk_t)
     load attribute certificate from an chunk
     (C:abac_context_load_attribute_chunk)
f  returns : 
        ABAC_CERT_SUCCESS   successfully loaded
        ABAC_CERT_INVALID   invalid certificate (or file not found)
        ABAC_CERT_BAD_SIG   invalid signature
***/
            int load_id_file(char *filename) { return abac_context_load_id_file(m_ctx, filename); }
            int load_id_chunk(abac_chunk_t cert) { return abac_context_load_id_chunk(m_ctx, cert); }
            int load_id_id(ID& id); /* defined later in the class */
            int load_attribute_file(char *filename) { return abac_context_load_attribute_file(m_ctx, filename); }
            int load_attribute_chunk(abac_chunk_t cert) { return abac_context_load_attribute_chunk(m_ctx, cert); }

/***
f  std::vector<Credential> query(char *, char *, bool &)
     run the query:
        role <-?- principal
     returns true/false in success
     returns a proof upon success, partial proof on failure
     (C:abac_context_query)
     (C::abac_free_credentials_free)
***/

    /* abac query, returns a vector of credentials on success, NULL on fail */
    std::vector<Credential> query(char *role, char *principal, bool &success);
/***
f  std::vector<Credential> credentials(bool &)
     returns a vector of all the credentials loaded in the context
     (C:abac_context_credentials)
     (C::abac_context_credentials_free)
***/
    std::vector<Credential> credentials();
/***
f  void load_directory(char *)
     load a directory full of certificates:
f       first: ${path}/NAME_ID.{der,pem} as identity certificates
               implicitly looking for ${path}/NAME_private.{der,pem} as
               the private key file
        last: ${path}/NAME_attr.xml as attribute certificates
      (C:abac_context_load_directory)
***/
            void load_directory(char *path) { abac_context_load_directory(m_ctx, path); }

/***
f  void set_nickname(char *key, char *nick)
     Set the nickname (value printed) for keyid.  The substitution is made 
     in Role::short_string(Context) and when bake(Context) is called on a new
     attribute.
     (C:abac_context_set_nickname)
***/
	void set_nickname(char *key, char *nick) {
	    abac_context_set_nickname(m_ctx, key, nick);
	}
        private:
            abac_context_t *m_ctx;
	friend class Role;
        friend class ID;
	friend class Attribute;
    };

/***
ABAC::Role
   A Role, most calls are rarely used outside the library 
***/
    class Role {
        public:
/***
f  Role()
     default constructor, do not use, for swig only
f  Role(abac_role_t*)
     copy constructor, used for cloning an Role
     (C:abac_role_dup)
f  Role(char *)
     instantiate a role from a string
     (C:abac_role_from_string)
f  Role(const Role &)
     copy constructor, used for cloning an Role
     (C:abac_role_dup)
f  ~Role()
     default destructor
     (C:abac_role_free)
***/
            Role() : m_role(NULL) { } // do not use: here for swig
            Role(abac_role_t *role) { m_role = abac_role_dup(role); }
            Role(char *role_name) { m_role = abac_role_from_string(role_name); }
            Role(const Role &role) { m_role = abac_role_dup(role.m_role); }
            ~Role() { abac_role_free(m_role); }
/***
f  bool is_principal()
     (C:abac_role_is_principal)
f  bool is_role()
     (C:abac_role_is_role)
f  bool is_linking()
     (C:abac_role_is_linking)
     indicates the type of role encoded
***/
            bool is_principal() const { return abac_role_is_principal(m_role); }
            bool is_role() const { return abac_role_is_role(m_role); }
            bool is_linking() const { return abac_role_is_linking(m_role); }

/***
f  char* string()
     string representation of the role
     (C:abac_role_string)
***/
            char *string() const { return abac_role_string(m_role); }
/***
f  char* short_string()
     string representation of the role
     (C:abac_role_short_string)
***/
            char *short_string(Context& c) const { 
		return abac_role_short_string(m_role, c.m_ctx);
	    }
/***
f  char* linked_role()
     the linked role of a linking role
     i.e., A.r1.r2, linked_role() returns A.r1
     (C:abac_role_linked_role)
f  char* role_name()
     the role name of any role (the part after the last dot)
     (C:abac_role_role_name)
f  char* principal()
     the principal part of any role
     (C:abac_role_principal)
***/
            char *linked_role() const { return abac_role_linked_role(m_role); }
            char *role_name() const { return abac_role_role_name(m_role); }
            char *principal() const { return abac_role_principal(m_role); }

        private:
            abac_role_t *m_role;
    };

/***
ABAC::Credential
   This is never instantiated directly. These will only ever be
   returned as a result of calls to Context::query or
   Context::credentials.
***/
    class Credential {
        public:
/***
f  Credential()
     default constructor, do not use, for swig only
f  Credential(abac_credential_t*)
     copy constructor, used for cloning a credential
     (C:abac_credential_head)
     (C:abac_credential_tail)
     (C:abac_credential_dup)
f  Credential(const Credential&)
     copy constructor, used for cloning a credential
     (C:abac_credential_head)
     (C:abac_credential_tail)
     (C:abac_credential_dup)
f  ~Credential()
     default destructor
     (C:abac_credential_free)
***/
            Credential() : m_cred(NULL) { } // do not use: here for swig
            Credential(abac_credential_t *cred) :
                m_head(abac_credential_head(cred)),
                m_tail(abac_credential_tail(cred)),
                m_cred(abac_credential_dup(cred))
                    { }
            Credential(const Credential &cred) :
                m_head(cred.m_head),
                m_tail(cred.m_tail),
                m_cred(abac_credential_dup(cred.m_cred))
                    { }
            ~Credential() { abac_credential_free(m_cred); }
/***
f  Role &head()
     returns the head of the credential
f  Role &tail()
     returns the tail of the credential
***/
            const Role &head() { return m_head; }
            const Role &tail() { return m_tail; }
/***
f  abac_chunk_t attribute_cert()
     returns the attribute certificate in chunk, suitable for
     transmission over the network or storage in a file
     (C:abac_credential_attribute_cert)
f  abac_chunk_t issuer_cert()
     returns the issuer certificate in chunk, again suitable for
     network transmission or file storage
     (C:abac_credential_issuer_cert)
***/
            abac_chunk_t attribute_cert() { return abac_credential_attribute_cert(m_cred); }
            abac_chunk_t issuer_cert() { return abac_credential_issuer_cert(m_cred); }
        
        private:
            abac_credential_t *m_cred;
            Role m_head, m_tail;
    };


/***
ABAC::ID
   An ID holds a principal credential. It maybe imported from an existing
   ID credential via external files, constructed from a streaming chunk,
   or instantiated on the fly
***/
    class ID {
        public:
/***
f  ID()
     default constructor, do not use, for swig only
f  ID(const ID &)
     copy constructor, used for cloning an ID
     (C:abac_id_dup)
f  ~ID()
     default destructor
     (C:abac_id_free)
***/
            ID() : m_id(NULL) { } // do not use: required by swig
            ID(const ID &id) { m_id = abac_id_dup(id.m_id); }
            ~ID() { abac_id_free(m_id); }

/***
f  ID(char *)
     load an ID certificate from a file, will throw an exception
     if the certificate cannot be loaded
     (C:abac_id_from_file)
***/
            ID(char *filename) : m_id(NULL) {
                m_id = abac_id_from_file(filename);
                if (m_id == NULL)
                    throw std::invalid_argument("Could not load ID cert");
            }

/***
f  ID_chunk(abac_chunk_t chunk)
     create an ID certificate from an certificate chunk, will
     throw an exception if the certificate cannot be loaded
     (C:abac_id_from_chunk)
***/
            ID(abac_chunk_t chunk) : m_id(NULL) {
                m_id = abac_id_from_chunk(chunk);
                if (m_id == NULL)
                    throw std::invalid_argument("Could not load ID certificate with a chunk");
            }
/***
f  ID(char *,int)
     generates a new ID(cert&key) with the supplied CN and validity period
     - CN must be alphanumeric and begin with a letter
     - validity must be at least one second
     will throw an exception if either of the above is violated
     (C:abac_id_generate)
***/
            ID(char *cn, int validity) : m_id(NULL) {
                int ret = abac_id_generate(&m_id, cn, validity);
                if (ret == ABAC_GENERATE_INVALID_CN)
                    throw std::invalid_argument("CN must be alphanumeric and start with a letter");
                if (ret == ABAC_GENERATE_INVALID_VALIDITY)
                    throw std::invalid_argument("Validity must be > 0 days");
            }
/***
f  void load_privkey(char *)
     loads the private key associated with the ID credential,
     will throw an exception if the key cannot be loaded
     (C:abac_id_privkey_from_file)
f  void load_privkey_chunk(abac_chunk_t)
     loads the private key associated with the ID credential,
     will throw an exception if the key cannot be loaded
     (C:abac_id_privkey_from_chunk)
f  int has_privkey()
     check to see if there is a privkey in this ID
     (C:abac_id_has_privkey)
***/
            void load_privkey(char *filename) {
                int ret = abac_id_privkey_from_file(m_id, filename);
                if (ret != ABAC_SUCCESS)
                    throw std::invalid_argument("Could not load private key");
            }
            void load_privkey_chunk(abac_chunk_t chunk) {
                int ret = abac_id_privkey_from_chunk(m_id, chunk);
                if (ret != ABAC_SUCCESS)
                    throw std::invalid_argument("Could not load private key with a chunk");
            }
            int has_privkey() {
                int ret= abac_id_has_privkey(m_id);
                return ret;
            }
/***
f  char *keyid()
     returns the SHA1 keyid of the id cert
     (C:abac_id_keyid)
f  char *cn()
     returns the cn of the id cert
     (C:abac_id_cn)
f  char *cert_filename()
     returns the default libabac filename for the cert. 
     value must be freed by caller.
     (C:abac_id_cert_filename)
***/
            char *keyid() { return abac_id_keyid(m_id); }
            char *cn() { return abac_id_cn(m_id); }
            char *cert_filename() { return abac_id_cert_filename(m_id); }
/***
f  void write_cert(FILE *)
     writes a PEM-encoded certificate to a file handle
     (C:abac_id_write_cert)
f  void write_cert(string &)
     writes a PEM-encoded certificate to a file named in string
f  void write_cert_file(const char *)
     writes a PEM-encoded certificate to a file
f  void write_cert_name(const char *)
     writes a PEM-encoded certificate to a file
     (added to support original libcreddy users)
***/
            void write_cert(FILE *out) { abac_id_write_cert(m_id, out); }
            void write_cert(const std::string &name) {
                FILE *out = fopen(name.c_str(), "a+");
                if (out == NULL)
                    throw std::invalid_argument("Could not open certificate file for writing");
                write_cert(out);
                fclose(out);
            }
            // Simplifies access from swig
            void write_cert_file(const char *n) {
                write_cert(std::string(n));
            }
            void write_cert_name(const char *n) {
                write_cert(std::string(n));
                fprintf(stderr,"ABAC::ID::write_cert_name is deprecated, please use ABAC::ID::write_cert_name\n");
            }
/***
f  char *privkey_filename()
     returns the default libabac filename for the private key. 
     value must be freed by caller.
     (C:abac_id_privkey_filename)
***/
            char *privkey_filename() { return abac_id_privkey_filename(m_id); }
/***
f  void write_privkey(FILE *)
     write the private key to a file handle
     throws a std::logic_error if no private key is loaded
     (C:abac_id_write_privkey)
f  void write_privkey(string &)
     writes a private key to file named in string
f  void write_privkey_file(const char *)
     writes a private key to a file
f  void write_privkey_name(const char *)
     writes a private key to a file
     (added to support original libcreddy users)
***/
            void write_privkey(FILE *out) {
                int ret = abac_id_write_privkey(m_id, out);
                if (ret!=ABAC_SUCCESS) throw std::logic_error("No private key loaded");
            }
            void write_privkey(const std::string &name) {
                FILE *out = fopen(name.c_str(), "a+");
                if (out == NULL)
                    throw std::invalid_argument("Could not open privkey file for writing");
                write_privkey(out);
                fclose(out);
            }
            // Simplifies access from swig
            void write_privkey_file(const char *name) {
                write_privkey(std::string(name));
            }
            void write_privkey_name(const char *name) {
                write_privkey(std::string(name));
                fprintf(stderr,"ABAC::ID::write_privkey_name is deprecated, please use ABAC::ID::write_privkey_file\n");
            }
/***
f  abac_chunk_t cert_chunk()
     returns a DER-encoded binary representation of the X.509 ID cert
     associated with this ID.
     can be passed to libabac's Context::load_id_chunk()
     (C:abac_id_cert_chunk)
f  abac_chunk_t privkey_chunk()
     returns a PEM-encoded binary representation of the private key
     associated with this ID.
     (C:abac_id_privkey_chunk)
***/
            abac_chunk_t cert_chunk() { return abac_id_cert_chunk(m_id); }
            abac_chunk_t privkey_chunk() { return abac_id_privkey_chunk(m_id); }

            friend class Attribute;
            friend class Context;

        private:
            abac_id_t *m_id;
    };

/***
ABAC::Attribute
   This is the attribute representation for the access policy rule
       LHS <- RHS
   The sequence of generation is to
       first, instantiate the object, ie, LHS (head)
       second, adding subject(s) to it, ie, RHS (tail)
       and then baking it.
   Only once it's baked can you access the X.509 cert.
   Once it's been baked you can no longer add subjects to it
***/
    class Attribute {
        public:
/***
f  Attribute()
     default constructor, do not use, for swig only
f  ~Attribute()
     default destructor
     (C:abac_attribute_free)
***/
            Attribute() : m_attr(NULL) { } // do not use: required by swig
            ~Attribute() { abac_attribute_free(m_attr); }

/***
f  Attribute(ID&, char*,int)
     constructor that creates an attribute policy to be signed by the issuer
     with the given role with a specified validity period
     An exception will be thrown if:
       - the issuer has no private key
       - the Head role is invalid
       - the validity period is invalid (must be >= 0 second)
       - The issuer is invalid
     (C:abac_attribute_create)
***/
            Attribute(ID &issuer, char *role, int validity) : m_attr(NULL) {
                int ret = abac_attribute_create(&m_attr, issuer.m_id, role, validity);
                if (ret == ABAC_ATTRIBUTE_ISSUER_NOKEY)
                    throw std::invalid_argument("Issuer has no private key");
                if (ret == ABAC_ATTRIBUTE_INVALID_ROLE)
                    throw std::invalid_argument("Role name must be alphanumeric");
                if (ret == ABAC_ATTRIBUTE_INVALID_VALIDITY)
                    throw std::invalid_argument("Validity must be > 0 days");
                if (ret == ABAC_ATTRIBUTE_INVALID_ISSUER)
                    throw std::invalid_argument("Issuer's validity expired");
            }


/***
f  bool principal(char *keyid) 
     {keyid}
     validate the principal and insert into the attribute
     throw a std::logic_error if the cert's been baked and keyid bad
     (C:abac_attribute_principal)
f bool role(char *keyid, char *role)
     {keyid.role}
     validate the principal and role and insert into the attribute
     throw a std::logic_error if the cert's been baked and keyid bad
     (C:abac_attribute_role)
f bool linking_role(char *keyid, char *role, char *linked)
     {keyid.linked.role}
     validate the role and linking role and insert into the attribute
     throw a std::logic_error if the cert's been baked and keyid bad
     (C:abac_attribute_linking_role)
***/
            bool principal(char *keyid) {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_principal(m_attr, keyid);
            }
            bool role(char *keyid, char *role) {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_role(m_attr, keyid, role);
            }
            bool linking_role(char *keyid, char *role, char *linked) {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_linking_role(m_attr, keyid, role, linked);
            }
/***
f  bool bake()
     Generate the cert. Call this after you've added subjects to your cert.
     This returns false if there are no subjects
     This will throw an exception if the cert's already been baked.
     (C:abac_attribute_bake)
***/
            bool bake() {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_bake(m_attr);
            }

/***
f  bool bake(Context c)
     Generate the cert. Call this after you've added subjects to your cert.
     This returns false if there are no subjects
     This will throw an exception if the cert's already been baked.
     This version annotated the baked credential with any mnemonic names in the
     context.
     (C:abac_attribute_bake_context)
***/
            bool bake(Context& c) {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_bake_context(m_attr, c.m_ctx);
            }

/***
f  bool baked()
     returns true iff the certificate has been baked.
     (C:abac_attribute_baked)
***/
            bool baked() { return abac_attribute_baked(m_attr); }

/***
f  set_output_format(char *fmt)
     {fmt}
     Set the attribute's output format.  Valid choices are GENIv1.0 and
     GENIV1.1.  Default is GENIv1.1.
***/
	    void set_output_format(char *fmt) {
		abac_attribute_set_output_format(m_attr, fmt);
	    }

/***
f  get_output_format(char *fmt)
     Get the attribute's output format.  Do not delete the string/
***/
	    char *get_output_format() {
		return abac_attribute_get_output_format(m_attr);
	    }

/***
f  void write(FILE *)
     write an attribute certificate in XML to an open file handle
     Throws an exception if the certificate isn't baked
     (C:abac_attribute_write)
f  void write(const string&)
     write an attribute certificate in XML to file named in string
f  void write_file(const char *)
     write an attribute certificate in XML to file
f  void write_name(const char *)
     write an attribute certificate in XML to file
     (added to support original libcreddy users)
***/
            void write(FILE *out) {
                int ret = abac_attribute_write(m_attr, out);
                if (ret!=ABAC_SUCCESS) throw std::logic_error("Cert is not baked");
            }
            void write(const std::string &name) {
                FILE *out = fopen(name.c_str(), "w");
                if (out == NULL)
                    throw std::invalid_argument("Could not open certificate file for writing");
                write(out);
                fclose(out);
            }
            void write_file(const char *name) {
                int ret = abac_attribute_write_file(m_attr, name);
                if (ret!=ABAC_SUCCESS) throw std::logic_error("Cert is not baked");
            }
            void write_name(const char *name) {
                write_file(name);
                fprintf(stderr,"ABAC::Attribute::write_name is deprecated, please use ABAC::Attribute::write_name\n");
            }
/***
f  abac_chunk_t cert_chunk()
     returns a XML structure of the attribute certificate in a abac_chunk_t
     Throws an exception if the certificate isn't baked
     the chunk can be passed to libabac's Context::load_attribute_chunk()
     (C:abac_attribute_cert_chunk)
***/
            abac_chunk_t cert_chunk() {
                abac_chunk_t ret=abac_attribute_cert_chunk(m_attr);
                if(ret.len == 0)
                    throw std::logic_error("Cert is not baked");
                return ret;
            }

        private:
            abac_attribute_t *m_attr;
    };

    int Context::load_id_id(ID& id)
    { return abac_context_load_id_id(m_ctx, id.m_id); }

    /* abac query, returns a vector of credentials on success, NULL on fail */
    inline std::vector<Credential> Context::query(char *role, char *principal,
	    bool &success) {
	std::vector<Credential> credentials = std::vector<Credential>();
	abac_credential_t **creds;
	int i, success_int;
	creds = abac_context_query(m_ctx, role, principal, &success_int);
	success = success_int;

	for (i = 0; creds[i] != NULL; ++i)
	    credentials.push_back(Credential(creds[i]));

	abac_context_credentials_free(creds);
	return credentials;
    }

    inline std::vector<Credential> Context::credentials() {
	std::vector<Credential> credentials = std::vector<Credential>();
	abac_credential_t **creds;
	int i;

	creds = abac_context_credentials(m_ctx);
	for (i = 0; creds[i] != NULL; ++i)
	    credentials.push_back(Credential(creds[i]));

	abac_context_credentials_free(creds);
	return credentials;
    }
}

#endif /* __ABAC_HH__ */
