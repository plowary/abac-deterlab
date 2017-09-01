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

    class Context {
        public:
            Context() { m_ctx = abac_context_new(); }
            Context(const Context &context) { m_ctx = abac_context_dup(context.m_ctx); }
            ~Context() { abac_context_free(m_ctx); }

            int load_id_file(char *filename) { return abac_context_load_id_file(m_ctx, filename); }
            int load_id_chunk(abac_chunk_t cert) { return abac_context_load_id_chunk(m_ctx, cert); }
            int load_id_id(ID& id); /* defined later in the class */
            int load_attribute_file(char *filename) { return abac_context_load_attribute_file(m_ctx, filename); }
            int load_attribute_chunk(abac_chunk_t cert) { return abac_context_load_attribute_chunk(m_ctx, cert); }

            void load_directory(char *path) { abac_context_load_directory(m_ctx, path); }


            /* abac query, returns a vector of credentials on success, NULL on fail */
            std::vector<Credential> query(char *role, char *principal, bool &success) {
                abac_credential_t **creds, **end;
                int i, success_int;
                creds = abac_context_query(m_ctx, role, principal, &success_int);
                success = success_int;

                for (i = 0; creds[i] != NULL; ++i)
                    ;

                end = &creds[i];
                std::vector<Credential> credentials = std::vector<Credential>(creds, end);
                abac_context_credentials_free(creds);
                return credentials;
            }
            std::vector<Credential> credentials() {
                abac_credential_t **creds, **end;
                int i;

                creds = abac_context_credentials(m_ctx);
                for (i = 0; creds[i] != NULL; ++i)
                    ;

                end = &creds[i];
                std::vector<Credential> credentials = std::vector<Credential>(creds, end);

                abac_context_credentials_free(creds);
                return credentials;
            }
	void set_nickname(char *key, char *nick) {
	    abac_context_set_nickname(m_ctx, key, nick);
	}
        private:
            abac_context_t *m_ctx;
	friend class Role;
        friend class ID;
	friend class Attribute;
    };

    class Role {
        public:
            Role() : m_role(NULL) { } // do not use: here for swig
            Role(abac_role_t *role) { m_role = abac_role_dup(role); }
            Role(char *role_name) { m_role = abac_role_from_string(role_name); }
            Role(const Role &role) { m_role = abac_role_dup(role.m_role); }
            ~Role() { abac_role_free(m_role); }
            bool is_principal() const { return abac_role_is_principal(m_role); }
            bool is_role() const { return abac_role_is_role(m_role); }
            bool is_linking() const { return abac_role_is_linking(m_role); }

            char *string() const { return abac_role_string(m_role); }
            char *short_string(Context& c) const { 
		return abac_role_short_string(m_role, c.m_ctx);
	    }
            char *linked_role() const { return abac_role_linked_role(m_role); }
            char *role_name() const { return abac_role_role_name(m_role); }
            char *principal() const { return abac_role_principal(m_role); }

        private:
            abac_role_t *m_role;
    };

    class Credential {
        public:
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
            const Role &head() { return m_head; }
            const Role &tail() { return m_tail; }
            abac_chunk_t attribute_cert() { return abac_credential_attribute_cert(m_cred); }
            abac_chunk_t issuer_cert() { return abac_credential_issuer_cert(m_cred); }
        
        private:
            abac_credential_t *m_cred;
            Role m_head, m_tail;
    };


    class ID {
        public:
            ID() : m_id(NULL) { } // do not use: required by swig
            ID(const ID &id) { m_id = abac_id_dup(id.m_id); }
            ~ID() { abac_id_free(m_id); }

            ID(char *filename) : m_id(NULL) {
                m_id = abac_id_from_file(filename);
                if (m_id == NULL)
                    throw std::invalid_argument("Could not load ID cert");
            }

            ID(abac_chunk_t chunk) : m_id(NULL) {
                m_id = abac_id_from_chunk(chunk);
                if (m_id == NULL)
                    throw std::invalid_argument("Could not load ID certificate with a chunk");
            }
            ID(char *cn, int validity) : m_id(NULL) {
                int ret = abac_id_generate(&m_id, cn, validity);
                if (ret == ABAC_GENERATE_INVALID_CN)
                    throw std::invalid_argument("CN must be alphanumeric and start with a letter");
                if (ret == ABAC_GENERATE_INVALID_VALIDITY)
                    throw std::invalid_argument("Validity must be > 0 days");
            }
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
            char *keyid() { return abac_id_keyid(m_id); }
            char *cn() { return abac_id_cn(m_id); }
            char *cert_filename() { return abac_id_cert_filename(m_id); }
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
            char *privkey_filename() { return abac_id_privkey_filename(m_id); }
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
            abac_chunk_t cert_chunk() { return abac_id_cert_chunk(m_id); }
            abac_chunk_t privkey_chunk() { return abac_id_privkey_chunk(m_id); }

            friend class Attribute;
            friend class Context;

        private:
            abac_id_t *m_id;
    };

    class Attribute {
        public:
            Attribute() : m_attr(NULL) { } // do not use: required by swig
            ~Attribute() { abac_attribute_free(m_attr); }

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
            bool bake() {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_bake(m_attr);
            }

            bool bake(Context& c) {
                if (baked()) throw std::logic_error("Cert is already baked");
                return abac_attribute_bake_context(m_attr, c.m_ctx);
            }

            bool baked() { return abac_attribute_baked(m_attr); }

	    void set_output_format(char *fmt) {
		abac_attribute_set_output_format(m_attr, fmt);
	    }

	    char *get_output_format() {
		return abac_attribute_get_output_format(m_attr);
	    }

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
}

#endif /* __ABAC_HH__ */
