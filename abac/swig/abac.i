%module ABAC

// Accessing these overloaded functions confuses perl and python.
// ignore the string& set,
// The bare name takes an open file.
%rename(ID_chunk) ABAC::ID::ID(abac_chunk_t);
%ignore ABAC::ID::write_cert(const std::string&);
%ignore ABAC::ID::write_privkey(const std::string&);
%ignore ABAC::Attribute::write(const std::string&);

// Accessing these overloaded functions confuses perl and python.
// Rename these so we can get to them

%rename(ID_chunk) Creddy::ID::ID(abac_chunk_t);


%{
#include "abac.hh"
using namespace ABAC;
%}

%include "language.i"

%ignore std::vector<ABAC::Credential>::vector(size_type); 
%ignore std::vector<ABAC::Credential>::resize(size_type);
%ignore std::vector<ABAC::Credential>::pop(); 

%include "std_vector.i"

namespace std {
    %template(CredentialVector) vector<ABAC::Credential>;
};

%include "abac.h"
%include "abac.hh"
