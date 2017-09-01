%{
#include "SSL_keyid.h"
%}

%include "SSL_keyid.h"

%include "chunk.i"

%typemap(argout) bool &success {
    --argvi;
    SV *array = $result;

    $result = sv_newmortal();
    sv_setiv($result, *$1);
    ++argvi;

    $result = array;
    ++argvi;
}

%typemap(in,numinputs=0) bool &success(bool temp) {
    $1 = &temp;
}

// Handle exceptions
%exception {
  try {
      $action
  }
  catch (std::invalid_argument) {
        croak("std::invalid_argument");
  }
  catch (std::logic_error) {
        croak("std::logic_error");
  }
}

// Calling these makes perl 5.12.4 dump core.  We protect the user from this by
// hiding the functions.
%ignore Creddy::ID::write_cert(std::FILE*);
%ignore Creddy::ID::write_privkey(std::FILE*);
%ignore Creddy::Attribute::write(std::FILE*);

// XXX We would love a typemap for FILE * in Perl, but that's not happening
// anytime soon. It's hard (impossible?) to get a PerlIO * from a GV (glob).
// If that were acquired, it's still funky getting a FILE * from that.
//
// See man perlapio for details, but you'd need:
//
// PerlIO_findFile(f)   // creates a FILE *
// PerlIO_close()       // closes it
//
// Once you create it with findFILE, you need to close it once you are done
// with it, so you'd need a typemap that gets called AFTER the function is done.
//
// Like I said, not happening.
