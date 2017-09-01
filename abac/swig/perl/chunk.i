// abac_chunk_t is a string
%typemap(in) abac_chunk_t {
    STRLEN len;
    $1.ptr = (unsigned char *)SvPV($input, len);
    $1.len = len;
}

%typemap(out) abac_chunk_t {
    $result = newSVpvn(
        (const char *)$1.ptr,
        $1.len
    );
    ++argvi;
}
