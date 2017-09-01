// bytearrays are new as of 2.6
%{
#if (PY_MAJOR_VERSION == 2 && PY_MINOR_VERSION >= 6) || PY_MAJOR_VERSION > 2
#define MODERN_PYTHON
#endif
%}

// abac_chunk_t is a bytearray or a string
%typemap(in) abac_chunk_t %{
    if (PyString_Check($input))
        PyString_AsStringAndSize(
            $input,
            (char **)&$1.ptr,
            (Py_ssize_t *)&$1.len
        );
#ifdef MODERN_PYTHON
    else if (PyByteArray_Check($input)) {
        $1.ptr = (unsigned char *)PyByteArray_AS_STRING($input);
        $1.len = PyByteArray_GET_SIZE($input);
    }
#endif
    else
        SWIG_exception(SWIG_TypeError, "Expected string or byte array");
%}

%typemap(out) abac_chunk_t %{
    $result = PyString_FromStringAndSize(
        (const char *)$1.ptr,
        $1.len
    );
    /* python duplicates the chunk memory, so we need to free it.  The chunk
     * structure itself is on the stack.*/
    free($1.ptr);
%}
