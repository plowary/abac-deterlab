%include "chunk.i"

%typemap(argout) bool &success {
    PyObject *o, *o2, *o3;
    o = PyBool_FromLong(*$1);
    if ((!$result) || ($result == Py_None)) {
        $result = o;
    } else {
        if (!PyTuple_Check($result)) {
            PyObject *o2 = $result;
            $result = PyTuple_New(1);
            PyTuple_SetItem($result,0,o2);
        }
        o3 = PyTuple_New(2);
        PyTuple_SetItem(o3,0,o);
        PyTuple_SetItem(o3,1,$result);
        $result = o3;
    }
}

%typemap(in,numinputs=0) bool &success(bool temp) {
    $1 = &temp;
}

// treat Python files as FILE *
%typemap(in) FILE * %{
    if (!PyFile_Check($input))
        SWIG_exception(SWIG_TypeError, "Expected file object");

    $1 = PyFile_AsFile($input);
%}

%exception {
    try {
        $action
    }
    catch (std::invalid_argument& e) {
        PyErr_SetString(PyExc_ValueError, e.what());
        return NULL;
    }
    catch (std::logic_error& e) {
        PyErr_SetString(PyExc_RuntimeError, e.what());
        return NULL;
    }
}
