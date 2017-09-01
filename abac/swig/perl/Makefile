all: ABAC.so ABAC.pm

ABAC.so: abac_wrap.o SSL_keyid.o
	g++ -shared abac_wrap.o SSL_keyid.o -labac -lssl -o ABAC.so

abac_wrap.o: abac_wrap.cxx
	g++ -g -c abac_wrap.cxx `perl -MExtUtils::Embed -e ccopts`

abac_wrap.cxx ABAC.py: abac.i language.i
	swig -c++ -perl abac.i

clean:
	rm -f ABAC.so ABAC.pm abac_wrap.o abac_wrap.cxx SSL_keyid.o
