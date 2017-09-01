
# cred_printer
#
VERSION=1.10
DISTFILES=dist/cred_printer-${VERSION}.tar.gz

all:	${DISTFILES}

dist/cred_printer-${VERSION}.tar.gz:
	python ./setup.py sdist

distclean:
	rm -rf cred_printer-${VERSION}
	rm -rf *.pyc *.core dist MANIFEST
clean:
	rm -rf cred_printer-${VERSION}
	rm -rf *.pyc *.core dist MANIFEST

