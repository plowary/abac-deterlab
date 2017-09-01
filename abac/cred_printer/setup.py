#!/usr/bin/env python

from distutils.core import setup

setup(name='cred_printer',
	version='1.10',
	description='ABAC X.509 to text service',
	author='Ted Faber',
	author_email='faber@isi.edu',
	url='http://abac.isi.deterlab.net',
	packages=['cred_printer'],
	requires=['M2Crypto'],
	provides=['cred_printer'],
	scripts=['cred_client.py', 'cred_server.py' ],
    )
