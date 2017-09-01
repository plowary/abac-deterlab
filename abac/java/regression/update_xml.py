#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as eTree


def update_xml(xml_filename, cert_filename):
    tree = eTree.parse(xml_filename)
    cred_type = None

    # Check if credential type is ABAC v1.0 or 1.1
    version = namespace_safe_find(tree, 'version')
    if version is not None:
        if version.text == '1.0':
            cred_type = '1.0'
        elif version.text == '1.1':
            cred_type = '1.1'

    # Check if credential type is privilege
    type_elem = namespace_safe_find(tree, 'type')
    if type_elem is not None and type_elem.text == 'privilege':
        cred_type = 'priv'

    # Raise error if credential type couldn't be found
    if cred_type is None:
        raise NameError('Could not find credential type')

    # Load the PEM data and get the correct issuer subject key identifier to use
    ski = os.popen('openssl x509 -in ' + cert_filename + ' -noout -text | '
                                                         'sed -n \'/Subject Key Identifier/{n;p;}\'').read()
    ski = ski.strip().lower().replace(':', '')

    # Rewrite the UUIDs in the unsigned credentials
    if cred_type == '1.0':
        rt0_elem = namespace_safe_find(tree, 'rt0')

        cred = rt0_elem.text
        arrow_index = cred.find("<-")
        fixed_cred = ski + cred[40:arrow_index+2] + ski + cred[arrow_index+40+2:]
        rt0_elem.text = fixed_cred
        print('Writing new v1.0 credential xml tree for ' + xml_filename)
        write_tree(tree, xml_filename)

    elif cred_type == '1.1':
        keyid_elem = namespace_safe_find(tree, 'keyid')
        keyid_elem.text = ski
        print('Writing new v1.1 credential xml tree for ' + xml_filename)
        write_tree(tree, xml_filename)

    elif cred_type == 'priv':
        owner_gid_elem = namespace_safe_find(tree, 'owner_gid')
        target_gid_elem = namespace_safe_find(tree, 'target_gid')
        gid = open(cert_filename, 'r').read()
        gid = gid.replace('-----BEGIN CERTIFICATE-----\n', '')
        gid = gid.replace('-----END CERTIFICATE-----\n', '')
        owner_gid_elem.text = gid
        target_gid_elem.text = gid
        print('Writing new priv credential xml tree for ' + xml_filename)
        write_tree(tree, xml_filename)


def write_tree(tree, xml_filename):
    output = eTree.tostring(tree.getroot(), encoding="utf-8", method="xml").decode(encoding="utf-8")
    # Remove ns0 from the output elements
    output = output.replace("ns0:", "")
    output = output.replace(":ns0", "")
    output = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>" + output
    xml_file = open(xml_filename, 'wt')
    xml_file.write(output)
    xml_file.close()
    print('Successfully wrote ' + xml_filename + ' to file')


def namespace_safe_find(tree, elem):
    root = tree.getroot()
    test_tree = eTree.tostring(root, encoding="utf-8", method="xml").decode(encoding="utf-8")
    ns = {'ns0': 'http://www.w3.org/2000/09/xmldsig#'}
    if test_tree.find('<ns0:' + elem) != -1:
        return root.find('.//ns0:' + elem, namespaces=ns)
    elif test_tree.find('<' + elem) != -1:
        return root.find('.//' + elem, namespaces=ns)

os.chdir(os.path.dirname(os.path.abspath(sys.argv[0])))  # cd to working directory
update_xml(sys.argv[1], sys.argv[2])
