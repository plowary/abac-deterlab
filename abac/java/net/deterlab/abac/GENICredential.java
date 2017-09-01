package net.deterlab.abac;

import java.io.*;
import java.math.*;
import java.text.*;

import java.util.*;

import java.security.*;
import java.security.cert.*;

import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.*;
import javax.xml.crypto.dsig.keyinfo.*;
import javax.xml.crypto.dsig.spec.*;

import org.xml.sax.*;
import org.w3c.dom.*;

/**
 * Abstract Base class from which GENI credentials are derived.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public abstract class GENICredential extends Credential implements Comparable {
    /** The signed XML representing this credential */
    protected Document doc;
    /** The GENI credential suffix */
    private static final String fileSuffix = ".xml";

    /**
     * X509KeySelector implementation from
     * http://www.outsourcingi.com/art-271-Programming-With-the-Java-XML-Digital-Signature-API.html
     * .
     *
     * Straight ahead extraction of a key from an X509 cert, but it is their
     * code and hard to improve on.
     */
    static protected class X509KeySelector extends KeySelector {
	public KeySelectorResult select(KeyInfo keyInfo,
					KeySelector.Purpose purpose,
					AlgorithmMethod method,
					XMLCryptoContext context)
	    throws KeySelectorException {
	    Iterator ki = keyInfo.getContent().iterator();
	    while (ki.hasNext()) {
		XMLStructure info = (XMLStructure) ki.next();
		if (!(info instanceof X509Data))
		    continue;
		X509Data x509Data = (X509Data) info;
		Iterator xi = x509Data.getContent().iterator();
		while (xi.hasNext()) {
		    Object o = xi.next();
		    if (!(o instanceof X509Certificate))
			continue;
		    final PublicKey key = ((X509Certificate)o).getPublicKey();
		    // Make sure the algorithm is compatible
		    // with the method.
		    if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
			return new KeySelectorResult() {
			    public Key getKey() { return key; }
			};
		    }
		}
	    }
	    throw new KeySelectorException("No key found!");
	}

	boolean algEquals(String algURI, String algName) {
	    if ((algName.equalsIgnoreCase("DSA") &&
		algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1)) ||
		(algName.equalsIgnoreCase("RSA") &&

		algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
		return true;
	    } else {
		return false;
	    }
	}
    }

    /**
     * Create an empty Credential.
     */
    public GENICredential() {
	super();
	doc = null;
	setSuffix(fileSuffix);
    }
    /**
     * Create a credential from a head and tail role.  This credential has no
     * underlying certificate, and cannot be exported or used in real proofs.
     * make_cert can create a certificate for a credential initialized this
     * way.
     * @param head the Role at the head of the credential
     * @param tail the Role at the tail of the credential
     */
    public GENICredential(Role head, Role tail) {
	super(head, tail);
	doc = null;
	setSuffix(fileSuffix);
    }

    /**
     * Do the credential extraction from an input stream.  This parses the
     * certificate from the input stream and saves it. The contents must be
     * validated and parsed later.
     * @param stream the InputStream to read the certificate from.
     * @return the parsed XML document
     * @throws IOException if the stream is unparsable
     */
    static protected Document read_certificate(InputStream stream)
	    throws IOException {
	DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	DocumentBuilder db = null;
	Document ldoc = null;

	if ( dbf == null )
	    throw new IOException("Cannot get DocumentBuilderFactory!?");
	try {
	    /* Note this setting is required to find the properly
	     * namespace-scoped signature block in the credential.
	     */
	    dbf.setNamespaceAware(true);
	    if ( (db = dbf.newDocumentBuilder()) == null )
		throw new IOException("Cannot get DocumentBuilder!?");
	    ldoc = db.parse(stream);
		ldoc.normalizeDocument();
	    return ldoc;
	}
	catch (IllegalArgumentException ie) {
	    throw new IOException("null stream", ie);
	}
	catch (SAXException se) {
	    throw new IOException(se.getMessage(), se);
	}
	catch (Exception e) {
	    throw new IOException(e.getMessage(), e);
	}

    }

    /**
     * Walk the document and set all instances of an xml:id attribute to be ID
     * attributes in terms of the java libraries.  This is needed for the
     * signature code to find signed subsections.  The "xml:id" is treated as
     * both a namespace free ID with a colon and as an "id" identifier in the
     * "xml" namespace so we don't miss it.
     * @param n the root of the document to mark
     */
    static protected void setIDAttrs(Node n) {
	if ( n.getNodeType() == Node.ELEMENT_NODE) {
	    Element e = (Element) n;
	    String id = e.getAttribute("xml:id");

	    if ( id != null && id.length() > 0 )
		e.setIdAttribute("xml:id", true);

	    id = e.getAttributeNS("xml", "id");
	    if ( id != null && id.length() > 0 )
		e.setIdAttributeNS("xml", "id", true);
	}

	for (Node nn = n.getFirstChild(); nn != null; nn = nn.getNextSibling())
	    setIDAttrs(nn);
    }

    /**
     * Return the child of Node n  that has the given name, if there is one.
     * @param n a Node to search
     * @param name the name to search for
     * @return a Node with the name, may be null
     */
    static protected Node getChildByName(Node n, String name) {
	if (name == null ) return null;

	for (Node nn = n.getFirstChild(); nn != null; nn = nn.getNextSibling())
	    if ( nn.getNodeType() == Node.ELEMENT_NODE &&
		    name.equals(nn.getNodeName())) return nn;
	return null;
    }

    /**
     * Find the X509Certificate in the Signature element and convert it to an
     * ABAC identity.  This assumes a KeyInfo in that section holding an
     * X509Data section containing the certificate in an X509Certificate
     * section.  Any of that not being found will cause a failure.  If the
     * Identity cannot be created a Gignature exception is thrown.
     * @param n a Node pointing to a Signature section
     * @return an Identity constructed frm the X509 Certificate
     * @throws MissingIssuerException if the Identity cannot be created from the
     * certificate.
     */
    static protected Identity getIdentity(Node n)
	throws MissingIssuerException {
	Identity rv = null;
	Node nn = getChildByName(n, "KeyInfo");
	String certStr = null;

	if ( nn == null ) return null;
	if ( ( nn = getChildByName(nn, "X509Data")) == null ) return null;
	if ( ( nn = getChildByName(nn, "X509Certificate")) == null ) return null;
	if ( ( certStr = nn.getTextContent()) == null ) return null;
	try {
	    certStr = "-----BEGIN CERTIFICATE-----\n" +
		certStr +
		"\n-----END CERTIFICATE-----";
	    return new Identity(new StringReader(certStr));
	}
	catch (Exception e) {
		throw new MissingIssuerException(e.getMessage(), e);
	}
    }

    static protected Date getTime(Document d, String field)
	    throws ABACException {
	Node root = null;
	Node n = null;
	SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssz");
	Date date = null;
	String dstr = null;

	if ( (root = getChildByName(d, "signed-credential")) == null)
	    throw new CertInvalidException("No signed-credential element");
	if ( (n = getChildByName(root, "credential")) == null )
	    throw new CertInvalidException("No credential element");
	if ( (n = getChildByName(n, field)) == null )
	    throw new CertInvalidException("No " + field + " element");

	if ( ( dstr = n.getTextContent()) == null )
	    throw new CertInvalidException("No expires content");

	dstr = dstr.replace("Z", "GMT");
	if ((date = df.parse(dstr, new ParsePosition(0))) == null)
	    throw new CertInvalidException("Cannot parse date: "+
		    n.getTextContent());

	return date;
    }

    /**
     * Initialize a credential from parsed certificate.  Validiate it against
     * the given identities and parse out the roles.  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    protected void init(Collection<Identity> ids)
	    throws ABACException {

	XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
	NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS,
	 	"Signature");
	DOMValidateContext valContext = null;
	XMLSignature signature = null;

	try {

	    if (nl.getLength() == 0) {
			System.out.println("length 0");
			throw new CertInvalidException("Cannot find Signature element");
		}

	    setIDAttrs(doc);
	    valContext = new DOMValidateContext(new X509KeySelector(),
		    nl.item(0));
	    if ( valContext == null ) {
			System.out.println("valContext null");
			throw new ABACException("No validation context!?");
		}

	    signature = fac.unmarshalXMLSignature(valContext);
	    if (signature == null) {
			System.out.println("sig null");
			throw new BadSignatureException("Cannot unmarshal signature");
		}

	    if (!signature.validate(valContext)) {
			System.out.println("sig val fail");
			throw new BadSignatureException("bad signature");
		}

	    m_expiration = getTime(doc, "expires");

	    if ( m_expiration.before(new Date())) {
			System.out.println("expired");
			throw new CertInvalidException("Certificate Expired " +
					m_expiration);
		}

	    load_roles();

	    // Load the issuer identity from the credential. If the identity in
	    // the credential is invalid throw out the credential (the
	    // getIdentity call will throw an exception)
	    id = getIdentity(nl.item(0));

	    if ( !ids.contains(id) ) ids.add(id);

		if (!id.getKeyID().equals(m_head.principal())) {
			System.err.println("Issuer and Principal IDs disagree!");
			throw new MissingIssuerException("Issuer ID and left hand " +
					"side principal disagree");
		}
	}
	catch (ABACException ae) {
		throw ae;
	}
	catch (Exception e) {
	    throw new BadSignatureException(e.getMessage(), e);
	}
    }

    /**
     * Parse a credential from an InputStream and initialize the role from it.
     * Combine read_credential(stream) and init(ids).  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param stream the InputStream to read the certificate from.
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    protected void init(InputStream stream, Collection<Identity> ids)
	    throws ABACException {
	 try {
	    doc = read_certificate(stream);
	 }
	 catch (IOException e) {
	     throw new CertInvalidException("Cannot parse cert", e);
	 }
	if (doc == null) throw new CertInvalidException("Unknown Format");
	init(ids);
    }

    /**
     * Create a credential from an attribute cert in a file. Throws an
     * exception if the cert file can't be opened or if there's a format
     * problem with the cert.  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param filename a String containing the filename to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredential(String filename, Collection<Identity> ids)
	throws ABACException {
	super();
	setSuffix(fileSuffix);
	try {
	    init(new FileInputStream(filename), ids);
	}
	catch (FileNotFoundException e) {
	    throw new CertInvalidException("Bad filename", e);
	}
    }

    /**
     * Create a credential from an attribute cert in a file. Throws an
     * exception if the cert file can't be opened or if there's a format
     * problem with the cert.  Note that catching
     * java.security.GeneralSecurityException catches most of the exceptions
     * this throws.
     * @param file the File to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredential(File file, Collection<Identity> ids)
	    throws ABACException {
	super();
	setSuffix(fileSuffix);
	try {
	    init(new FileInputStream(file), ids);
	}
	catch (FileNotFoundException e) {
	    throw new CertInvalidException("Bad filename", e);
	}
    }

    /**
     * Create a credential from an InputStream.  Throws an exception if the
     * stream can't be parsed or if there's a format problem with the cert.
     * Note that catching java.security.GeneralSecurityException catches most
     * of the exceptions this throws.
     * @param s the InputStream to read
     * @param ids a Collection of Identities to use in validating the cert
     * @throws CertInvalidException if the stream is unparsable
     * @throws MissingIssuerException if none of the Identities can validate the
     *				    certificate
     * @throws BadSignatureException if the signature check fails
     */
    GENICredential(InputStream s, Collection<Identity> ids)
	    throws ABACException {
	super();
	setSuffix(fileSuffix);
	init(s, ids);
    }

    /**
     * Encode the abac credential's XML and set the validity. Overload this to
     * build a real credential.
     * @param validity a long holding the number of seconds that the credential
     * is valid for.
     * @return a Node, the place to attach signatures
     * @throws ABACException if any of the XML construction fails
     */
    abstract protected Node make_rt0_content(long validity)
	throws ABACException;

    /**
     * Create a certificate from this credential issued by the given identity
     * valid for the given time (in seconds).  This is the signed XML ABAC
     * credential.
     * @param i the Identity that will issue the certificate
     * @param validity a long holding the number of seconds that the credential
     * is valid for.
     * @throws ABACException if xml creation fails
     * @throws MissingIssuerException if the issuer is bad
     * @throws BadSignatureException if the signature creation fails
     */
    public void make_cert(Identity i, long validity)
	    throws ABACException {
	X509Certificate cert = i.getCertificate();
	KeyPair kp = i.getKeyPair();
	PublicKey pubKey = null;
	PrivateKey privKey = null;
	if ( cert == null )
	    throw new MissingIssuerException("No credential in identity?");
	if ( kp == null )
	    throw new MissingIssuerException("No keypair in identity?");

	pubKey = kp.getPublic();
	if ((privKey = kp.getPrivate()) == null )
	    throw new MissingIssuerException("No private ket in identity");

	XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
	Reference ref = null;
	SignedInfo si = null;
	KeyInfoFactory kif = fac.getKeyInfoFactory();

	/* The <Object> doesn't say much, but shuts the compiler up about
	 * unchecked references.  The lists are polymorphyc and the signature
	 * libs expect that, so <Object> is the best we can do.
	 */
	List<Object> x509Content = new ArrayList<Object>();
	List<Object> keyInfo = new ArrayList<Object>();
	x509Content.add(cert.getSubjectX500Principal().getName());
	x509Content.add(cert);
	X509Data xd = kif.newX509Data(x509Content);
	KeyValue kv = null;

	try {
	    kv = kif.newKeyValue(pubKey);
	}
	catch (KeyException ke) {
	    throw new ABACException("Unsupported key format " +
		    ke.getMessage(), ke);
	}

	Collections.addAll(keyInfo, kv, xd);

	KeyInfo ki = kif.newKeyInfo(keyInfo);
	Node sig = make_rt0_content(validity);

	try {
	    ref = fac.newReference("#ref0",
		    fac.newDigestMethod(DigestMethod.SHA1, null),
		    Collections.singletonList(
			fac.newTransform(Transform.ENVELOPED,
			    (TransformParameterSpec) null)),
		    null, null);

	    si = fac.newSignedInfo(
		    fac.newCanonicalizationMethod(
			CanonicalizationMethod.INCLUSIVE,
			(C14NMethodParameterSpec) null),
		    fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
		    Collections.singletonList(ref));

	    DOMSignContext dsc = new DOMSignContext(privKey, sig);
	    XMLSignature signature = fac.newXMLSignature(si, ki);
	    signature.sign(dsc);
	}
	catch (Exception me) {
	    throw new BadSignatureException(me.getMessage(), me);
	}

    }

    /**
     * Create a certificate from this credential issued by the given identity
     * valid for the default validity period.  This is the signed XML ABAC
     * credential.
     * @param i the Identity that will issue the certificate
     * @throws ABACException if xml creation fails
     * @throws MissingIssuerException if the issuer is bad
     * @throws BadSignatureException if the signature creation fails
     */
    public void make_cert(Identity i)
	    throws ABACException {
	make_cert(i, defaultValidity);
    }

    /**
     * Load the roles off the attribute cert. Overload it to make a real
     * credential.
     * @throws CertInvalidException if the certificate is badly formatted
     */
    abstract protected void load_roles() throws CertInvalidException;
    /**
     * Output the signed GENI ABAC certificate associated with this
     * Credential to the OutputStream.
     * @param s the OutputStream on which to write
     * @throws IOException if there is an error writing.
     */
    public void write(OutputStream s) throws IOException {
	if ( doc == null )
	    return;
	try {
	    TransformerFactory tf = TransformerFactory.newInstance();
	    Transformer t = tf.newTransformer();
	    DOMSource source = new DOMSource(doc);
	    StreamResult result = new StreamResult(s);

	    t.transform(source, result);
	    s.flush();
	}
	catch (Exception e) {
	    throw new IOException(e.getMessage(), e);
	}
    }
    /**
     * Output the signed GENI ABAC certificate associated with this
     * Credential to the OutputStream.
     * @param fn a String, the file name on which to write
     * @throws IOException if there is an error writing.
     */
    public void write(String fn) throws IOException {
	write(new FileOutputStream(fn));
    }

    /**
     * Return true if this Credential has a certificate associated.  A jabac
     * extension.
     * @return true if this Credential has a certificate associated.
     */
    public boolean hasCertificate() { return doc != null; }

}
