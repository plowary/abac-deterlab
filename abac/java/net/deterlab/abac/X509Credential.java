package net.deterlab.abac;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.*;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Extension;
import java.util.*;
import java.security.*;
import java.security.cert.*;

import javax.security.auth.x500.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509AttributeCertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v2AttributeCertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.util.*;
import org.bouncycastle.openssl.*;

import static java.lang.System.in;

/**
 * An ABAC credential, with or without an underlying certificate that
 * represents it.  These are edges in proof garphs and can be constructed from
 * their constituent Roles.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class X509Credential extends Credential implements Comparable {
	/** The ASN1 OID for an IETF attribute. */
	protected static String attrOID = "1.3.6.1.5.5.7.10.4";
	/** The ASN1 OID for AuthorityKeyIdentifier. */
	protected static String authKeyOID = "2.5.29.35";
	/** The certificate representing this credential */
	protected X509AttributeCertificateHolder ac;
	/** The X.509 credential suffix */
	private static final String fileSuffix = ".der";

	/** Make sure BouncyCastle is loaded */
	static { Context.loadBouncyCastle(); }

	/**
	 * Create an empty Credential.
	 */
	public X509Credential() {
		super();
		ac = null;
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
	public X509Credential(Role head, Role tail) {
		super(head, tail);
		ac = null;
		setSuffix(fileSuffix);
	}

	/**
	 * Do the credential extraction from an input stream.  This parses the
	 * certificate from the input stream and saves it. The contents must be
	 * validated and parsed later.
	 * @param stream the InputStream to read the certificate from.
	 * @throws IOException if the stream is unparsable
	 */
	protected void read_certificate(InputStream stream)
			throws IOException {
		try {
			ASN1InputStream derIn = new ASN1InputStream(stream);
			ASN1Sequence seq = (ASN1Sequence) derIn.readObject();

			AttributeCertificate cert = AttributeCertificate.getInstance(seq);
			ac = new X509AttributeCertificateHolder(cert);
		}
		catch (Exception e) {
			throw new IOException(e.getMessage(), e);
		}
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
		for (Identity i: ids) {
			try {
				PublicKey publicKey = i.getCertificate().getPublicKey();
				ContentVerifierProvider cvp = new JcaContentVerifierProviderBuilder().setProvider(new BouncyCastleProvider()).build(publicKey);
				/*AlgorithmIdentifier sigAlgIdentifier = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
				ContentVerifier verifier = cvp.get(sigAlgIdentifier);
				ac.verify(i.getCertificate().getPublicKey(), "BC");
				*/
				if (!ac.isSignatureValid(cvp)) {
					CertException ex = new CertException("The identity certificate's signature is invalid!");
					throw ex;
				}

				id = i;
				break;
			}
			catch (OperatorCreationException e) { }
			catch (CertException e) { }
		}
		if (id == null) {
			System.err.println("Exception: Identity is null");
			throw new MissingIssuerException("Unknown identity");
		}

		m_expiration = ac.getNotAfter();
		load_roles();

		if (!id.getKeyID().equals(m_head.principal())) {
			System.err.println("id found as " + id.getKeyID() + " but credential head id is " + m_head.principal());
			throw new MissingIssuerException("Unknown identity");
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
			read_certificate(stream);
		}
		catch (IOException e) {
			throw new CertInvalidException(e.getMessage(), e);
		}
		if (ac == null) throw new CertInvalidException("Unknown Format");
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
	X509Credential(String filename, Collection<Identity> ids)
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
	X509Credential(File file, Collection<Identity> ids)
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
	X509Credential(InputStream s, Collection<Identity> ids)
			throws ABACException {
		super();
		setSuffix(fileSuffix);
		init(s, ids);
	}

	/**
	 * Create a credential from an X509V2AttributeCertificate object.  Throws
	 * an exception if the certificate doesn't parse into an ABAC credential,
	 * or cannot be validated.  Note that catching
	 * java.security.GeneralSecurityException catches most of the exceptions
	 * this throws.
	 * @param c the X509V2AttributeCertificate to create from
	 * @param ids a Collection of Identities to use in validating the cert
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 *				    certificate
	 * @throws BadSignatureException if the signature check fails
	 */
	X509Credential(AttributeCertificate c,
				   Collection<Identity> ids)
			throws ABACException {
		super();
		setSuffix(fileSuffix);
		ac = new X509AttributeCertificateHolder(c);
		init(ids);
	}


	/**
	 * Create a certificate from this credential issued by the given identity
	 * valid for the given time.
	 * @param i the Identity that will issue the certificate
	 * @param validity a long holding the number of seconds that the credential
	 * is valid for.
	 * @throws ABACException if xml creation fails
	 * @throws MissingIssuerException if the issuer is bad
	 * @throws BadSignatureException if the signature creation fails
	 */
	public void make_cert(Identity i, long validity)
			throws ABACException {
		PrivateKey key = i.getKeyPair().getPrivate();
		SubjectPublicKeyInfo pki = Context.extractSubjectPublicKeyInfo(
				i.getKeyPair().getPublic());
		try {
			org.bouncycastle.cert.AttributeCertificateHolder holder = new
					org.bouncycastle.cert.AttributeCertificateHolder(new X500Name("CN="+m_head.principal()));
			org.bouncycastle.cert.AttributeCertificateIssuer issuer = new
					org.bouncycastle.cert.AttributeCertificateIssuer(new X500Name("CN="+m_head.principal()));


			BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
			Date notBefore = new Date(System.currentTimeMillis());
			Date notAfter = new Date(System.currentTimeMillis() + (1000L * validity));

			X509v2AttributeCertificateBuilder gen = new X509v2AttributeCertificateBuilder(holder, issuer, serial, notBefore, notAfter);
			gen.addAttribute(new ASN1ObjectIdentifier(attrOID), new DERSequence(new DERSequence(new DERUTF8String(toString()))));

			JcaDigestCalculatorProviderBuilder dcpBuilder = new JcaDigestCalculatorProviderBuilder();
			DigestCalculator dc = null;
			try {
				DigestCalculatorProvider dcp = dcpBuilder.build();
				dc = dcp.get(CertificateID.HASH_SHA1);
			} catch (OperatorCreationException e) {
				e.printStackTrace();
			}

			X509ExtensionUtils extUtils = new X509ExtensionUtils(dc);
			AuthorityKeyIdentifier authKeyId = extUtils.createAuthorityKeyIdentifier(pki);
			gen.addExtension((new ASN1ObjectIdentifier(authKeyOID)), false, authKeyId);
			ac = gen.build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(key));
		}
		catch (Exception e) {
			System.err.println("exception caught, can't encode cert");
			throw new ABACException("Cannot encode cert", e);
		}

		// Create the cert.
		id = i;
	}

	/**
	 * Create a certificate from this credential issued by the given identity
	 * valid for the default validity.
	 * @param i the Identity that will issue the certificate
	 * @throws ABACException if xml creation fails
	 * @throws MissingIssuerException if the issuer is bad
	 * @throws BadSignatureException if the signature creation fails
	 */
	public void make_cert(Identity i) throws ABACException {
		make_cert(i, defaultValidity);
	}

	/**
	 * Load the roles off the attribute cert.
	 * @throws CertInvalidException if the certificate is badly formatted
	 */
	private void load_roles() throws CertInvalidException {
		String roles = null;
		try {
			Attribute attr = ac.getAttributes()[0];

			ASN1Encodable t1AsEncodable = attr.getAttributeValues()[0];
			DERSequence t1 = new DERSequence(t1AsEncodable);

			ASN1Encodable t2AsEncodable = t1.getObjectAt(0);
			DERSequence t2 = new DERSequence(t2AsEncodable);

			ASN1Encodable t3AsEncodable = t2.getObjectAt(0);
			DERUTF8String t3 = new DERUTF8String(t3AsEncodable.toString());

			roles = t3.getString();
			roles = roles.replace("[[", "");
			roles = roles.replace("]]", "");

		}
		catch (Exception e) {
			System.err.println("load_roles exception is ");
			e.printStackTrace();
			throw new CertInvalidException("Badly formatted certificate");
		}

		String[] parts = roles.split("\\s*<--?\\s*");
		if (parts.length != 2) {
			System.err.println("PARTS LENGTH INVALID");
			throw new CertInvalidException("Invalid attribute: " + roles);
		}

		m_head = new Role(parts[0]);
		m_tail = new Role(parts[1]);
	}

	/**
	 * Output the DER formatted attribute certificate associated with this
	 * Credential to the OutputStream.
	 * @param s the OutputStream on which to write
	 * @throws IOException if there is an error writing.
	 */
	public void write(OutputStream s) throws IOException {
		if (ac != null )
			s.write(ac.getEncoded());
		s.flush();
	}

	/**
	 * Output the DER formatted attribute certificate associated with this
	 * Credential to the filename given.
	 * @param fn a String containing the output filename
	 * @throws IOException if there is an error writing.
	 */
	public void write(String fn) throws IOException, FileNotFoundException {
		write(new FileOutputStream(fn));
	}

	/**
	 * Return true if this Credential has a certificate associated.  A jabac
	 * extension.
	 * @return true if this Credential has a certificate associated.
	 */
	public boolean hasCertificate() {
		return ac != null;
	}

	/**
	 * Return a CredentialFactorySpecialization for X509Credentials.  Used by
	 * the CredentialFactory to parse and generate these kind of credentials.
	 * It is basically a wrapper around constuctor calls.
	 * @return a CredentialParser for this kind of credential.
	 */
	static public CredentialFactorySpecialization
	getCredentialFactorySpecialization() {
		return new CredentialFactorySpecialization() {
			public Credential[] parseCredential(InputStream is,
												Collection<Identity> ids) throws ABACException {
				return new Credential[] { new X509Credential(is, ids) };
			}
			public Credential generateCredential(Role head, Role tail,
												 KeyIDMap aliases) {
				return new X509Credential(head, tail);
			}
		};
	}


}
