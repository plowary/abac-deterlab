package net.deterlab.abac;

import java.io.*;
import java.math.*;
import java.text.*;

import java.util.*;
import java.security.*;
import java.security.cert.*;

import javax.security.auth.x500.*;

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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.x509.util.*;
import org.bouncycastle.openssl.*;

/**
 * An ABAC credential formatted as an abac-type GENI credential.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class GENIPrivCredential extends GENICredential {
	/**
	 * Create an empty Credential.
	 */
	public GENIPrivCredential() {
		super();
		doc = null;
	}
	/**
	 * Create a credential from a head and tail role.  This credential has no
	 * underlying certificate, and cannot be exported or used in real proofs.
	 * make_cert can create a certificate for a credential initialized this
	 * way.
	 * @param head the Role at the head of the credential
	 * @param tail the Role at the tail of the credential
	 * @param d an XML document actually ignored.
	 * @param i an identity that's actually ignored
	 * @param e the expiration of this credential
	 */
	public GENIPrivCredential(Role head, Role tail, Document d, Identity i,
							  Date e) {
		m_head = head;
		m_tail = tail;
		doc = null;
		id = null;
		m_expiration = e;
	}
	/**
	 * Create a certificate from this credential issued by the given identity
	 * valid for the given period; these credentials cannot be turned into
	 * certificates, so this will always throw an exception.
	 * @param i the Identity that will issue the certificate
	 * @param validity a long holding the number of seconds that the credential
	 * is valid for.
	 * @throws ABACException if xml creation fails
	 * @throws MissingIssuerException if the issuer is bad
	 * @throws BadSignatureException if the signature creation fails
	 */
	public void make_cert(Identity i, long validity)
			throws ABACException {
		throw new ABACException("Cannot generate a GENIPrivCredential");
	}


	/**
	 * Create a certificate from this credential issued by the given identity;
	 * these credentials cannot be turned into certificates, so this will
	 * always throw an exception.
	 * @param i the Identity that will issue the certificate
	 * @throws ABACException if xml creation fails
	 * @throws MissingIssuerException if the issuer is bad
	 * @throws BadSignatureException if the signature creation fails
	 */
	public void make_cert(Identity i)
			throws ABACException {
		throw new ABACException("Cannot generate a GENIPrivCredential");
	}

	/**
	 * Class that parses a GENI privilege credential into multiple
	 * GENIPrivCredential objects.
	 */
	static class GENIPrivSpecialization
			extends CredentialFactorySpecialization {

		/**
		 * Extract an identity from a field holding a PEM-encoded x.509
		 * certificate (for example, owner_gid).
		 *
		 * @param n a Node that has the certificate in its Text Content
		 * @return the Identity
		 */
		protected Identity nodeToIdentity(Node n) {
			String certStr = null;

			if ((certStr = n.getTextContent()) == null) return null;
			try {
				certStr = "-----BEGIN CERTIFICATE-----\n" +
						certStr +
						"\n-----END CERTIFICATE-----";
				return new Identity(new StringReader(certStr));
			} catch (Exception e) {
				return null;
			}
		}

		/**
		 * Parses the credential into multiple Objects based on the permissions
		 * imbued by the credential.
		 *
		 * @param d      a Document, the parsed credential
		 * @param issuer an Identity that signed the credential
		 * @return an array of GENIPrivCredentials that represent the
		 * credential
		 * @throws ABACException if XML creation fails
		 */
		protected Credential[] make_creds(Document d, Identity issuer)
				throws ABACException {
			Node root = null;
			Node credential = null;
			Node owner_gid = null;
			Node target_gid = null;
			Node privileges = null;
			Node priv = null;
			Identity owner = null;
			Identity target = null;
			ArrayList<GENIPrivCredential> rv =
					new ArrayList<GENIPrivCredential>();

			if ((root = getChildByName(d, "signed-credential")) == null)
				throw new CertInvalidException("No signed-credential element");
			if ((credential = getChildByName(root, "credential")) == null)
				throw new CertInvalidException("No credential element");
			if ((owner_gid = getChildByName(credential, "owner_gid")) == null)
				throw new CertInvalidException("No owner_gid element");
			if ((target_gid = getChildByName(credential, "target_gid")) == null)
				throw new CertInvalidException("No target_gid element");
			if ((privileges = getChildByName(credential, "privileges")) == null)
				throw new CertInvalidException("No privileges element");

			Date exp = getTime(d, "expires");

			if (exp.before(new Date()))
				throw new CertInvalidException("Certificate Expired " + exp);

			if ((owner = nodeToIdentity(owner_gid)) == null)
				throw new CertInvalidException("Bad owner_gid element");
			if ((target = nodeToIdentity(target_gid)) == null)
				throw new CertInvalidException("Bad target_gid element");

			if (privileges != null)
				for (Node n = privileges.getFirstChild(); n != null;
					 n = n.getNextSibling()) {
		/* Ignore non-elements and non-privilege elements */
					if (n.getNodeType() != Node.ELEMENT_NODE ||
							!"privilege".equals(n.getNodeName())) continue;
					Node name = null;
					Node can_delegate = null;
					boolean cd = false;
					String cds = null;
					String pname = null;

					if ((name = getChildByName(n, "name")) == null)
						throw new CertInvalidException("No privilege name");

					if ((can_delegate = getChildByName(n, "can_delegate")) == null)
						throw new CertInvalidException("No privilege delegate");

					if ((pname = name.getTextContent()) == null)
						throw new CertInvalidException("No privilege name text");
					if ((cds = can_delegate.getTextContent()) == null)
						throw new CertInvalidException("No delegate text");
					cd = cds.equals("1") || cds.equals("true");

		/* First privilege includes the basic speaks for defintion 
		 * for this owner */
					if (rv.isEmpty()) {
						rv.add(new GENIPrivCredential(
								new Role(issuer.getKeyID() + ".speaks_for_" +
										owner.getKeyID()),
								new Role(owner.getKeyID()), d, issuer, exp));
						rv.add(new GENIPrivCredential(
								new Role(issuer.getKeyID() + ".speaks_for_" +
										owner.getKeyID()),
								new Role(owner.getKeyID() + ".speaks_for_" +
										owner.getKeyID()), d, issuer, exp));
					}

		/* The privilege itself */
					rv.add(new GENIPrivCredential(
							new Role(issuer.getKeyID() + "." + pname + "_" +
									target.getKeyID()),
							new Role(issuer.getKeyID() + ".speaks_for_" +
									owner.getKeyID()), d, issuer, exp));
					if (cd) {
		    /* The rules for delegation, if necessary */
						rv.add(new GENIPrivCredential(
								new Role(issuer.getKeyID() + "." + pname +
										"_" + target.getKeyID()),
								new Role(issuer.getKeyID() + ".can_delegate_"
										+ pname + "_" + target.getKeyID() +
										"." + pname + "_" + target.getKeyID()),
								d, issuer, exp));
						rv.add(new GENIPrivCredential(
								new Role(issuer.getKeyID() +
										".can_delegate_" + pname),
								new Role(owner.getKeyID()), d, issuer, exp));
					}
				}
			return rv.toArray(new Credential[rv.size()]);
		}

		/**
		 * Parse the credential into multiple GENIPrivCredentials that encode
		 * its semantics.
		 *
		 * @param is  an InputStream containing the credentals
		 * @param ids a Collection of Identities to use in validation
		 * @return an array of GENIPrivCredentials that represent the
		 * credential
		 * @throws CertInvalidException   if the stream is unparsable
		 * @throws MissingIssuerException if none of the Identities can
		 *                                validate the certificate
		 * @throws BadSignatureException  if the signature check fails
		 */
		public Credential[] parseCredential(InputStream is,
											Collection<Identity> ids) throws ABACException {
			try {
				Document d = read_certificate(is);
				XMLSignatureFactory fac =
						XMLSignatureFactory.getInstance("DOM");
				NodeList nl = d.getElementsByTagNameNS(XMLSignature.XMLNS,
						"Signature");
				DOMValidateContext valContext = null;
				XMLSignature signature = null;
				Identity lid = null;


				if (nl.getLength() == 0) {
					System.err.println("no signature found");
					throw new CertInvalidException(
							"Cannot find Signature element");
				}

				setIDAttrs(d);
				valContext = new DOMValidateContext(new X509KeySelector(),
						nl.item(0));
				if (valContext == null) {
					System.err.println("valContext is null");
					throw new ABACException("No validation context!?");
				}

				signature = fac.unmarshalXMLSignature(valContext);
				if (signature == null) {
					System.err.println("signature unmarshal failed");
					throw new BadSignatureException(
							"Cannot unmarshal signature");
				}

				if (!signature.validate(valContext)) {
					System.err.println("signature validation failed");
					throw new BadSignatureException("bad signature");
				}

				lid = getIdentity(nl.item(0));
				if (!ids.contains(lid)) ids.add(lid);

				return make_creds(d, lid);
			} catch (ABACException ae) {
				throw ae;
			}
			catch (Exception e) {
				System.err.println("Attempt to parse credential as GENIPrivCredential failed!");
				throw new BadSignatureException(e.getMessage(), e);
			}
		}

		/**
		 * One cannot create a GENIPrivCredential to encodes a single arbitrary
		 * head and tail, so this always fails.
		 * @param head a Role to encode
		 * @param tail a Role to encode
		 * @param aliases a KeyIDMap with keyid aliases
		 * @return null
		 */
		public Credential generateCredential(Role head, Role tail,
											 KeyIDMap aliases) {
			return null;
		}
	};

	/**
	 * These credentials are parsed in the specialization, so load_roles is
	 * not used.
	 * @throws CertInvalidException never
	 */
	protected void load_roles() throws CertInvalidException { }


	/**
	 * These credentials are never baked so make_rt0_content is
	 * not used.
	 * @return a Node, the place to attach signatures
	 * @throws ABACException never
	 */
	protected Node make_rt0_content(long validity) throws ABACException {
		return null;
	}

	/**
	 * Return a CredentialCredentialFactorySpecialization for
	 * GENIPrivCredentials.  Used by the CredentialFactory to parse these kind
	 * of credentials.
	 * @return a CredentialFactorySpecialization for this kind of credential.
	 */
	static public CredentialFactorySpecialization
	getCredentialFactorySpecialization() {
		return new GENIPrivSpecialization();
	}
}
