package net.deterlab.abac;

import java.io.*;
import java.util.*;
import java.lang.reflect.*;


/**
 * A class for parsing and generating Credentials inside a Context.  All
 * credential parsing should use a credential factory inside a context uses a
 * CredentialFactory.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class CredentialFactory implements Cloneable {
	protected List<CredentialFactorySpecialization> spec;

	/**
	 * The xmlparsing routines helpfully close input streams when they
	 * successfully parse a document from one.  It's possible for a correctly
	 * parsed XML document to need to be reparsed by later specialization, for
	 * example because the XML was fine, but it was the wrong type of
	 * credential.  This makes the close operation a NOOP.
	 */
	static protected class UnclosableBufferedInputStream extends
			BufferedInputStream {
		public UnclosableBufferedInputStream(InputStream is) {
			super(is);
		}
		public UnclosableBufferedInputStream(InputStream is, int s) {
			super(is, s);
		}

		public void close() throws IOException { }
	};
	/** The classes understood by the default CredentialFactory (in order) */
	static public String[] defNames = new String[] {
			"net.deterlab.abac.GENICredentialv1_1",
			"net.deterlab.abac.GENICredentialv1_0",
			"net.deterlab.abac.X509Credential",
			"net.deterlab.abac.GENIPrivCredential",
	};

	/** Maximum credential size that can be rewound for reparsing */
	public static final int maxSize = 50 * 1024;

	/**
	 * Create a Credential Factory that parses the default type(s)
	 * @throws ABACException if the object cannot be created
	 */
	public CredentialFactory() throws ABACException {
		spec = new ArrayList<CredentialFactorySpecialization>();
		for ( String name: defNames)
			registerClass(name);
	}

	/**
	 * Create a Credential Factory that parses the given type(s).  Each String
	 * should be the binary name for a class that exports a static
	 * getCredentialParser method that returns a CredentialParser for the
	 * class.
	 * @param names a Collection of Strings naming the classes to parse
	 * @throws ABACException if the object cannot be created
	 */
	public CredentialFactory(Collection<String> names) throws ABACException {
		spec = new ArrayList<CredentialFactorySpecialization>();
		for (String n : names )
			registerClass(n);
	}

	/**
	 * Create a Credential Factory that parses the given type(s).  Each String
	 * should be the binary name for a class that exports a static
	 * getCredentialParser method that returns a CredentialParser for the
	 * class.
	 * @param names an Array of Strings naming the classes to parse
	 * @throws ABACException if the object cannot be created
	 */
	public CredentialFactory(String[] names) throws ABACException {
		spec = new ArrayList<CredentialFactorySpecialization>();
		for (String n : names )
			registerClass(n);
	}

	/**
	 * Create a Credential Factory that is a clone of the given
	 * CredentialFactory.
	 * @param cf the CredentialFactory to copy
	 * @throws ABACException if the object cannot be created
	 */
	public CredentialFactory(CredentialFactory cf) throws ABACException {
		this();

		spec = new ArrayList<CredentialFactorySpecialization>();

		for ( int i = 0; i < spec.size(); i++)
			spec.add(cf.spec.get(i));
	}

	/**
	 * Make a copy of this CredentialFactory
	 * @return a CredentialFactory, a copy of this one
	 */
	public Object clone() throws CloneNotSupportedException {
		CredentialFactory cf = null;
		try {
			cf = new CredentialFactory(this);
		}
		catch (ABACException ae) {
			return null;
		}
		return cf;
	}


	/**
	 * Parse an input stream using each possible credential format and the
	 * available identities for validation.  Return the credentials found or
	 * throw an ABACException with the problem.  It wraps the input stream in a
	 * BufferedInputStream in order to retry is a parser fails.  Credentials
	 * larger than maxSize will nor be able to be reparsed.
	 * @param is an InputStream to parse
	 * @param ids a Collection of Identities for validation
	 * @return an Array of Credentials parsed
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 * @throws BadSignatureException if the signature check fails
	 */
	public Credential[] parseCredential(InputStream is,
										Collection<Identity> ids) throws ABACException {
		Credential[] credsArr = null;
		ABACException err = null;
		UnclosableBufferedInputStream bs =
				new UnclosableBufferedInputStream(is, maxSize);

		bs.mark(maxSize);

		for (CredentialFactorySpecialization c : spec ) {
			try {
				credsArr = c.parseCredential(bs, ids);
				break;
			}
			catch (ABACException e ) {
				err = e;
				credsArr = null;
			}
			try {
				if (spec.size() > 1) bs.reset();
			}
			catch (IOException ie) {
				break;
			}
		}

		if ( credsArr != null )
			return credsArr;
		else
			throw (err != null) ? err :
					new ABACException("null exception and failed construction??");
	}


	/**
	 * Parse a File using each possible credential format and the
	 * available identities for validation.  Return the credentials found or
	 * throw an ABACException with the problem.  Calls the InputStream version
	 * internally.
	 * @param f a File to parse
	 * @param ids a Collection of Identities for validation
	 * @return an Array of Credentials parsed
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 * @throws BadSignatureException if the signature check fails
	 */
	public Credential[] parseCredential(File f,
										Collection<Identity> ids) throws ABACException {
		try {
			return parseCredential(new FileInputStream(f), ids);
		}
		catch (FileNotFoundException e) {
			throw new CertInvalidException(e.getMessage(), e);
		}
	}
	/**
	 * Parse a file named fn using each possible credential format and the
	 * available identities for validation.  Return the credentials found or
	 * throw an ABACException with the problem.  Calls the InputStream version
	 * internally.
	 * @param s a String holding the content to parse
	 * @param ids a Collection of Identities for validation
	 * @return an Array of Credentials parsed
	 * @throws CertInvalidException if the stream is unparsable
	 * @throws MissingIssuerException if none of the Identities can validate the
	 * @throws BadSignatureException if the signature check fails
	 */
	public Credential[] parseCredential(String s,
										Collection<Identity> ids) throws ABACException {
		ByteArrayInputStream bs = new ByteArrayInputStream(s.getBytes());

		return parseCredential(bs, ids);
	}

	/**
	 * Return a credential from the first class registered in
	 * the factory.
	 * @param head a Role, the head of the encoded ABAC statement
	 * @param tail a Role, the tail of the decoded ABAC statement
	 * @param aliases a KeyIDMap holding aliases for this creation
	 * @return a Credential encoding that ABAC statement
	 */
	public Credential generateCredential(Role head, Role tail,
										 KeyIDMap aliases) {
		if (spec.isEmpty()) return null;
		return spec.get(0).generateCredential(head, tail, aliases);
	}

	/**
	 * Add the named class to the list of usable specializations.  The class
	 * passed in must have a static getCredentialFactorySpecialization() method
	 * that returns a CredentialFactorySpecialization to use.
	 * @param name a String containing the binary name of the class to register
	 * @throws ABACException if there is a problem.  The cause field of this
	 * exception is set to the classloading exception, if any.
	 */
	public void registerClass(String name)
			throws ABACException {
		CredentialFactorySpecialization cs = null;

		try {
	    /* <?> doesn't guarantee much, but shuts the compiler up */
			Class<?> c =  Class.forName(name);
			Method m = c.getMethod("getCredentialFactorySpecialization");

			cs = (CredentialFactorySpecialization) m.invoke(null);
		}
		catch (Exception e) {
			throw new ABACException("Could not register credential type" +
					e.getMessage(), e);
		}

		spec.add(cs);
	}
}
