package net.deterlab.abac;

import edu.uci.ics.jung.graph.*;
import edu.uci.ics.jung.graph.util.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;
import java.security.*;
import java.security.cert.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.x509.*;
import org.bouncycastle.openssl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Represents a global graph of credentials in the form of principals and
 * attributes.  Contains the identities and credentials that can be used in a
 * proof.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class Context {
	/** Certificate imported successfully */
	public static final int ABAC_CERT_SUCCESS = 0;
	/** Certificate import failed, invalid certificate */
	public static final int ABAC_CERT_INVALID = -1;
	/** Certificate import failed, signature filed */
	public static final int ABAC_CERT_BAD_SIG = -2;
	/** Certificate import failed, unknown issuer */
	public static final int ABAC_CERT_MISSING_ISSUER = -3;

	/** Internal graph representation */
	protected Graph<Role,Credential> g;
	/** Set of edges in the graph that were added by the logic.  */
	protected Set<Credential> derived_edges;
	/** Internal persistent query object */
	protected Query pq;
	/** True when the graph has been changed since the last set of implied
	 * edges were calculated. */
	protected boolean dirty;
	/** Set of identities known to this Context. */
	protected Set<Identity> m_identities;
	/** The CredentialFactory for this Context */
	protected CredentialFactory credentialFactory;

	/** Translation of nicknames to keyids */
	protected KeyIDMap keyMap;

	/** True once BouncyCastle has been loaded. */
	static boolean providerLoaded = false;

	/**
	 * Load the BouncyCastle provider, necessary for ABAC crypto (shouldn't
	 * need to be called directly).  This is called from the Context static
	 * constructor and static constructors in other ABAC classes that use
	 * BouncyCastle crypto (which loads a Context, which calls it as well) to
	 * make sure crypto is available.
	 */
	static void loadBouncyCastle() {
		if ( !providerLoaded ) {
			AccessController.doPrivileged(new PrivilegedAction<Object>() {
				public Object run() {
					Security.addProvider(new BouncyCastleProvider());
					return null;
				}
			});
			providerLoaded = true;
		}
	}

	/** Load the BouncyCastle provider. */
	static { loadBouncyCastle(); };

	/**
	 * The result of a query on this context.  The credentials form a partial
	 * or total proof, and success indicates whether the proof succeeded.
	 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
	 * @version 1.5
	 */
	public class QueryResult {
		/** Credentials returned */
		protected Collection<Credential> creds;
		/** True if the proof succeeded. */
		protected boolean success;

		/**
		 * Construct a result from components.
		 * @param c the collection of credentials in the proof
		 * @param s a boolean, true if the query succeeded.
		 */
		QueryResult(Collection<Credential> c, boolean s) {
			creds = c;
			success = s;
		}

		/**
		 * Empty constructor
		 */
		public QueryResult() {
			creds = new TreeSet<Credential>();
			success = false;
		}

		/**
		 * Return the credentials in the proof.
		 * @return the collection of credentials
		 */
		public Collection<Credential> getCredentials() { return creds; }
		/**
		 * Return the success in the proof.
		 * @return the boolean, true on success
		 */
		public boolean getSuccess() { return success; }
	}


	/**
	 * Create an empty Context.
	 */
	public Context() {
        /* create the graph */
		g = Graphs.<Role,Credential>synchronizedDirectedGraph(
				new DirectedSparseGraph<Role,Credential>());
		derived_edges = new HashSet<Credential>();
		pq = new Query(g);
		dirty = false;
		m_identities = new TreeSet<Identity>();
		keyMap = new KeyIDMap();
		try {
			credentialFactory = new CredentialFactory();
		}
		catch (ABACException ignored) { }
	}

	/**
	 * Create a context from another context.
	 * @param c the Context to copy
	 */
	public Context(Context c) {
		this();
		for (Identity i: c.m_identities)
			load_id_chunk(i);
		for (Credential cr: c.credentials())
			load_attribute_chunk(cr);
		derive_implied_edges();
		try {
			credentialFactory = (CredentialFactory) c.credentialFactory.clone();
		}
		catch (CloneNotSupportedException ignored) { }
	}

	/**
	 * Create a Context from a collection of Credentials.  A jabac extension.
	 * @param creds the collection of credentials
	 */
	public Context(Collection<Credential> creds) {
		this();
		for (Credential c: creds) {
			Identity i = c.issuer();

			if (i != null ) load_id_chunk(i);
			load_attribute_chunk(c);
		}
	}

	/**
	 * Load an Identity from a file.
	 * @param fn a String containing the file name.
	 * @return one of the static int return codes.
	 */
	public int load_id_file(String fn) { return load_id_chunk(new File(fn)); }
	/**
	 * Load an Identity from a file.
	 * @param fn a File containing the file name.
	 * @return one of the static int return codes.
	 */
	public int load_id_file(File fn) { return load_id_chunk(fn); }
	/**
	 * Load an Identity from an object.  Supported objects are an Identity, a
	 * String, a File, or a java.security.cert.X509Certificate.  A string
	 * creates an new identity, and the others are derived from the contents of
	 * the data or file.
	 * @param c an object convertable to an identity as above.
	 * @return one of the static int return codes.
	 */
	public int load_id_chunk(Object c) {
		try {
			if (c instanceof Identity)
				addIdentity((Identity) c);
			else if (c instanceof String)
				addIdentity(new Identity((String) c));
			else if (c instanceof File)
				addIdentity(new Identity((File) c));
			else if (c instanceof X509Certificate)
				addIdentity(new Identity((X509Certificate) c));
			else
				return ABAC_CERT_INVALID;
		}
		catch (BadSignatureException sig) {
			return ABAC_CERT_BAD_SIG;
		}
		catch (Exception e) {
			return ABAC_CERT_INVALID;
		}
		return ABAC_CERT_SUCCESS;
	}

	/**
	 * Load an attribute certificate from a file.
	 * @param fn a String containing the file name.
	 * @return one of the static int return codes.
	 */
	public int load_attribute_file(String fn) {
		return load_attribute_chunk(new File(fn));
	}

	/**
	 * Load an attribute certificate from a file.
	 * @param fn a File containing the file name.
	 * @return one of the static int return codes.
	 */
	public int load_attribute_file(File fn) { return load_attribute_chunk(fn); }

	/**
	 * Load an Credential from an object.  Supported objects are a Credential, a
	 * String, a File, or an org.bouncycastle.x509.X509V2AttributeCertificate.
	 * A string creates an new Credential, and the others are derived from the
	 * contents of the data or file.
	 * @param c an object convertable to a Credential as above.
	 * @return one of the static int return codes.
	 */
	public int load_attribute_chunk(Object c) {
		try {
			Credential[] creds = null;

			if (c instanceof Credential) {
				add_credential((Credential) c);
				return ABAC_CERT_SUCCESS;
			} else if (c instanceof String) {
				creds = credentialFactory.parseCredential(
						(String) c, m_identities);
			} else if (c instanceof File) {
				creds = credentialFactory.parseCredential(
						(File) c, m_identities);
			} else if ( c instanceof AttributeCertificate)  {
				// TODO change this?
				System.out.println("processing AttributeCertificate");
				add_credential(new X509Credential((AttributeCertificate) c,
						m_identities));
				return ABAC_CERT_SUCCESS;
			} else return ABAC_CERT_INVALID;

			if ( creds == null )
				return ABAC_CERT_INVALID;

			for (Credential cc: creds )
				add_credential(cc);
		}
		catch (MissingIssuerException sig) {
			return ABAC_CERT_MISSING_ISSUER ;
		}
		catch (BadSignatureException sig) {
			return ABAC_CERT_BAD_SIG;
		}
		catch (CertInvalidException e) {
			return ABAC_CERT_INVALID;
		}
		catch (ABACException ae) {
			return ABAC_CERT_INVALID;
		}
		return ABAC_CERT_SUCCESS;
	}

	/**
	 * Determine if prinicpal possesses role in the current context.  If so,
	 * return a proof of that, otherwise return a partial proof of it.
	 * @param role a String encoding the role to check for.
	 * @param principal a String with the principal ID in it.
	 * @return a Context.QueryResult containing the result.
	 */
	public QueryResult query(String role, String principal) {
		derive_implied_edges();

		Query q = new Query(g);
		Graph<Role, Credential> rg = q.run(role, principal);
		TreeSet<Credential> tr = new TreeSet<Credential>();

		for ( Credential c: rg.getEdges())
			tr.add(c);

		return new QueryResult(tr, q.successful());
	}

	/**
	 * Return a collection of the credentials in the graph.s
	 * @return a collection of the credentials in the graph.
	 */
	public Collection<Credential> credentials() {
		Collection<Credential> creds = new HashSet<Credential>();

		// only non-derived edges
		for (Credential cred : g.getEdges())
			if (!derived_edges.contains(cred))
				creds.add(cred);

		return creds;
	}

	/**
	 * Return all the Identities known in this context.  A jabac extension.
	 * @return all the Identities known in this context.
	 */
	public Collection<Identity> identities() {
		return m_identities;
	}

	/**
	 * Returns true if the given Identity is known in this Context.  A jabac
	 * extension.
	 * @param i the Identity to look for
	 * @return a boolean, true if the Identity is known.
	 */
	public boolean knowsIdentity(Identity i) { return m_identities.contains(i);}
	/**
	 * Returns true if an Identity with the given string representation is
	 * known in this Context.  A jabac extension.
	 * @param k the string representing the Identity to look for
	 * @return a boolean, true if the Identity is known.
	 */
	public boolean knowsKeyID(String k) {
		boolean known = false;
		for (Identity i: m_identities)
			if (k.equals(i.getKeyID())) return true;
		return false;
	}


	/**
	 * Add a credential to the graph.
	 * @param cred the Credential to add
	 */
	protected void add_credential(Credential cred) {
		Role tail = cred.tail();
		Role head = cred.head();

		// explicitly add the vertices, to avoid a null pointer exception
		if ( !g.containsVertex(head))
			g.addVertex(head);
		if ( !g.containsVertex(tail))
			g.addVertex(tail);

		if (!g.containsEdge(cred))
			g.addEdge(cred, tail, head);

		// add the prereqs of an intersection to the graph
		if (tail.is_intersection()) {
			try {
				for (Role prereq : tail.prereqs())
					g.addVertex(prereq);
			} catch (ABACException ignored) { }
		}

	/* If the credential includes new names for identities, incorporate
	 * them. */
		if ( cred instanceof MapsKeyIDs ) {
			MapsKeyIDs km = (MapsKeyIDs) cred;

			keyMap.merge(km.getMapping(), true);
		}


		dirty = true;
	}

	/**
	 * Remove a credential from the graph.
	 * @param cred the Credential to remove
	 */
	protected void remove_credential(Credential cred) {
		if (g.containsEdge(cred))
			g.removeEdge(cred);
		dirty = true;
	}

	/**
	 * Add a role w/o an edge
	 * @param v the Role to add
	 */
	protected void add_vertex(Role v) {
		if (!g.containsVertex(v)) {
			g.addVertex(v);
			dirty = true;
		}
	}

	/**
	 * Remove a role and connected edges.
	 * @param v the Role to remove
	 */
	protected void remove_vertex(Role v) {
		if (g.containsVertex(v)) {
			g.removeVertex(v);
			dirty = true;
		}
	}

	/**
	 * Derive the implied edges in the graph, according to RT0 derivation rules.
	 * They are added to this graph. See "Distributed Credential Chain Discovery
	 * in Trust Management" by Ninghui Li et al. for details. Note that a
	 * derived linking edge can imply a new intersection edge and vice versa.
	 * Therefore we iteratively derive edges, giving up when an iteration
	 * produces 0 new edges.
	 */
	protected synchronized void derive_implied_edges() {
		// nothing to do on a clean graph
		if (!dirty)
			return;

		clear_old_edges();

		// iteratively derive links. continue as long as new links are added
		while (derive_links_iter() > 0)
			;
		dirty = false;
	}

	/**
	 * Single iteration of deriving implied edges. Returns the number of new
	 * links added.
	 * @return the number of new links added.
	 */
	protected int derive_links_iter() {
		int count = 0;

        /* for every node in the graph.. */
		for (Role vertex : g.getVertices()) {
			if (vertex.is_intersection()) {
				// for each prereq edge:
				//     find set of principals that have the prereq
				// find the intersection of all sets (i.e., principals
				//     that satisfy all prereqs)
				// for each principal in intersection:
				//     add derived edge

				Set<Role> principals = null;
				try {
					for (Role prereq : vertex.prereqs()) {
						Set<Role> cur_principals = pq.find_principals(prereq);

						if (principals == null)
							principals = cur_principals;
						else
							// no, they couldn't just call it "intersection"
							principals.retainAll(cur_principals);

						if (principals.size() == 0)
							break;
					}
				}
				catch (ABACException ignored) { }

				// add em
				for (Role principal : principals)
					if (add_derived_edge(vertex, principal))
						++count;
			}

			else if (vertex.is_linking()) {
				// make the rest of the code a bit clearer
				Role A_r1_r2 = vertex;

				Role A_r1 = new Role(A_r1_r2.A_r1());
				String r2 = A_r1_r2.r2();

                /* locate the node A.r1 */
				if (!g.containsVertex(A_r1)) continue;

                /* for each B that satisfies A_r1 */
				for (Role principal : pq.find_principals(A_r1)) {
					Role B_r2 = new Role(principal + "." + r2);
					if (!g.containsVertex(B_r2)) continue;

					if (add_derived_edge(A_r1_r2, B_r2))
						++count;
				}
			}
		}

		return count;
	}

	/**
	 * Add a derived edge in the graph. Returns true only if the edge does not
	 * exist.
	 * @param head the head of the link to add
	 * @param tail the tail of the link to add
	 * @return a boolean, true if an edge has been added
	 */
	protected boolean add_derived_edge(Role head, Role tail) {
		// edge exists: return false
		if (g.findEdge(tail, head) != null)
			return false;

		// add the new edge
		Credential derived_edge = new InternalCredential(head, tail);
		derived_edges.add(derived_edge);
		g.addEdge(derived_edge, tail, head);

		return true;
	}

	/**
	 * Clear the derived edges that currently exist in the graph. This is done
	 * before the edges are rederived. The derived edges in filtered graphs are
	 * also cleared.
	 */
	protected void clear_old_edges() {
		for (Credential i: derived_edges)
			g.removeEdge(i);
		derived_edges = new HashSet<Credential>();
	}

	/**
	 * Put the Identity into the set of ids used to validate certificates.
	 * Also put the keyID and name into the translation mappings used by Roles
	 * to pretty print.  In the role mapping, if multiple ids use the same
	 * common name they are disambiguated.  Only one entry for keyid is
	 * allowed.
	 * @param id the Identity to add
	 */
	protected void addIdentity(Identity id) {
		if (m_identities.contains(id))
			return;
		m_identities.add(id);
		if (id.getName() != null && id.getKeyID() != null)
			keyMap.addNickname(id.getKeyID(), id.getName());
	}

	/**
	 * Expand menmonic names in a Role string, e.g. the CN of the issuer
	 * certificate, into the full key ID.  Used internally by Roles to provide
	 * transparent use of mnemonics
	 * @param s the string to expand
	 * @return the String after expansion.
	 */
	String expandKeyID(String s) { return keyMap.expandKeyID(s); }

	/**
	 * Convert key IDs to  menmonic names in a Role string.  The inverse of
	 * expandKeyID.
	 * @param s the string to expand
	 * @return the String after expansion.
	 */
	String expandNickname(String s) { return keyMap.expandNickname(s); }

	/**
	 * Read the current ZipEntry's bytes from z.  Tedious because there's no
	 * way to reliably tell how big the entry is, so we have to rely on a
	 * simple expanding array read of the bytes.
	 * @param z the stream to operate on
	 * @return the raw data bytes
	 * @throws IOException if reading fails
	 */
	protected byte[] readCurrentZipEntry(ZipInputStream z) throws IOException {
		final int bsize = 4096;
		byte[] buf = new byte[bsize];
		byte[] rv = new byte[0];
		int r = 0;

		// z.read returns -1 at the end of entry
		while ((r = z.read(buf, 0, bsize)) != -1 ) {
			byte[] b = new byte[rv.length + r];

			System.arraycopy(rv, 0, b, 0, rv.length);
			System.arraycopy(buf, 0, b, rv.length, r);
			rv = b;
		}
		return rv;
	}

	/**
	 * Import a zip file.  First import all the identities
	 * (pem), then the credentials (der) into the credential graph then any
	 * alias files into the two maps.  If keys is not null, any key pairs in
	 * PEM files are put in there.  If errors is not null, errors reading files
	 * are added indexed by filename.  This is a jabac extension.
	 * @param s the InputStream to read
	 * @param keys a Collection into which to insert unmatched keys
	 * @param errors a Map from entry name to generated exception
	 * @throws IOException if the file is unreadable.  Per entry exceptions are
	 *			   returned in the errors parameter.
	 */
	public void load_zip(InputStream s, Collection<KeyPair> keys,
						 Map<String, Exception> errors) throws IOException {
		Map<String, byte[]> derEntries = new HashMap<String, byte[]>();
		Map<String, Identity> ids = new TreeMap<String, Identity>();
		Map<String, KeyPair> kps = new TreeMap<String, KeyPair>();
		int entries = 0;

		ZipInputStream z = new ZipInputStream(s);

		for (ZipEntry ze = z.getNextEntry(); ze != null; ze = z.getNextEntry()){
			try {
				entries++;
				byte[] buf = readCurrentZipEntry(z);
				PEMParser r = new PEMParser(
						new InputStreamReader(new ByteArrayInputStream(buf)));
				Object o = readPEM(r);

				if ( o != null ) {
					if (o instanceof Identity) {
						Identity i = (Identity) o;
						String kid = i.getKeyID();

						if (kps.containsKey(kid) ) {
							i.setKeyPair(kps.get(kid));
							kps.remove(kid);
						}
						else if (i.getKeyPair() == null )
							ids.put(i.getKeyID(), i);

						load_id_chunk(i);
					}
					else if (o instanceof KeyPair ) {
						KeyPair kp = (KeyPair) o;
						String kid = extractKeyID(kp.getPublic());

						if (ids.containsKey(kid)) {
							Identity i = ids.get(kid);

							i.setKeyPair(kp);
							ids.remove(kid);
						}
						else {
							kps.put(kid, kp);
						}
					}
				}
				else {
					// Not a PEM file
					derEntries.put(ze.getName(),buf);
					continue;
				}
			}
			catch (Exception e ) {
				if (errors != null ) errors.put(ze.getName(), e);
			}
		}

		for ( String k: derEntries.keySet() ) {
			try {
				Credential[] creds = credentialFactory.parseCredential(
						new ByteArrayInputStream(derEntries.get(k)),
						m_identities);
				for (Credential c: creds)
					add_credential(c);
			}
			catch (Exception e ) {
				if (errors != null ) errors.put(k, e);
			}
		}

		if (entries == 0)
			throw new IOException("Not a ZIP file (or empty ZIP file)");
	}
	/**
	 * Equivalent to load_zip(s, null, null).
	 * @param s the InputStream to read
	 * @throws IOException if the file is unreadable. To see per-entry
	 *			    exceptions use a signature with the errors parameter
	 */
	public void load_zip(InputStream s)
			throws IOException {
		load_zip(s, null, null);
	}
	/**
	 * Equivalent to load_zip(s, null, errors).
	 * @param s the InputStream to read
	 * @param errors a Map from entry name to generated exception
	 * @throws IOException if the file is unreadable.  Per entry exceptions are
	 *			   returned in the errors parameter.
	 */
	public void load_zip(InputStream s,
						 Map<String, Exception> errors) throws IOException {
		load_zip(s, null, errors);
	}
	/**
	 * Equivalent to load_zip(s, keys, null).
	 * @param s the InputStream to read
	 * @param keys a Collection into which to insert unmatched keys
	 * @throws IOException if the file is unreadable. To see per-entry
	 *			    exceptions use a signature with the errors parameter
	 */
	public void load_zip(InputStream s,
						 Collection<KeyPair> keys) throws IOException {
		load_zip(s, keys, null);
	}

	/**
	 * Loads a zip file.  Equivalent to
	 * load_zip(new FileInputStream(zf), keys, errors).
	 * @param zf the File to read
	 * @param keys a Collection into which to insert unmatched keys
	 * @param errors a Map from entry name to generated exception
	 * @throws IOException if the file is unreadable.  Per entry exceptions are
	 *			   returned in the errors parameter.
	 */
	public void load_zip(File zf, Collection<KeyPair> keys,
						 Map<String, Exception> errors) throws IOException {
		load_zip(new FileInputStream(zf), keys, errors);
	}
	/**
	 * Equivalent to load_zip(d, null, null).
	 * @param d the File to read
	 * @throws IOException if the file is unreadable. To see per-entry
	 *			    exceptions use a signature with the errors parameter
	 */
	public void load_zip(File d)
			throws IOException {
		load_zip(d, null, null);
	}
	/**
	 * Equivalent to load_zip(d, null, errors).
	 * @param d the File to read
	 * @param errors a Map from entry name to generated exception
	 * @throws IOException if the file is unreadable.  Per entry exceptions are
	 *			   returned in the errors parameter.
	 */
	public void load_zip(File d,
						 Map<String, Exception> errors) throws IOException {
		load_zip(d, null, errors);
	}
	/**
	 * Equivalent to load_zip(d, keys, null).
	 * @param d the File to read
	 * @param keys a Collection into which to insert unmatched keys
	 * @throws IOException if the file is unreadable. To see per-entry
	 *			    exceptions use a signature with the errors parameter
	 */
	public void load_zip(File d,
						 Collection<KeyPair> keys) throws IOException {
		load_zip(d, keys, null);
	}

	/**
	 * Read a PEM file that contains an X509 Certificate, a key pair, or both.
	 * If a cert is present it is converted into an Identity.  A key pair is
	 * returned as a java.security.KeyPair and both are returned as an Identity
	 * with an associated key pair.
	 * @param r a PEMParser from which to read
	 * @return an object encoding the contents (as above)
	 * @throws IOException for an unreadable or badly formated input
	 */
	protected Object readPEM(PEMParser r) throws IOException {
		Identity i = null;
		KeyPair keys = null;
		Object o = null;

		while ( (o = r.readObject()) != null ) {
			if (o instanceof X509Certificate) {
				if ( i == null ) {
					try {
						i = new Identity((X509Certificate)o);
					}
					catch (Exception e) {
						// Translate Idenitiy exceptions to IOException
						throw new IOException(e);
					}
					if (keys != null ) {
						i.setKeyPair(keys);
						keys = null;
					}
				}
				else throw new IOException("Two certificates");
			}
			else if (o instanceof X509CertificateHolder) {
				try {
					X509Certificate crt = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) o);
					i = new Identity(crt);
				}
				catch (Exception e) {
					System.err.println(e.getMessage());
				}
			}
			else if (o instanceof KeyPair ) {
				if ( i != null ) i.setKeyPair((KeyPair) o);
				else keys = (KeyPair) o;
			}
			else if (o instanceof PEMKeyPair) {
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
				KeyPair keyPair = converter.getKeyPair((PEMKeyPair) o);
				if (i != null) i.setKeyPair(keyPair);
				else keys = keyPair;
			}
			else {
				throw new IOException("Unexpected PEM object: " +
						o.getClass().getName());
			}
		}

		if ( i != null ) return i;
		else if ( keys != null) return keys;
		else return null;
	}

	/**
	 * Import a directory full of files.  First import all the identities
	 * (pem), then the credentials (der) into the credential graph then any
	 * alias files into the two maps.  If keys is not null, any key pairs in
	 * PEM files are put in there.  If errors is not null, errors reading files
	 * are added indexed by filename.  This behaves slightly differently from
	 * the load_directory description in the general libabac documentation.
	 * @param d the File to read.  If it is a directory its contents are read
	 * @param keys a Collection into which to insert unmatched keys
	 * @param errors a Map from entry name to generated exception
	 */
	public void load_directory(File d, Collection<KeyPair> keys,
							   Map<String, Exception> errors) {
		Vector<File> derFiles = new Vector<File>();
		Collection<File> files = new Vector<File>();
		Map<String, Identity> ids = new TreeMap<String, Identity>();
		Map<String, KeyPair> kps = new TreeMap<String, KeyPair>();

		if (d.isDirectory() )
			for (File f : d.listFiles())
				files.add(f);
		else files.add(d);

		for (File f: files ) {
			try {
				PEMParser r = new PEMParser(new FileReader(f));
				Object o = readPEM(r);

				if ( o != null ) {
					if (o instanceof Identity) {
						Identity i = (Identity) o;
						String kid = i.getKeyID();

						if (kps.containsKey(kid) ) {
							i.setKeyPair(kps.get(kid));
							kps.remove(kid);
						}
						else if (i.getKeyPair() == null )
							ids.put(i.getKeyID(), i);

						load_id_chunk(i);
					}
					else if (o instanceof KeyPair ) {
						KeyPair kp = (KeyPair) o;
						String kid = extractKeyID(kp.getPublic());

						if (ids.containsKey(kid)) {
							Identity i = ids.get(kid);

							i.setKeyPair(kp);
							ids.remove(kid);
						}
						else {
							kps.put(kid, kp);
						}
					}
				}
				else {
					// Not a PEM file
					derFiles.add(f);
					continue;
				}
			}
			catch (Exception e ) {
				System.err.println("error for file " + f.getName() + ", error was ");
				e.printStackTrace();
				if (errors != null ) errors.put(f.getName(), e);
			}
		}
		for ( File f : derFiles ) {
			try {
				Credential[] creds = credentialFactory.parseCredential(f,
						m_identities);
				for (Credential c: creds)
					add_credential(c);

			}
			catch (Exception e ) {
				e.printStackTrace();
				if (errors != null ) errors.put(f.getName(), e);
			}
		}
	}
	/**
	 * Equivalent to load_directory(d, null, null).
	 * @param d the File to read.  If it is a directory its contents are read
	 */
	public void load_directory(File d) {
		load_directory(d, null, null);
	}
	/**
	 * Equivalent to load_directory(d, null, null).
	 * @param d the File to read.  If it is a directory its contents are read
	 * @param errors a Map from entry name to generated exception
	 */
	public void load_directory(File d, Map<String, Exception> errors) {
		load_directory(d, null, errors);
	}
	/**
	 * Equivalent to load_directory(d, null, null).
	 * @param d the File to read.  If it is a directory its contents are read
	 * @param keys a Collection into which to insert unmatched keys
	 */
	public void load_directory(File d, Collection<KeyPair> keys) {
		load_directory(d, keys, null);
	}

	/**
	 * Load from a simple rt0 text format.  A jabac extension.  The format is
	 * <pre>
	 * # comments
	 * role &lt;- role
	 * </pre>
	 *
	 * Spaces are not significant around the arrow and the tail can be as long
	 * as needed.
	 * @param s the InputStream to load
	 * @throws IOException if there is an error getting the file open or in
	 * format
	 */
	public void load_rt0(InputStream s)
			throws IOException {
		Pattern comment = Pattern.compile("(^\\s*#|^\\s*$)");
		Pattern rule = Pattern.compile("([\\w\\.]+)\\s*<-+\\s*(.+)");
		LineNumberReader r = new LineNumberReader(new InputStreamReader(s));
		String line = null;

		while ((line = r.readLine()) != null) {
			Matcher cm = comment.matcher(line);
			Matcher rm = rule.matcher(line);

			if (cm.find()) continue;
			if (rm.find())
				add_credential(new InternalCredential(new Role(rm.group(1)),
						new Role(rm.group(2))));
			else
				throw new IOException("Unexpected format: line " +
						r.getLineNumber());
		}
	}
	/**
	 * Equivalent to load_rt0(new FileInputStream(f)
	 * @param f the File to load
	 * @throws IOException if there is an error getting the file open
	 */
	public void load_rt0(File f) throws IOException {
		load_rt0(new FileInputStream(f));
	}


	/**
	 * Write the certificates that make up the context as a zip file, with an
	 * entry for each credential or identity.  The files are all zipped in a
	 * directory derived from the filename.
	 * @param s the OutputStream to write
	 * @param allIDs a boolean, if true write certificates for all Identities,
	 * whether used in signing a credential or not.
	 * @param withPrivateKeys a boolean, if true write the Identities as PEM
	 * file containing both the certificate and the private keys.
	 * @throws IOException if there is a problem writing the file.
	 */
	public void write_zip(OutputStream s, boolean allIDs,
						  boolean withPrivateKeys) throws IOException {
		ZipOutputStream z = new ZipOutputStream(s);
		Set<Identity> ids = allIDs ?  m_identities : new TreeSet<Identity>();
		String baseDir = "creds";
		int idx = baseDir.indexOf('.');


		if (idx != -1)
			baseDir = baseDir.substring(0, idx);

		int n = 0;
		for (Credential c: credentials()) {
			z.putNextEntry(new ZipEntry(baseDir + File.separator +
					"attr" + n++  + c.getSuffix()));
			c.write(z);
			z.closeEntry();
			if ( c.issuer() != null && !allIDs) ids.add(c.issuer());
		}
		for (Identity i: ids) {
			z.putNextEntry(new ZipEntry(baseDir + File.separator +
					i.getName() + ".pem"));
			i.write(z);
			if (withPrivateKeys)
				i.writePrivateKey(z);
			z.closeEntry();
		}
		z.close();
	}
	/**
	 * Equivalent to
	 * write_zip(new FileOutputStream(f), allIDs, withPrivateKeys).
	 * @param f the File to write
	 * @param allIDs a boolean, if true write certificates for all Identities,
	 * whether used in signing a credential or not.
	 * @param withPrivateKeys a boolean, if true write the Identities as PEM
	 * file containing both the certificate and the private keys.
	 * @throws IOException if there is a problem writing the file.
	 */
	public void write_zip(File f, boolean allIDs, boolean withPrivateKeys)
			throws IOException {
		write_zip(new FileOutputStream(f), allIDs, withPrivateKeys);
	}

	/**
	 * Write to a simple rt0 text format.  A jabac extension.
	 * The format is
	 * <pre>
	 * role &lt;- role
	 * </pre>
	 *
	 * @param w a Writer to print on
	 * @param useKeyIDs a boolean, true to print key IDs not mnemonics
	 */
	public void write_rt0(Writer w, boolean useKeyIDs) {
		PrintWriter pw = w instanceof PrintWriter ?
				(PrintWriter) w : new PrintWriter(w);

		for (Credential c: credentials())
			pw.println(useKeyIDs ? c.toString() : c.simpleString(this));
		pw.flush();
	}

	/**
	 * Call write_rt0 on a FileWriter derived from f.
	 * @param f the File to write to
	 * @param useKeyIDs a boolean, true to print key IDs not mnemonics
	 * @throws IOException if there is a problem writing the file.
	 */
	public void write_rt0(File f, boolean useKeyIDs) throws IOException {
		write_rt0(new FileWriter(f), useKeyIDs);
	}

	/**
	 * Equivalent to write_rt0(w, false);
	 * @param w a Writer to print on
	 */
	public void write_rt0(Writer w) { write_rt0(w, false); }

	/**
	 * Equivalent to write_rt0(f, false);
	 * @param f the File to write to
	 * @throws IOException if there is a problem writing the file.
	 */
	public void write_rt0(File f) throws IOException {
		write_rt0(new FileWriter(f), false);
	}

	/**
	 * Return this Context's CredentialFactory.
	 * @return this Context's CredentialFactory.
	 */
	public CredentialFactory getCredentialFactory() {
		return credentialFactory;
	}

	/**
	 * Set this Context's CredentialFactory.
	 * @param cf the new CredentialFactoty
	 */
	public void setCredentialFactory(CredentialFactory cf) {
		credentialFactory = cf;
	}

	/**
	 * Return a new credential supported by this Context.  It is not inserted
	 * in the Context, but will have access to the context's keyid aliases.
	 * @param head a Role, the head of the encoded ABAC statement
	 * @param tail a Role, the tail of the decoded ABAC statement
	 * @return a Credential encoding that ABAC statement
	 */
	public Credential newCredential(Role head, Role tail) {
		return credentialFactory.generateCredential(head, tail, keyMap);
	}

	/**
	 * Get to the SHA1 hash of the key.  Used by Roles and Identities to get a
	 * key ID.
	 * @param k the PublicKey to get the ID from.
	 * @return a String with the key identifier
	 */
	static String extractKeyID(PublicKey k) {
		SubjectPublicKeyInfo ki = extractSubjectPublicKeyInfo(k);
		JcaDigestCalculatorProviderBuilder dcpBuilder = new JcaDigestCalculatorProviderBuilder();
		DigestCalculator dc = null;
		try {
			DigestCalculatorProvider dcp = dcpBuilder.build();
			dc = dcp.get(CertificateID.HASH_SHA1);
		} catch (OperatorCreationException e) {
			e.printStackTrace();
		}
		X509ExtensionUtils extUtils = new X509ExtensionUtils(dc);
		SubjectKeyIdentifier id = extUtils.createSubjectKeyIdentifier(ki);

		// Now format it into a string for keeps
		Formatter fmt = new Formatter(new StringWriter());
		for (byte b: id.getKeyIdentifier())
			fmt.format("%02x", b);
		return fmt.out().toString();
	}

	/**
	 * Extratct the SubjectPublicKeyInfo.  Useful for some other encryptions,
	 * notably Certificate.make_cert().
	 * @param k the PublicKey to get the ID from.
	 * @return a String with the key identifier
	 */
	static SubjectPublicKeyInfo extractSubjectPublicKeyInfo(
			PublicKey k) {
		ASN1Sequence seq = null;
		try {
			seq = (ASN1Sequence) new ASN1InputStream(
					k.getEncoded()).readObject();
		}
		catch (IOException ie) {
			// Badly formatted key??
			return null;
		}
		return SubjectPublicKeyInfo.getInstance(seq);
	}

}
