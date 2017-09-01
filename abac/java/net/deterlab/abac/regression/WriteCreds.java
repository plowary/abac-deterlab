package net.deterlab.abac.regression;

import java.io.*;
import java.util.*;

import net.deterlab.abac.*;

public class WriteCreds extends RegressionTest {
    protected String className;
    /**
     * Put out an identity and key into dir named by the name of the Identity
     * @param i the Identity to write
     * @param dir a File holding the destination directory
     * @throws IOException if the file writing fails
     */
    public void writeCombinedIdentity(Identity i, File dir) 
	    throws IOException {
	FileOutputStream f = new FileOutputStream(
		new File(dir,  i.getName() + ".pem"));

	i.write(f);
	i.writePrivateKey(f);
    }
    /**
     * Create a new Credential/Identity writing test for the given class of
     * credentials.
     * @param cn a String containing the binary name of the class to test
     */
     public WriteCreds(String cn) { 
	 super(cn.substring(
		     cn.lastIndexOf('.') == -1 ? 0 : cn.lastIndexOf('.') +1 ) + 
		 " credential writing test"); 
	 className = cn;
     }

    /**
     * Carry out the test.  Create credentials for the create_experiment
     * example, run the proof and make sure the correct proof is generated.
     * @param data a File pointing to a directory that contains files the test
     * may need
     * @param scratch a File pointing to a directory that the test can use to
     * store data
     * @return a boolean, true if the test is passed
     */
    public boolean runTest(File data, File scratch) {
	try {
	    Context ctxt = new Context();
	    Identity acme = new Identity("Acme", 10L*365L*24L*3600L);
	    Identity globotron = new Identity("Globotron");
	    Identity alice = new Identity("Alice");
	    Identity bob = new Identity("Bob");
	    Vector<Identity> ids = new Vector<Identity>();
	    Vector<Credential> creds = new Vector<Credential>();
	    Collections.addAll(ids, acme, globotron, alice, bob);

	    for ( Identity i: ids) 
		writeCombinedIdentity(i, scratch);

	    ctxt.setCredentialFactory(new CredentialFactory(
			new String[] { className}));

	    for (Identity id: new Identity[] { acme, globotron, alice, bob } ) 
		ctxt.load_id_chunk(id.getCertificate());

	    Credential c = ctxt.newCredential(
		    new Role(acme.getKeyID() + ".experiment_create"),
		    new Role(acme.getKeyID() + ".partner.experiment_create"));
	    c.make_cert(acme);
	    creds.add(c);
	    c = ctxt.newCredential(
		    new Role(acme.getKeyID() + ".partner"),
		    new Role(globotron.getKeyID()));
	    c.make_cert(acme);
	    creds.add(c);
	    c = ctxt.newCredential(
		    new Role(globotron.getKeyID() + ".experiment_create"),
		    new Role(globotron.getKeyID() + ".admin.power_user"));
	    c.make_cert(globotron);
	    creds.add(c);
	    c = ctxt.newCredential(
		    new Role(globotron.getKeyID() + ".admin"),
		    new Role(alice.getKeyID()));
	    c.make_cert(globotron);
	    creds.add(c);
	    c = ctxt.newCredential(
		    new Role(alice.getKeyID() + ".power_user"),
		    new Role(bob.getKeyID()));
	    c.make_cert(alice);
	    creds.add(c);

	    int i =0;
	    for (Credential cc: creds) {
		cc.write(new File(scratch,"e" + i + cc.getSuffix()).toString());
		i++;
	    }

	    Context ctxt2 = new Context();

	    ctxt2.load_directory(scratch);
	    Collection<Identity> nids = ctxt2.identities();
	    Collection<Credential> ncreds = ctxt2.credentials();

	    if ( nids.size() != ids.size()) {
		setReason("Different number of identities read " + nids.size() +
			" expected " + ids.size());
		return false;
	    }
	    for (Identity ii: ids ) 
		if ( !nids.contains(ii)) {
		    setReason("Identity " + ii + " not read successfully");
		    return false;
		}

	    if ( ncreds.size() != creds.size()) {
		setReason("Different number of credentials read " + 
			ncreds.size() + " expecting " + creds.size());
		return false;
	    }
	    for (Credential cc: creds ) 
		if ( !ncreds.contains(cc)) {
		    setReason("Credential " + cc + " not read successfully");
		    return false;
		} 

	}
	catch (Exception e) {
	    setReason(e.getMessage());
	    return false;
	}
	return true;
    }
}
