package net.deterlab.abac.regression;

import java.io.*;
import java.util.*;

import net.deterlab.abac.*;

public class RocketsTest extends RegressionTest {
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
     */
     public RocketsTest(String name) { 
	 super(name);
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
	    Identity acme = new Identity("Acme");
	    Identity warnerBros = new Identity("WarnerBros");
	    Identity batman = new Identity("Batman");
	    Identity coyote = new Identity("Coyote");
	    ArrayList<Credential> inProof = new ArrayList<Credential>();

	    ctxt.load_id_chunk(acme);
	    ctxt.load_id_chunk(warnerBros);
	    ctxt.load_id_chunk(batman);
	    ctxt.load_id_chunk(coyote);

	    Credential c = ctxt.newCredential(
		    new Role(acme.getKeyID() + ".buy_rockets"),
		    new Role(acme.getKeyID() + ".preferred_customer & " +
			warnerBros.getKeyID() + ".character"));
	    c.make_cert(acme);
	    ctxt.load_attribute_chunk(c);
	    inProof.add(c);
	    c = ctxt.newCredential(
		    new Role(acme.getKeyID() + ".preferred_customer"),
		    new Role(coyote.getKeyID()));
	    c.make_cert(acme);
	    ctxt.load_attribute_chunk(c);
	    inProof.add(c);
	    c = ctxt.newCredential(
		    new Role(acme.getKeyID() + ".preferred_customer"),
		    new Role(batman.getKeyID()));
	    c.make_cert(acme);
	    ctxt.load_attribute_chunk(c);
	    c = ctxt.newCredential(
		    new Role(warnerBros.getKeyID() + ".character"),
		    new Role(coyote.getKeyID()));
	    c.make_cert(warnerBros);
	    ctxt.load_attribute_chunk(c);
	    inProof.add(c);

	    /* For checking only.  An internal credential of this form will
	     * come out of the Context in the proof. */
	    c = new InternalCredential(
		    new Role(acme.getKeyID() + ".preferred_customer & " +
			warnerBros.getKeyID() + ".character"), 
		    new Role(coyote.getKeyID()));
	    inProof.add(c);

	    Context.QueryResult q = ctxt.query(
		    acme.getKeyID() + ".buy_rockets",
		    coyote.getKeyID());

	    if ( !q.getSuccess()) {
		setReason("Coyote can buy rockets proof failed?");
		return false;
	    }
	    if ( inProof.size() != q.getCredentials().size()) {
		setReason("Coyote can buy rockets proof is the wrong size");
		return false;
	    }

	    for (Credential cc: inProof)
		if ( !q.getCredentials().contains(cc)) {
		    setReason("Coyote can buy rockets proof missing cred "+cc);
		    return false;
		}

	    q = ctxt.query(acme.getKeyID() + ".buy_rockets",
		    batman.getKeyID());
	    if ( q.getSuccess()) {
		setReason("Batman can buy rockets ?");
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
