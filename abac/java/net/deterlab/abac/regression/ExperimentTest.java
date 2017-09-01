package net.deterlab.abac.regression;

import java.io.*;
import java.util.*;

import net.deterlab.abac.*;

public class ExperimentTest extends RegressionTest {
    /**
     * Create a new Credential/Identity writing test for the given class of
     * credentials.
     */
     public ExperimentTest(String n) { 
	 super(n);
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
	    Identity globotron = new Identity("Globotron");
	    Identity alice = new Identity("Alice");
	    Identity bob = new Identity("Bob");
	    Vector<Identity> ids = new Vector<Identity>();
	    Vector<Credential> creds = new Vector<Credential>();
	    Collections.addAll(ids, acme, globotron, alice, bob);


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

	    for (Identity id: ids ) 
		ctxt.load_id_chunk(id);
	    for (Credential cc: creds ) 
		ctxt.load_attribute_chunk(cc);

	    /* For proof checking.  These internal credentials will be created
	     * inside the context */
	    creds.add(new InternalCredential(
		    new Role(acme.getKeyID() + ".partner.experiment_create"), 
		    new Role(globotron.getKeyID() + ".experiment_create")));
	    creds.add(new InternalCredential(
		    new Role(globotron.getKeyID() + ".admin.power_user"), 
		    new Role(alice.getKeyID() + ".power_user")));

	    Context.QueryResult q = ctxt.query(
		    acme.getKeyID() + ".experiment_create",
		    bob.getKeyID());

	    if ( !q.getSuccess() ) { 
		setReason("Could not prove Bob can create experiment");
		return false;
	    }

	    if ( creds.size() != q.getCredentials().size()) {
		for (Credential cc : q.getCredentials())
		    System.out.println(cc.simpleString(ctxt));
		setReason("Bob's proof is the wrong size");
		return false;
	    }

	    for ( Credential cc: creds )
		if ( !q.getCredentials().contains(cc)) {
		    setReason("Credential missing from proof: " + cc);
		    return false;
		}

	    q = ctxt.query(
		    acme.getKeyID() + ".experiment_create",
		    alice.getKeyID());

	    if ( q.getSuccess() ) { 
		setReason("Could prove Alice can create experiment");
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
