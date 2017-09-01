package net.deterlab.abac.regression;

import java.io.*;
import java.util.*;

import net.deterlab.abac.*;

public class BigTest extends RegressionTest {
    protected int nids;
    /**
     * Create a new Credential/Identity writing test for the given class of
     * credentials.
     */
     public BigTest(String n, int ids) { 
	 super(n);
	 nids = ids;
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
	    Vector<Identity> ids = new Vector<Identity>();

	    for (int i =0; i< nids; i++) {
		Identity id = new Identity("Identity" + i);
		ids.add(id);
		ctxt.load_id_chunk(id);
	    }

	    for (int i = 0 ; i < nids; i++ ) {
		for ( int j = 0; j < nids ; j++ ) {
		    Credential c = ctxt.newCredential(
			    new Role(ids.elementAt(i).getKeyID() + ".role"+j),
			    (j > 0) ?  
				new Role(ids.elementAt(i).getKeyID() + 
				    ".role"+(j-1)) :
				new Role(ids.elementAt(i).getKeyID()));
		    c.make_cert(ids.elementAt(i));
		    ctxt.load_attribute_chunk(c);

		    c = ctxt.newCredential(
			    new Role(ids.elementAt(i).getKeyID() + ".role"+j),
				new Role(ids.elementAt((i+1)%nids).getKeyID() + 
				    ".role"+j));
		    c.make_cert(ids.elementAt(i));
		    ctxt.load_attribute_chunk(c);
		}
	    }
	    Context.QueryResult q = ctxt.query(
		    ids.elementAt(nids-1).getKeyID() + ".role" + (nids-1), 
		    ids.elementAt(0).getKeyID());
	    if (!q.getSuccess() ) {
		setReason("Cannot prove " +
		    new Role(ids.elementAt(nids-1).getKeyID() 
			+ ".role" + (nids-1)).simpleString(ctxt) + " <- " +
		    new Role(ids.elementAt(0).getKeyID()).simpleString(ctxt));
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
