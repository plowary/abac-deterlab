import java.io.*;
import java.util.*;

import edu.uci.ics.jung.graph.*;

import net.deterlab.abac.Credential;
import net.deterlab.abac.CredentialFactory;
import net.deterlab.abac.Context;
import net.deterlab.abac.Role;
import net.deterlab.abac.Identity;

import java.security.KeyPair;


/**
 * Simple test of the native Java implementation of ABAC. Loads credentials
 * from an rt0 file and runs a query against them.
 */
public class GraphTest {
    public static void main(String[] args) throws IOException {
	File saveDir = new File(".");
        if (args.length < 3) {
            System.out.println("Usage: GraphTest <files> <role> <principal>");
            System.out.println("    runs the query role <-?- principal "
		    + "and prints the result");
            System.exit(1);
        }

	Context ctxt = new Context();
	Map<String, Exception> errs = new HashMap<String, Exception>();

	for (int i= 0; i < args.length-2; i++) {
	    File f = new File(args[i]);

	    try {
		if (f.isDirectory()) {
		    ctxt.load_directory(f, errs);
		    saveDir = f;
		}
		else if (f.getPath().endsWith(".pem")) 
		    ctxt.load_id_file(f);
		else if (f.getPath().endsWith(".der"))
		    ctxt.load_attribute_file(f);
		else if (f.getPath().endsWith(".zip"))
		    ctxt.load_zip(f, errs);
		else if (f.getPath().endsWith(".rt0"))
		    ctxt.load_rt0(f);
		else
		    System.out.println(f + " of unknown type");
	    }
	    catch (Exception e) {
		System.err.println("Failed to process " + f + ": " +e);
	    }
	}

	if (errs.keySet().size() > 0) System.err.println("Errors");
	for (String f: errs.keySet()) System.err.println(f + " " + errs.get(f));

	System.out.println("All read credentials");
	for (Credential c: ctxt.credentials() ) 
	    System.out.println(c.simpleString(ctxt) + " " + c.expiration());
	System.out.println("End of read credentials");

        //
        // run the query
        //

	Role role = new Role(args[args.length-2], ctxt);
	Role prin = new Role(args[args.length-1], ctxt);
	Context.QueryResult ret = ctxt.query(role.toString(), prin.toString());
	Set<Identity> ids = new TreeSet<Identity>();

	String fn = "attr";
	int n = 0;
	String suf = ".der";
	System.out.println("Result: " + ret.getSuccess());
	System.out.println("Proof");
        for (Credential c : ret.getCredentials()) {
            System.out.println(c.simpleString(ctxt));
	    if ( c.hasCertificate()) {
		c.write(new File(saveDir, fn + n++ + suf).toString());
		ids.add(c.issuer());
	    }
	}

	fn = "id";
	n = 0;
	suf = ".pem";
	System.out.println("Identities");
	for (Identity i: ids) {
	    System.out.println("ID: " + i);
	    i.write(new File(saveDir, fn + n++ + suf).toString());
	}
	try {
	    ctxt.write_zip(new File(saveDir, "testout.zip"), true, true);
	}
	catch (IOException ioe) {
	    System.err.println("Could not write ZIP: " + ioe);
	}
	System.out.println("rt0 with keyids");
	ctxt.write_rt0(new OutputStreamWriter(System.out), true);
    }
}
