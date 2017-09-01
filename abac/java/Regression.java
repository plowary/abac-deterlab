import java.io.*;
import java.util.*;

import net.deterlab.abac.*;
import net.deterlab.abac.regression.*;


/**
 * Simple test of the native Java implementation of ABAC. Loads credentials
 * from an rt0 file and runs a query against them.
 */
public class Regression {

    static RegressionTest[] tests = new RegressionTest[] {
	new WriteCreds("net.deterlab.abac.GENICredentialv1_0"),
	new WriteCreds("net.deterlab.abac.GENICredentialv1_1"),
	new WriteCreds("net.deterlab.abac.X509Credential"),
	new ReadCreds("e0-check-geni.xml", "Acme-check-geni.pem", 1),
	new ReadCreds("e0-check-geni11.xml", "Acme-check-geni11.pem", 1),
	new ReadCreds("e0-check-x509.der", "Acme-check-x509.pem", 1),
	new ReadCreds("priv.xml", "issuer.pem", 6),
	new ReadCreds("not_ss.xml", "not_ss.pem", 1),
	new RocketsTest("Rockets test"),
	new ExperimentTest("Experiment test"),
	new BigTest("Big test", 20),
    };

    public static void fatal(String s) {
	if (s != null ) 
	    System.out.println(s);
	//System.exit(20);
    }

    public static boolean clearDir(File d) {
	for (String fn: d.list() ) {
	    File f = new File(d, fn);

	    if ( f.isDirectory() ) 
		if ( !clearDir(f) ) return false;
	    if ( !f.delete() ) return false;
	}
	return true;
    }


    public static void main(String[] args) throws IOException {
	if (args.length < 2 ) 
	    fatal("Usage Regression regression_data_dir scratch");

	File data = new File(args[0]);
	File scratch = new File(args[1]);

	if ( !data.isDirectory() ) 
	    fatal(data + " is not a directory");
	if ( !scratch.isDirectory() ) 
	    fatal(scratch + " is not a directory");

	int i = 0;
	for (RegressionTest test: tests) {
	    File testDir = new File(scratch, "test" +i);
	    if ( testDir.isDirectory()) 
		clearDir(testDir);
	    if (!testDir.mkdir()) 
		fatal("Cannot make " +testDir);

	    if ( test.runTest(data, testDir)) 
		System.out.println(test.getName() + " Passed.");
	    else 
		fatal(test.getName() + " Failed: " + test.getReason());
	    i++;
	}
	System.exit(0);
    }
}
