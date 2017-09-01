package net.deterlab.abac.regression;

import java.io.*;
import java.util.*;

import net.deterlab.abac.*;

public class ReadCreds extends RegressionTest {
    /** The credential to read */
    protected String credName;
    /** The ID to read */
    protected String idName;
    /** The expected number of creds to import from credname */
    protected int ncreds;
    /** The expected number of identities in the credential */
    protected int nids;
    /**
     * Create a new Credential/Identity reading test for the given credential
     * file name.
     * @param cname a String containing filename of the credential
     * @param idname a String containing filename of the Identity
     * @param nc an int containing number of credentials created from cname
     * @param ni an int containing number of identities expected in cname
     */
     public ReadCreds(String cname, String idname, int nc, int ni) { 
	 super("Read credential " +cname);
	 credName = cname;
	 idName = idname;
	 ncreds = nc;
	 nids = ni;
     }

    /**
     * Create a new Credential/Identity reading test for the given credential
     * file name.
     * @param cname a String containing filename of the credential
     * @param idname a String containing filename of the Identity
     * @param nc an int containing number of credentials created from cname
     */
     public ReadCreds(String cname, String idname, int nc) { 
	 this(cname, idname, nc, 1);
     }

     /**
      * Copy the bytes from from to to.
      * @param from a File, the source file
      * @param to a File, the destination file.
      * @throws IOException if something goes wrong
      */
     public void copyFile(File from, File to) throws IOException {
	 FileInputStream fromStream = new FileInputStream(from);
	 FileOutputStream toStream = new FileOutputStream(to);
	 byte[] buf = new byte[4096];
	 int len = 0;

	 while ( (len = fromStream.read(buf)) != -1 ) 
	     toStream.write(buf, 0, len);
	 fromStream.close();
	 toStream.close();
     }

     /**
      * Compare the contents of a and b, returning true if they all match.
      * @param a a File to be compared
      * @param b a File to be compared
      * @return true if all bytes are the same
      * @throws IOException if there is a problem reading the files
      */
     public boolean compareFile(File a, File b) throws IOException {
	 FileInputStream aStream = new FileInputStream(a);
	 FileInputStream bStream = new FileInputStream(b);
	 byte[] aBuf = new byte[4096];
	 byte[] bBuf = new byte[4096];
	 int len = 0;

	 while ( (len = aStream.read(aBuf)) != -1 ) {
	     int l = 0;
	     int t = 0;
	     while ( (t = bStream.read(bBuf, l, len - l)) != -1 && l < len ) 
		 l += t;
	     if (l != len) return false;
	     for (int i=0 ; i< len; i++) 
		 if (aBuf[i] != bBuf[i]) return false;
	 }
	 return true;
     }


    /**
     * Copy credName and idName from scratch, load them into a context, making
     * sure the right number of credentials come out, and save them to scratch.
     * Compare the input and output files.
     * @param data a File pointing to a directory that contains files the test
     * may need
     * @param scratch a File pointing to a directory that the test can use to
     * store data
     * @return a boolean, true if the test is passed
     */
    public boolean runTest(File data, File scratch) {
	try {
	    Context ctxt = new Context();
	    File origCred = new File(scratch, credName);
	    File origID = new File(scratch, idName);

	    if ( credName != null ) 
		copyFile(new File(data, credName), origCred);
	    if ( idName != null ) 
		copyFile(new File(data, idName), origID);


	    ctxt.load_directory(scratch);
	    Collection<Identity> ids = ctxt.identities();
	    Collection<Credential> creds = ctxt.credentials();

	    if ( ids.size() != nids) {
		setReason("Different number of identities read.  Got " + 
			ids.size() + " expected: " + nids);
		return false;
	    }
	    if ( creds.size() != ncreds) {
		setReason("Different number of credentials read. Got: " + 
			creds.size() + " expected: " + ncreds);
		return false;
	    }
	    File credFn = new File(scratch, credName + ".new");
	    File idFn = new File(scratch, idName + ".new");

	    for ( Identity i: ids ) 
		i.write(idFn.toString());

	    for (Credential c: creds )
		c.write(credFn.toString());

	    if ( ! compareFile(credFn, origCred)) 
		setReason("Credential files differ");
	    if ( idName != null && ! compareFile(idFn, origID)) 
		setReason("Identity files differ");

	}
	catch (Exception e) {
	    setReason(e.getMessage());
	    return false;
	}
	return true;
    }
}
