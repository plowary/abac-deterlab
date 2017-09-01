import org.bouncycastle.asn1.util.Dump;

public class Dumper {
    static public void main(String[] args) {
	try {
	    org.bouncycastle.asn1.util.Dump.main(args);
	}
	catch (Exception e) {
	    System.err.println(e);
	    System.exit(20);
	}
	System.exit(0);
    }
}
