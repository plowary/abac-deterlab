package net.deterlab.abac;

import java.io.*;
import java.util.*;

/**
 * This class parses or generates credentials.  The parser produces one or more
 * Credentials.  The generator produces exactly one credential. Each class that
 * wants to be parsed and generated needs to export a static method that
 * returns one of these.  For credentials that parse 1 credential to 1 input it
 * will be a wrapper around a constructor.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public abstract class CredentialFactorySpecialization {
    /**
     * Parse one or more Credentials from the given input and IDs.  The
     * sub-type of Credential returned is up to this class.
     * @param is an InputStream to be parsed
     * @param ids a Collection of Identity s to use in validating credentials.
     * @return an array of Credentials
     * @throws ABACException on parsing problems
     */
    public abstract Credential[] parseCredential(InputStream is, 
	    Collection<Identity> ids) throws ABACException;

    /**
     * Return an object derived from a credential with the given roles.
     * @param head a Role, the head of the encoded ABAC statement
     * @param tail a Role, the tail of the decoded ABAC statement
     * @param aliases a KeyIDMap containing aliases for keyids
     * @return a Credential encoding that ABAC statement
     */
    public abstract Credential generateCredential(Role head, Role tail, 
	    KeyIDMap aliases);
}
