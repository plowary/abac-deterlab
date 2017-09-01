package net.deterlab.abac;

/**
 * A Certificate (ID or Credential) was invalid for a reason other than bad
 * signature or missing issuer, usually something that is not a certificate at
 * all was parsed.  These exceptions include a cause from the underlying
 * library that caused them when possible.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class CertInvalidException extends ABACException  {
    /**
     * Constructs a new CertInvalidException.
     */
    public CertInvalidException() { super(); }
    /**
     * Constructs a new CertInvalidException with a detail message.
     * @param m a String the detail message
     */
    public CertInvalidException(String m) { super(m); }
    /**
     * Constructs a new CertInvalidException with a detail message and a cause.
     * @param m a String the detail message
     * @param c a Throwable the cause
     */
    public CertInvalidException(String m, Throwable c) { super(m, c); }
    /**
     * Constructs a new CertInvalidException with a cause.
     * @param c a Throwable the cause
     */
    public CertInvalidException(Throwable c) { super(c); }
}

