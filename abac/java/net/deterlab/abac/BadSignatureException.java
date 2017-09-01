package net.deterlab.abac;

/**
 * A Bad Signature was found on an ID or Credential.  These exceptions
 * include a cause from the underlying library that caused them when possible.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class BadSignatureException extends ABACException  {
    /**
     * Constructs a new BadSignatureException.
     */
    public BadSignatureException() { super(); }
    /**
     * Constructs a new BadSignatureException with a detail message.
     * @param m a String the detail message
     */
    public BadSignatureException(String m) { super(m); }
    /**
     * Constructs a new BadSignatureException with a detail message and a cause.
     * @param m a String the detail message
     * @param c a Throwable the cause
     */
    public BadSignatureException(String m, Throwable c) { super(m, c); }
    /**
     * Constructs a new BadSignatureException with a cause.
     * @param c a Throwable the cause
     */
    public BadSignatureException(Throwable c) { super(c); }
}

