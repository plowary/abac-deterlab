package net.deterlab.abac;

/**
 * An attempt to validate a credential failed because no issuer was found.  All
 * these exceptions include a cause from the underlying library that caused
 * them when possible.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class MissingIssuerException extends ABACException  {
    /**
     * Constructs a new MissingIssuerException.
     */
    public MissingIssuerException() { super(); }
    /**
     * Constructs a new MissingIssuerException with a detail message.
     * @param m a String the detail message
     */
    public MissingIssuerException(String m) { super(m); }
    /**
     * Constructs a new MissingIssuerException with a detail message and a cause.
     * @param m a String the detail message
     * @param c a Throwable the cause
     */
    public MissingIssuerException(String m, Throwable c) { super(m, c); }
    /**
     * Constructs a new MissingIssuerException with a cause.
     * @param c a Throwable the cause
     */
    public MissingIssuerException(Throwable c) { super(c); }
}

