package net.deterlab.abac;

/**
 * Superclass for all jabac Exceptions passed to the user; some generic errors
 * also throw ABACExceptions.  These exceptions include a cause from the
 * underlying library that caused them when
 * possible.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class ABACException extends Exception  {
    /**
     * Constructs a new ABACException.
     */
    public ABACException() { super(); }
    /**
     * Constructs a new ABACException with a detail message.
     * @param m a String the detail message
     */
    public ABACException(String m) { super(m); }
    /**
     * Constructs a new ABACException with a detail message and a cause.
     * @param m a String the detail message
     * @param c a Throwable the cause
     */
    public ABACException(String m, Throwable c) { super(m, c); }
    /**
     * Constructs a new ABACException with a cause.
     * @param c a Throwable the cause
     */
    public ABACException(Throwable c) { super(c); }
}

