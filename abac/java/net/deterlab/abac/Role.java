package net.deterlab.abac;

import java.util.*;

/**
 * Represents a role, which is a vertex in a Credential graph.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class Role implements Comparable {
    /** The role represnetation */
    protected String m_string;
    /** The role broken into parts between dots */
    protected String[] m_parts;
    /** The linking role from a linking Role */
    protected String m_A_r1;
    /** The linked role from a linked Role */
    protected String m_r2;
    /** A prefix of the role */
    protected String m_prefix;
    /** Prerequisite roles for an intersection role. */
    protected Role[] m_prereqs;

    /**
     * Create a role from a string. A single role must be of the format "A",
     * "A.r1", or "A.r1.r2", where A is a principal and r1 and r2 are role
     * names. This constructor also supports intersection roles: a sequence of
     * two or more roles separated by "&amp;". The whitespace surrounding &amp;
     * is arbitrary.
     *
     * If the string does not have this format, the constructor throws a
     * RuntimeException.
     *
     * @param s a String with the role name
     * @throws RuntimeException if the string is badly formatted
     */
    public Role(String s) {
        m_string = s;

        // intersection roles have at least two roles separated by "&"
        String[] isect_roles = s.split("&");

        // ordinary role
        if (isect_roles.length == 1)
            single_role();

        // intersection role: make a list of prereqs
        else {
            m_prereqs = new Role[isect_roles.length];

	    // trim() handles arbitrary whitespace
            for (int i = 0; i < isect_roles.length; ++i)
                m_prereqs[i] = new Role(isect_roles[i].trim());

            // this make is_principal etc. work properly
            m_parts = new String[0];
        }
    }

    /**
     * Create a role from the given string, converted from mnemonic strings to
     * key IDs that are known from the Context.  This is a jabac extension.
     * @param s the String containing the rile name.
     * @param c the Context in which to expand mnemonics
     * @throws RuntimeException if the string is badly formatted.
     */
    public Role(String s, Context c) {
	this(c.expandKeyID(s));
    }

    /**
     * Copy an existing role.
     * @param r the Role to copy
     */
    public Role(Role r) {
	m_string = r.m_string;
	m_A_r1 = r.m_A_r1;
	m_r2 = r.m_r2;
	m_prefix = r.m_prefix;
	m_parts = new String[r.m_parts.length];
	for (int i = 0; i < r.m_parts.length; i++) 
	    m_parts[i] = r.m_parts[i];
	m_prereqs = new Role[m_prereqs.length];
	for (int i = 0; i < r.m_prereqs.length; i++) 
	    m_prereqs[i] = new Role(r.m_prereqs[i]);
    }

    /**
     * Initialize a single non-intersection role. See constructor for details
     * of role format. Will throw RuntimeException if the role is invalid.
     * @throws RuntimeException if a role is invalid.
     */
    private void single_role() {
        m_parts = m_string.split("\\.");
        if (m_parts.length > 3)
            throw new RuntimeException("Not a valid role: " + m_string);

        // linking role: prefix is A.r1 from A.r1.r2
        if (is_linking()) {
            m_A_r1 = m_parts[0] + "." + m_parts[1];
            m_r2 = m_parts[2];
            m_prefix = m_A_r1;
        }

        // role: prefix is A from A.r1
        else if (is_role())
            m_prefix = m_parts[0];

        // principal: prefix is the whole thing
        else
            m_prefix = m_string;
    }

    /**
     * Returns true iff the role is a principal.
     * @return true iff the role is a principal.
     */
    public boolean is_principal() { return m_parts.length == 1; }

    /**
     * Returns true iff the role is a role (i.e., A.r1).
     * @return true iff the role is a role (i.e., A.r1).
     */
    public boolean is_role() { return m_parts.length == 2; }

    /**
     * Returns true iff the role is a linking role (i.e., A.r1.r2).
     * @return true iff the role is a linking role (i.e., A.r1.r2).
     */
    public boolean is_linking() { return m_parts.length == 3; }

    /**
     * Returns true iff the role represents an intersection role.
     * @return true iff the role represents an intersection role.
     */
    public boolean is_intersection() { return m_prereqs != null; }

    /**
     * Returns the first two elements of a linking role's name. This typically
     * refers to another role in the graph. This will throw a runtime
     * exception if the node is not a linking role.
     * @return the first two elements of a linking role's name.
     * @throws RuntimeException if the role is not linking
     */
    String A_r1() throws RuntimeException {
        if (!is_linking())
            throw new RuntimeException("Not a linking role");
        return m_A_r1;
    }

    /**
     * Return the last element of a linking role's name. This will throw a
     * runtime exception if the node is not a linking role.
     * @return the last element of a linking role's name.
     * @throws RuntimeException if the node is not a linking role.
     */
    String r2() throws RuntimeException {
        if (!is_linking())
            throw new RuntimeException("Not a linking role");
        return m_r2;
    }

    /**
     * Returns the principal part of a role or principal. This is everything
     * except the last element of the name.  Used by Query.
     * @return the principal part of a role or principal.
     */
    String principal_part() {
        return m_prefix;
    }

    /**
     * Return the principal
     * @return the principal
     */
    public String principal() { return m_parts.length > 0 ? m_parts[0] : null; }
    /**
     * Return the role name after the last dot
     * @return the role name
     */
    public String role_name() { 
	return m_parts.length > 1 ? m_parts[m_parts.length-1] : null;
    }
    /**
     * Return the linked role (first two parts of a linking role)
     * @return the linked role
     */
    public String linked_role() { return A_r1(); }

    /**
     * Return the linking role (the middle role of a linking role)
     * @return a String, the linking role (the middle role of a linking role)
     */
    public String linking_role() {
	return m_parts.length > 2 ? m_parts[1] : null;
    }

    /**
     * Get the roles that form the prerequisites to this intersection. Throws
     * a runtime exception if this is not an intersection role.
     * @return a Role[] of prerequisites
     * @throws ABACException if this is not an intersection role
     */
    public Role[] prereqs() throws ABACException {
        if (!is_intersection())
            throw new ABACException("Not an intersection role.");

        return m_prereqs;
    }

    /**
     * Returns a string representation of the Role.
     * @return a string representation of the Role.
     */
    public String toString() {
        return m_string;
    }

    /**
     * Returns a string representation of the Role with mnemonic names from the
     * given Context.  A jabac extension.
     * @param c A Context used to look up mnemonic names.
     * @return a string representation of the Role with mnemonic names from the
     * given Context.
     */
    public String simpleString(Context c) {
	return c.expandNickname(m_string);
    }

    /**
     * Return true if the two roles are the same.  Two Roles are the same if
     * their string representations are equal.
     * @param v2 an Object to compare
     * @return a boolean, true if the two Roles are equal.
     */
    public boolean equals(Object v2) {
        if (v2 instanceof Role)
            return m_string.equals(((Role)v2).m_string);
        return false;
    }

    /**
     * Order the roles for sorting.  Return a lexical comparison of the two
     * Roles
     * @param o an Object to compare against
     * @return -1 if this Role is before, 0 if they are the same, and 1
     *		    if this Role is after the given object.
     */
    public int compareTo(Object o) {
	if (o instanceof Role) 
	    return m_string.compareTo(((Role)o).m_string);
	else return 1;
    }

    /**
     * Returns a hash code value for the object.  It is the hash of the string
     * representation.
     * @return a hash code value for the object.
     */
    public int hashCode() {
        return m_string.hashCode();
    }

}
