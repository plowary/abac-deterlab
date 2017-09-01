package net.deterlab.abac;

import edu.uci.ics.jung.graph.*;
import edu.uci.ics.jung.graph.util.*;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;
import java.security.*;
import java.security.cert.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.*;
import org.bouncycastle.openssl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Represents a global graph of credentials in the form of principals and
 * attributes.  Contains the identities and credentials that can be used in a
 * proof.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public class KeyIDMap {
    /** Translation from nickname to issuer pubkey identifier */
    protected Map<String, String> nicknames;
    /** Translation from issuer pubkey identifier to nickname */
    protected Map<String, String> keys;

    /**
     * Create an empty Context.
     */
    public KeyIDMap() {
	nicknames = new TreeMap<String, String>();
	keys = new TreeMap<String, String>();
    }

    /**
     * Create a KeyIDMap from another KeyIDMap
     * @param k the KeyIDMap to copy
     */
    public KeyIDMap(KeyIDMap k) {
	nicknames = new TreeMap<String, String>(k.nicknames);
	keys = new TreeMap<String, String>(k.keys);
    }

    /**
     * Add a mapping from keyid to nickname and back. If the keyid is already
     * assigned a nickname, this fails.  If the nickname is already assigned to
     * another key, it is disambiguated from other known nicknames.  The
     * nickname that is assigned is returned, or null on failure.
     * @param keyid a String, the keyid to map
     * @param nick a String, the nickname to assign
     * @return a String, the nickname actually assigned
     */
    public String addNickname(String keyid, String nick) { 
	String name = nick;
	int n= 1;

	if ( keyid == null || nick == null) return null;
	if ( keys.containsKey(keyid) ) return null;

	while (nicknames.containsKey(name)) {
	    name = nick + n++;
	}
	nicknames.put(name, keyid);
	keys.put(keyid, name);
	return name;
    }

    /**
     * Return the nickname of this keyid, if any.
     * @param keyid the keyID to look up
     * @return the nickname of this keyid, or null if it is unknown.
     */
    public String keyToNickname(String keyid) {
	return keys.get(keyid);
    }

    /**
     * Return the keyis of this nickname, if any.
     * @param nick the nickname to look up
     * @return the keyid of this nickname, or null if it is unknown.
     */
    public String nicknameToKey(String nick) {
	return nicknames.get(nick);
    }

    /**
     * Return all the keyIDs this map knows.
     * @return a Set of Strings containing all the keyIDs this map knows.
     */
    public Set<String> getKeys() {
	return keys.keySet();
    }

    /**
     * Remove the mapping associated with this keyid.
     * @param keyid a String to remove from both maps as a keyis
     * @return a boolean, true if the keyid was found and removed
     */
    public boolean clearKey(String keyid) {
	String nick = keys.get(keyid);

	if ( nick == null ) return false;

	nicknames.remove(nick);
	keys.remove(keyid);
	return true;
    }

    /**
     * Remove the mapping associated with this nickname.
     * @param nick a String to remove from both maps as a nickname
     * @return a boolean, true if the nickname was found and removed
     */
    public boolean clearNickname(String nick) {
	String keyid = nicknames.get(nick);

	if ( keyid == null ) return false;

	nicknames.remove(nick);
	keys.remove(keyid);
	return true;
    }

    /**
     * Merge the mapping into this one.  If overwrite is true, entries in km
     * overwrite entries in this.
     * @param km the KeyIDMap to merge
     * @param overwrite a boolean, true if km entries overwrite this map
     */
    public void merge(KeyIDMap km, boolean overwrite) {
	for (String k : km.getKeys()) {
	    if (keyToNickname(k) != null) {
		if ( overwrite) clearKey(k);
		else continue;
	    }
	    addNickname(k, km.keyToNickname(k));
	}
    }

    /**
     * Translate either keys to nicknames or vice versa.  Break the string into
     * space separated tokens and then each of them into period separated
     * strings.  If any of the smallest strings is in the map, replace it with
     * the value.
     * @param is the string to manipulate
     * @param m the Map containing translations
     * @return the string after modification
     */
    protected String replace(String is, Map<String, String> m) {
	String rv = "";
	for (String tok: is.split(" ")) {
	    String term = "";
	    for (String s: tok.split("\\.")) {
		String next = m.containsKey(s) ? m.get(s) : s;

		if (term.isEmpty()) term = next;
		else term += "." + next;
	    }
	    if (rv.isEmpty()) rv = term;
	    else rv += " " + term;
	}
	return rv;
    }

    /**
     * Expand menmonic names in a Role string, e.g. the CN of the issuer
     * certificate, into the full key ID.  Used internally by Roles to provide
     * transparent use of mnemonics
     * @param s the string to expand
     * @return the String after expansion.
     */
    public String expandKeyID(String s) { return replace(s, nicknames); }
    /**
     * Convert key IDs to  menmonic names in a Role string.  The inverse of
     * expandKeyID.
     * @param s the string to expand
     * @return the String after expansion.
     */
    public String expandNickname(String s) { return replace(s, keys); }

}
