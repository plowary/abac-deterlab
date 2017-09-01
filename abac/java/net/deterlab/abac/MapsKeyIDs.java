package net.deterlab.abac;

/**
 * If this class constructs a key mapping, this interface gives access to it.
 * @author <a href="http://abac.deterlab.net">ISI ABAC team</a>
 * @version 1.5
 */
public interface MapsKeyIDs {
    /**
     * Return the keymap.
     * @return a KeyIDMap, this class's keymap
     */
    public KeyIDMap getMapping();
}
