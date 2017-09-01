package net.deterlab.abac.regression;

import java.io.*;

public abstract class RegressionTest {
    /** The name of the test */
    protected String testName;
    /** A reason if the test fails */
    protected String reason;

    /**
     * Create a new test with the give name.
     * @param name a String, the test name
     */
    protected RegressionTest(String name) {
	testName = name;
	reason = null;
    }

    /**
     * Return the test name
     * @return a String the test name
     */
    public String getName() { return testName; }

    /**
     * Return the failure reason (if any)
     * @return a String the failure reason (if any)
     */
    public String getReason() { return reason; }

    /**
     * Set the failure reason 
     * @param msg a String holding the new reason
     */
    public void setReason(String msg) { reason = msg; }

    /**
     * Carry out the test
     * @param data a File pointing to a directory that contains files the test
     * may need
     * @param scratch a File pointing to a directory that the test can use to
     * store data
     * @return a boolean, true if the test is passed
     */
    public abstract boolean runTest(File data, File scratch);
}
