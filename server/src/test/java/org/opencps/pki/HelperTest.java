/**
 * 
 */
package org.opencps.pki;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author nguyennv
 *
 */
public class HelperTest extends TestCase {

    /**
     * Create the test case
     */
    public HelperTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(HelperTest.class);
    }
    
    public void testStripFileExtension() {
        assertEquals("/tmp/test", Helper.stripFileExtension("/tmp/test.txt"));
    }

}
