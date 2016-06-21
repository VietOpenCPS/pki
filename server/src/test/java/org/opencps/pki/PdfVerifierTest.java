/**
 * 
 */
package org.opencps.pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Nguyen Van Nguyen <nguyennv@iwayvietnam.com>
 */
public class PdfVerifierTest extends TestCase {
    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";
    private static final String signImagePath = "./src/test/java/resources/signature.png";

    X509Certificate cert;
    CertificateFactory cf;
    PdfVerifier verifier;
    PdfSigner signer;

    /**
     * Create the test case
     */
    public PdfVerifierTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(PdfVerifierTest.class);
    }

    protected void setUp() throws IOException, OperatorCreationException, PKCSException, GeneralSecurityException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new PdfSigner(pdfPath, cert);
        verifier = new PdfVerifier();
        signer.setSignatureGraphic(signImagePath);
        byte[] hash = signer.computeHash();

        Security.addProvider(new BouncyCastleProvider());
        File file = new File(keyPath);
        PEMParser pemParser = new PEMParser(new FileReader(file));
        PKCS8EncryptedPrivateKeyInfo keyInfo = (PKCS8EncryptedPrivateKeyInfo) pemParser.readObject();
        pemParser.close();

        JceOpenSSLPKCS8DecryptorProviderBuilder jce = new JceOpenSSLPKCS8DecryptorProviderBuilder();
        InputDecryptorProvider decProv = jce.build("opencps".toCharArray());
        PrivateKeyInfo info = keyInfo.decryptPrivateKeyInfo(decProv);
        
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(info.getEncoded(ASN1Encoding.DER)));
        
        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");
        
        byte[] extSignature = signature.sign(hash);
        signer.sign(extSignature);
    }
    
    public void testVerifySignature() throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(signer.getSignedFilePath());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        assertTrue(names.size() > 0);
        assertEquals(names.get(0), signer.getSignatureFieldName());
        for (String name : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            assertTrue(pkcs7.verify());
        }
        
        assertFalse(verifier.verifySignature(signer.getSignedFilePath()));
    }
    
    public void testGetSignatureInfo() {
        List<CertificateInfo> infors = verifier.getSignatureInfo(signer.getSignedFilePath());
        CertificateInfo infor = infors.size() > 0 ? infors.get(0) : null;
        assertEquals("OpenCPS PKI", infor.getCommonName());
    }

}
