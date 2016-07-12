/**
 * 
 */
package org.opencps.pki;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.itextpdf.text.pdf.AcroFields;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.codec.Base64;
import com.itextpdf.text.pdf.security.CertificateUtil;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.TSAClient;
import com.itextpdf.text.pdf.security.TSAClientBouncyCastle;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author nguyennv
 *
 */
public class PdfPkcs7SignerTest extends TestCase {

    private static final String certPath = "./src/test/java/resources/cert.pem";
    private static final String keyPath = "./src/test/java/resources/key.pem";
    private static final String pdfPath = "./src/test/java/resources/opencps.pdf";
    private static final String signImagePath = "./src/test/java/resources/signature.png";

    private static final String encodedPkcs7 = "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";

    X509Certificate cert;
    CertificateFactory cf;
    PdfPkcs7Signer signer;

    /**
     * Create the test case
     */
    public PdfPkcs7SignerTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite(PdfPkcs7SignerTest.class);
    }

    protected void setUp() throws CertificateException, FileNotFoundException {
        cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate) cf.generateCertificate(new FileInputStream(new File(certPath)));
        signer = new PdfPkcs7Signer(pdfPath, cert);
    }
    
    public void testSignGenEncodedPKCS7() throws SignatureException, IOException, GeneralSecurityException {
        signer.setSignatureGraphic(signImagePath);
        byte[] signature = genEncodedPKCS7(signer.computeHash());
        assertTrue(signer.sign(signature));

        PdfReader reader = new PdfReader(signer.getSignedFilePath());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        assertTrue(names.size() > 0);
        assertEquals(names.get(0), signer.getSignatureFieldName());
        for (String name : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            assertTrue(pkcs7.verify());
        }
    }
    
    public void testSignWithInvalidEncodedPKCS7() {
        try {
            signer.setSignatureGraphic(signImagePath);
            signer.setSignatureFieldName("Signature1");
            signer.sign(Base64.decode(encodedPkcs7));
            fail("Missing exception");
        } catch (Exception ex) {
            assertEquals("Encoded pkcs7 is invalid. The certificate from signer not equal pkcs7's certificate", ex.getMessage());
        }
    }

    public void testSignWithEncodedPKCS7() throws IOException, GeneralSecurityException {
        PdfPKCS7 sgn = new PdfPKCS7(Base64.decode(encodedPkcs7), PdfName.ADBE_PKCS7_DETACHED, "BC");
        X509Certificate signCert = sgn.getSigningCertificate();

        PdfPkcs7Signer signer = new PdfPkcs7Signer(pdfPath, signCert);
        signer.computeHash();

        signer.setSignatureGraphic(signImagePath);
        signer.sign(Base64.decode(encodedPkcs7));

        PdfReader reader = new PdfReader(signer.getSignedFilePath());
        AcroFields fields = reader.getAcroFields();
        ArrayList<String> names = fields.getSignatureNames();
        assertTrue(names.size() > 0);
        assertEquals(names.get(0), signer.getSignatureFieldName());
        for (String name : names) {
            PdfPKCS7 pkcs7 = fields.verifySignature(name);
            assertFalse(pkcs7.verify());
        }
    }
    
    protected byte[] genEncodedPKCS7(byte[] hash) throws IOException, GeneralSecurityException {
        PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(keyPath)));
        PemObject pemObject = pemReader.readPemObject();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = factory.generatePrivate(privKeySpec);
        pemReader.close();

        PdfPKCS7 sgn = new PdfPKCS7(null, new Certificate[] { cert }, signer.getHashAlgorithm().toString(), null, signer.getExternalDigest(), false);

        PrivateKeySignature signature = new PrivateKeySignature(privateKey, signer.getHashAlgorithm().toString(), "BC");
        byte[] extSignature = signature.sign(sgn.getAuthenticatedAttributeBytes(hash, null, null, CryptoStandard.CMS));

        sgn.setExternalDigest(extSignature, null, cert.getPublicKey().getAlgorithm());

        TSAClient tsaClient = null;
        String tsaUrl = CertificateUtil.getTSAURL(cert);
        if (tsaUrl != null) {
            tsaClient = new TSAClientBouncyCastle(tsaUrl);
        }
        
        return sgn.getEncodedPKCS7(hash, tsaClient, null, null, CryptoStandard.CMS);
    }

}
