package com.itextpdf.samples.signatures.chapter04;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;

/**
 * iText7 deferred signed pdf document shows “the document has been altered or corrupted since the signature was applied”
 * https://stackoverflow.com/questions/66099648/itext7-deferred-signed-pdf-document-shows-the-document-has-been-altered-or-corr
 */

public class DeferredSigning {

    public static final String SRC = "./src/test/resources/pdfs/doc-blank.pdf";

    public static final String DEST = "./target/signatures/";
    public static final String TEMP = "./target/signatures/doc-empty-sig.pdf";

    public static final String CERTIFICADO_PEM = "encryption/certificado-digital.pem";

    protected static final String[] RESULT_FILES = new String[]{
            "doc-sig-ok.pdf"
    };

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream inputStream = DeferredSigning.class.getClassLoader().getResourceAsStream(CERTIFICADO_PEM);
        Certificate[] certificate = new Certificate[] { cf.generateCertificate(inputStream) };

        DeferredSigning app = new DeferredSigning();
        app.emptySignature(SRC, TEMP, "sig", certificate);
        app.signDocument(TEMP, DEST + RESULT_FILES[0], "sig", certificate);
    }

    public void emptySignature(String src, String dest, String fieldname, Certificate[] certificate)
            throws IOException, GeneralSecurityException {

        PdfReader reader = new PdfReader(src);
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance
                .setPageRect(new Rectangle(36, 36, 300, 100))
                .setReason("FLAVIO SANTANA")
                .setLocation("DETRAN GO")
                .setPageNumber(1)
                .setCertificate(certificate[0]);

        signer.setFieldName(fieldname);

        /* ExternalBlankSignatureContainer constructor will create the PdfDictionary for the signature
         * information and will insert the /Filter and /SubFilter values into this dictionary.
         * It will leave just a blank placeholder for the signature that is to be inserted later.
         */
        PreSignatureContainer container = new PreSignatureContainer(PdfName.Adobe_PPKLite,
                PdfName.Adbe_pkcs7_detached);

        // Sign the document using an external container.
        // 8192 is the size of the empty signature placeholder.
        signer.signExternalContainer(container, 8192);

        byte[] documentHash = container.getHash();
        String documentHashBase64 = Base64.getEncoder().encodeToString(documentHash);

        System.out.println("{\"hashBase64\": \"" + documentHashBase64 + "\"" + "}");

    }

    public void signDocument(String docEmptySign, String dest, String fieldName, Certificate[] certificate)
            throws IOException, GeneralSecurityException {

        String assinarRaw = "Hn+cMEFu3il3g+hYRG2dQyzbzrHaDZDoRJm3kn/7X6kESnXUYi6JUcj7s+QhAhkK5K0UjQ+v9HsHabbrLk5/E3vSG3o6zNMVmtCVa2tLqj+d+FVyWnAh4eGQW643wF3RdjBMrDUoemu0WLzhq1qeI/6I9T7mmQzGJPZpo9T2xqgs1dlYGqzorPf422ZOS/0ghuoUEA9RQ6mXnK/aAqwhfi7k312YfCPIZMTWzascVGViMPiaeWA8aTv592+KhFpQM+Ehpq4j4hvBPcfw27oVW3SCVi50TEesZRraC4tSZGGGwvR6jPG/Z03PZ2k/FLBsE3xc0+PYkEQIZMNH5AoYTQ==";
//      String assinarPKCS7 = "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";

        PdfReader reader = new PdfReader(docEmptySign);
        FileOutputStream os = new FileOutputStream(dest);

        BouncyCastleDigest digest = new BouncyCastleDigest();
        PdfPKCS7 sgn = new PdfPKCS7(null, certificate, "SHA256", null, digest, false);

        sgn.setExternalDigest(Base64.getDecoder().decode(assinarRaw.getBytes()), null, "RSA");

        byte[] encodedPKCS7 = sgn.getEncodedPKCS7(null, PdfSigner.CryptoStandard.CMS, null, null, null);


        PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());

        IExternalSignatureContainer external = new CustomExternalSignature(encodedPKCS7);
        signer.signDeferred(signer.getDocument(), fieldName, os, external);

        os.close();
        reader.close();

    }

    class CustomExternalSignature implements IExternalSignatureContainer {

        protected byte[] encodedSig;

        public CustomExternalSignature(byte[] encodedSig) {
            this.encodedSig = encodedSig;
        }

        public byte[] sign(InputStream is) throws GeneralSecurityException {
            return this.encodedSig;
        }

        public void modifySigningDictionary(PdfDictionary signDic) {
            // Do nothing because of X and Y.
        }
    }

    public class PreSignatureContainer implements IExternalSignatureContainer {
        private PdfDictionary sigDic;
        private byte hash[];

        public PreSignatureContainer(PdfName filter, PdfName subFilter) {
            sigDic = new PdfDictionary();
            sigDic.put(PdfName.Filter, filter);
            sigDic.put(PdfName.SubFilter, subFilter);
        }

        @Override
        public byte[] sign(InputStream data) throws GeneralSecurityException {
            String hashAlgorithm = "SHA256";
            BouncyCastleDigest digest = new BouncyCastleDigest();

            try {
                this.hash = DigestAlgorithms.digest(data, digest.getMessageDigest(hashAlgorithm));
            } catch (IOException e) {
                throw new GeneralSecurityException("PreSignatureContainer signing exception", e);
            }

            return new byte[0];
        }

        @Override
        public void modifySigningDictionary(PdfDictionary signDic) {
            signDic.putAll(sigDic);
        }

        public byte[] getHash() {
            return hash;
        }
    }

}
