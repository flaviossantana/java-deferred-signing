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
 * Documentação:
 * https://manual-integracao-assinatura-digital.readthedocs.io/en/2.8/iniciarintegracao.html
 *
 * iText7 deferred signed pdf document shows “the document has been altered or corrupted since the signature was applied”
 * https://stackoverflow.com/questions/66099648/itext7-deferred-signed-pdf-document-shows-the-document-has-been-altered-or-corr
 */

public class DeferredSigning {

    public static final String SRC = "./src/test/resources/pdfs/doc-blank.pdf";

    public static final String DEST = "./target/signatures/";
    public static final String TEMP = "./target/signatures/doc-empty-sig.pdf";

    protected static final String[] RESULT_FILES = new String[]{
            "doc-sig-ok.pdf"
    };

    /**
     * Certificado PEM recuperado do serviço:
     * https://assinatura-api.staging.iti.br/externo/v2/certificadoPublico
     */
    public static final String CERTIFICADO_PEM = "encryption/certificado-digital.pem";


    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certificadoPem = DeferredSigning.class.getClassLoader().getResourceAsStream(CERTIFICADO_PEM);
        Certificate[] certificate = new Certificate[]{cf.generateCertificate(certificadoPem)};

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
                .setReasonCaption("Razão: ")
                .setReason("INTEGRAÇÃO GOV BR")
                .setLocationCaption("Orgão: ")
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

        /**
         * Hash SHA256 codificado em Base64 que será enviado para o serviço:
         * https://assinatura-api.staging.iti.br/externo/v2/assinarRaw
         */
        System.out.println("{\"hashBase64\": \"" + documentHashBase64 + "\"" + "}");

    }

    public void signDocument(String docEmptySign, String dest, String fieldName, Certificate[] certificate)
            throws IOException, GeneralSecurityException {

        /**
         * Assinatura digital SHA256-RSA codificada em Base64 na retornada do serviço:
         * https://assinatura-api.staging.iti.br/externo/v2/assinarRaw
         */
        String assinarRaw = "sFq2PCt5OIrICLEokDv+HrS3hvQPMERlWq/Lx6kipMm6Ti6VMU8vJEv8fd7XeU/7uLXV6z9ezk9HPtGKfMQBQPIzkechTAunbtxaMGSyr+qrxwyytktx4HsyzxcQIdIngMi3uz4PxnArr10bDZKB5WtmMBLoE3dZcNrzcefNkOcSbKSxwH76yImHip27pxAmuYWTSae9DqVEbaBYLjGWSJGflLTzUv2JZPPT4lCmyNxtpM3Q5Lyz5gzMDG9gDcGGsDVaf/0JUNE7VArH/nwR8Co8z3cADTfdstbC5ZcPmpOePSOjO53C6Gd07IQWy8doDQT80knHiXNJAzqXl17LGg==";

        try (PdfReader reader = new PdfReader(docEmptySign)) {
            try (FileOutputStream os = new FileOutputStream(dest)) {
                BouncyCastleDigest digest = new BouncyCastleDigest();
                PdfPKCS7 sgn = new PdfPKCS7(null, certificate, "SHA256", null, digest, false);

                sgn.setExternalDigest(Base64.getDecoder().decode(assinarRaw.getBytes()), null, "RSA");

                byte[] encodedPKCS7 = sgn.getEncodedPKCS7(null, PdfSigner.CryptoStandard.CMS, null, null, null);


                PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());

                IExternalSignatureContainer external = new CustomExternalSignature(encodedPKCS7);
                signer.signDeferred(signer.getDocument(), fieldName, os, external);
            }
        }

    }

    class CustomExternalSignature implements IExternalSignatureContainer {

        protected byte[] encodedSig;

        public CustomExternalSignature(byte[] encodedSig) {
            this.encodedSig = encodedSig;
        }

        public byte[] sign(InputStream is) {
            return this.encodedSig;
        }

        public void modifySigningDictionary(PdfDictionary signDic) {
            // Do nothing because of X and Y.
        }
    }

    public class PreSignatureContainer implements IExternalSignatureContainer {
        private PdfDictionary sigDic;
        private byte[] hash;

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
            return this.hash;
        }
    }

}
