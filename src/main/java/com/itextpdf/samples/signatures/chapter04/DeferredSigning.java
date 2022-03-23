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
 * https://manual-integracao-assinatura-digital.readthedocs.io/en/latest/iniciarintegracao.html
 *
 * iText7 deferred signed pdf document shows “the document has been altered or corrupted since the signature was applied”
 * https://stackoverflow.com/questions/66099648/itext7-deferred-signed-pdf-document-shows-the-document-has-been-altered-or-corr
 * https://stackoverflow.com/questions/67889692/java-itext7-deferred-with-sign-prefix-producing-invalid-signed-pdf
 *
 * Convert File to Hex:
 * https://mkyong.com/java/how-to-convert-file-to-hex-in-java/
 */

public class DeferredSigning {

    public static final String DEST = "./target/signatures/";
    public static final String RESULT_FILES = "doc-sig-ok.pdf";
    public static final String SRC = "./src/test/resources/pdfs/doc-blank.pdf";

    /**
     * Documentos que foi enviado o hash para a API do GOV.BR
     * e foi retornado o arquivo response.p7s que esta no diretorio:
     * encryption/response.p7s
     */
    public static final String TEMP = "./src/test/resources/pdfs/doc-empty-sig.pdf";

    /**
     * Certificado PEM recuperado do serviço:
     * https://assinatura-api.staging.iti.br/externo/v2/certificadoPublico
     */
    public static final String CERTIFICADO_PEM = "encryption/certificado-digital.pem";

    /**
     * Arquivo contendo o pacote PKCS#7 com a assinatura digital do hash SHA256-RSA e com o certificado público do usuário.
     * Retornado no serviço:
     * https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7
     */
    public static final String PKCS7 = "encryption/response.p7s";

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        File file = new File(DEST);
        file.mkdirs();

        BouncyCastleProvider providerBC = new BouncyCastleProvider();
        Security.addProvider(providerBC);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream certificadoPem = DeferredSigning.class.getClassLoader().getResourceAsStream(CERTIFICADO_PEM);
        Certificate[] certificate = new Certificate[]{cf.generateCertificate(certificadoPem)};

        DeferredSigning app = new DeferredSigning();
//      app.emptySignature(SRC, TEMP, "sig", certificate);
        app.signDocument(TEMP, DEST + RESULT_FILES, "sig", certificate);
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

        /**
         * ExternalBlankSignatureContainer constructor will create the PdfDictionary for the signature
         * information and will insert the /Filter and /SubFilter values into this dictionary.
         * It will leave just a blank placeholder for the signature that is to be inserted later.
         */
        PreSignatureContainer container = new PreSignatureContainer(
                PdfName.Adobe_PPKLite,
                PdfName.Adbe_pkcs7_detached
        );

        // Sign the document using an external container.
        // 8192 is the size of the empty signature placeholder.
        signer.signExternalContainer(container, 20000);

        byte[] documentHash = container.getHash();
        String documentHashBase64 = Base64.getEncoder().encodeToString(documentHash);

        /**
         * Hash SHA256 codificado em Base64 que será enviado para o serviço:
         * https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7
         */
        System.out.println("{\"hashBase64\": \"" + documentHashBase64 + "\"" + "}");

    }

    public void signDocument(
            String docEmptySign,
            String dest,
            String fieldName,
            Certificate[] certificate)
            throws IOException, GeneralSecurityException {

        /**
         * Assinatura digital de um HASH SHA-256 em PKCS#7
         * https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7
         */
        InputStream pkcs7IS = DeferredSigning.class.getClassLoader().getResourceAsStream(PKCS7);

        /**
         * O resultado da operação assinarPKCS7 deve ser codificado em hexadecimal e
         * embutido no espaço que foi previamente alocado no documento no passo 1.
         */
        String pkcs7Hex = convertPkcs7ToHex(pkcs7IS);

        System.out.println(pkcs7Hex);

        /**
         * Hash SHA256 codificado em Base64 que foi enviado para o serviço:
         * https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7
         */
        byte[] documentHash = Base64.getDecoder().decode("thBb+H4cyK/oBx/Z7w1Zu0UFz0ue1RZXS2FHiHzuMWM=");

        try (PdfReader reader = new PdfReader(docEmptySign)) {
            try (FileOutputStream os = new FileOutputStream(dest)) {

                BouncyCastleDigest digest = new BouncyCastleDigest();
                Security.addProvider(new BouncyCastleProvider());

                PdfPKCS7 sgn = new PdfPKCS7(
                        null,
                        certificate,
                        "SHA256",
                        null,
                        digest,
                        false);

                sgn.setExternalDigest(
                        pkcs7Hex.getBytes(),
                        null,
                        "RSA");


                byte[] encodedPKCS7 = sgn.getEncodedPKCS7(
                        documentHash,
                        PdfSigner.CryptoStandard.CADES,
                        null,
                        null,
                        null);


                PdfSigner signer = new PdfSigner(reader, os, new StampingProperties());

                IExternalSignatureContainer external = new CustomExternalSignature(encodedPKCS7);

                signer.signDeferred(
                        signer.getDocument(),
                        fieldName,
                        os,
                        external);
            }
        }

    }

    public static String convertPkcs7ToHex(InputStream pkcs7IS) throws IOException {

        final String UNKNOWN_CHARACTER = ".";

        StringBuilder result = new StringBuilder();
        StringBuilder hex = new StringBuilder();
        StringBuilder input = new StringBuilder();

        int count = 0;
        int value;


        while ((value = pkcs7IS.read()) != -1) {

            hex.append(String.format("%02X", value));

            //If the character is unable to convert, just prints a dot "."
            if (!Character.isISOControl(value)) {
                input.append((char) value);
            } else {
                input.append(UNKNOWN_CHARACTER);
            }

            // After 15 bytes, reset everything for formatting purpose
            if (count == 14) {
                result.append(hex);
                hex.setLength(0);
                input.setLength(0);
                count = 0;
            } else {
                count++;
            }

        }


        return result.toString();
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
