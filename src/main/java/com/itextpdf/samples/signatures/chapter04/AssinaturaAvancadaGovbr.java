package com.itextpdf.samples.signatures.chapter04;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AssinaturaAvancadaGovbr {

    private static final Logger LOGGER = Logger.getLogger(AssinaturaAvancadaGovbr.class.getName());

    private static final String SRC = "./src/test/resources/pdfs/doc-blank.pdf";
    private static final String RESULT_FILES = "./target/signatures/doc-sig-ok.pdf";

    public static void main(String[] args) {
        new AssinaturaAvancadaGovbr()
                .embutirAssinatura(
                        SRC,
                        RESULT_FILES,
                        "XUXU"
                );
    }

    private void embutirAssinatura(String pdfOriginal, String pdfAssinado, String nomeCampoAssinatura) {

        try (FileOutputStream pdfAssinadoOS = new FileOutputStream(pdfAssinado)) {
            try (PdfReader pdfReader = new PdfReader(pdfOriginal)) {
                PdfSigner pdfSigner = new PdfSigner(pdfReader, pdfAssinadoOS, new StampingProperties());

                Rectangle rectangle = new Rectangle(36, 36, 300, 100);
                PdfSignatureAppearance appearance = pdfSigner.getSignatureAppearance();
                appearance
                        .setReason("SIGN.GOV.BR")
                        .setLocation("ORGÃO SOLICITANTE")
                        .setPageRect(rectangle)
                        .setPageNumber(1);

                pdfSigner.setFieldName(nomeCampoAssinatura);

                SignatureContainer signatureContainer = new SignatureContainer();

                pdfSigner.signExternalContainer(signatureContainer, 8192);
            }
        } catch (IOException ioe) {
            LOGGER.log(Level.SEVERE, "IOEXCEPTION", ioe);
        } catch (GeneralSecurityException gse) {
            LOGGER.log(Level.SEVERE, "GENERALSECURITYEXCEPTION", gse);
        }
    }


    public class SignatureContainer implements IExternalSignatureContainer {

        private SignatureContainer() {
            super();
        }

        @Override
        public byte[] sign(InputStream data) {

            try {

                String hashAlgorithm = "SHA256";
                BouncyCastleDigest digest = new BouncyCastleDigest();
                byte[] documentHash = DigestAlgorithms.digest(data, digest.getMessageDigest(hashAlgorithm));
                String documentHashBase64 = Base64.getEncoder().encodeToString(documentHash);

                try (CloseableHttpClient httpclient = HttpClients.createDefault()) {

                    HttpPost post = new HttpPost("https://assinatura-api.staging.iti.br/externo/v2/assinarPKCS7");
                    post.setEntity(new StringEntity("{\"hashBase64\": \"" + documentHashBase64 + "\"}", ContentType.APPLICATION_JSON));
                    post.addHeader("Content-Type", "application/json");
                    post.addHeader("Authorization", "Bearer AT-352-nxh-XnIOaMxYL1WFFluhZwLfy5czbET7");

                    try (CloseableHttpResponse response = httpclient.execute(post)) {

                        HttpEntity entity = response.getEntity();

                        InputStream inputStream = entity.getContent();
                        byte[] targetArray = new byte[inputStream.available()];
                        inputStream.read(targetArray);

                        return targetArray;

                    }
                }
            } catch (IOException ioe) {
                LOGGER.log(Level.SEVERE, "IOEXCEPTION", ioe);
            } catch (GeneralSecurityException gse) {
                LOGGER.log(Level.SEVERE, "GENERALSECURITYEXCEPTION", gse);
            }


            return new byte[0];
        }

        @Override
        public void modifySigningDictionary(PdfDictionary pdfDictionary) {
            pdfDictionary.put(PdfName.Filter, PdfName.Adobe_PPKLite);
            pdfDictionary.put(PdfName.SubFilter, PdfName.Adbe_pkcs7_detached);

        }
    }

}
