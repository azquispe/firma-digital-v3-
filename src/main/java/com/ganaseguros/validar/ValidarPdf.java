package com.ganaseguros.validar;

import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ValidarPdf extends Validar {
    protected String urlPost = null;
    protected String token = null;

    public ValidarPdf(File file) {
        try {
            super.file = file;
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            try (InputStream is = new FileInputStream(file)) {
                certificados = listarCertificados(is);
            }
        } catch (Exception ignore) {
        }
    }

    public ValidarPdf(File file, String urlPost, String token) {
        this(file);
        this.urlPost = urlPost;
        this.token = token;
    }
    
    public ValidarPdf(InputStream is) {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            certificados = listarCertificados(is);
        } catch (Exception ignore) {
        }
    }

    @Override
    public boolean isRemoto() {
        return urlPost != null;
    }

    @Override
    public String getPost() {
        return urlPost;
    }

    @Override
    public String getToken() {
        return token;
    }

    @Override
    public String getRevisionPath(String revision) {
        try {
            File out = new File(System.getProperty("java.io.tmpdir"), "documento.pdf");
            int c = 1;
            while (out.exists()) {
                out = new File(System.getProperty("java.io.tmpdir"), "documento" + c + ".pdf");
                c++;
            }
            PdfReader pdf = new PdfReader(file);
            PdfDocument pdfDocument = new PdfDocument(pdf);
            SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
            try (InputStream is = signatureUtil.extractRevision(revision);OutputStream os = new FileOutputStream(out)) {
                byte[] buffer = new byte[8 * 1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    os.write(buffer, 0, bytesRead);
                }
            }
            return out.getAbsolutePath();
        } catch (IOException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    private boolean bloqueaDocumento(PdfArray referenceArray) {
        if (referenceArray == null || referenceArray.size() == 0) {
            return false;
        }
        for (PdfObject referenceObject : referenceArray) {
            if (referenceObject.isIndirectReference())
                referenceObject = ((PdfIndirectReference)referenceObject).getRefersTo(true);
            if (referenceObject.isIndirectReference()) {
                continue;
            }
            if (!referenceObject.isDictionary()) {
                continue;
            }
            PdfDictionary reference = (PdfDictionary) referenceObject;

            PdfName method = reference.getAsName(PdfName.TransformMethod);
            if (method == null) {
                continue;
            }
            if (new PdfName("UR").equals(method)) {
                continue;
            }
            if (!PdfName.DocMDP.equals(method) && !PdfName.FieldMDP.equals(method)) {
                continue;
            }

            PdfDictionary transformParams = reference.getAsDictionary(PdfName.TransformParams);
            if (transformParams == null) {
                continue;
            }

            PdfNumber p = transformParams.getAsNumber(PdfName.P);
            if (p != null) {
                return p.intValue() == 1;
            }
        }
        return false;
    }

    public List<CertDate> listarCertificados(InputStream is) throws Exception {
        Certificate certificateTSA;
        try (InputStreamReader isr = new InputStreamReader(getClass().getClassLoader().getResourceAsStream("timestamp.crt"))) {
            PemReader reader = new PemReader(isr);
            byte[] cert = reader.readPemObject().getContent();
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            certificateTSA = certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
            reader.close();
        }

        List<CertDate> certs = new ArrayList<>();
        ContentsChecker pdf = new ContentsChecker(is);
        PdfDocument pdfDocument = new PdfDocument(pdf);
        SignatureUtil signatureUtil = new SignatureUtil(pdfDocument);
        List<String> firmas = signatureUtil.getSignatureNames();

        for (String nombre : firmas) {
            PdfDictionary dict = signatureUtil.getSignatureDictionary(nombre);
            PdfArray referenceArray = dict.getAsArray(PdfName.Reference);
            PdfPKCS7 pkcs7 = signatureUtil.readSignatureData(nombre);

            CertDate certDate;
            if (pkcs7.getTimeStampToken() != null && pkcs7.getTimeStampToken().isSignatureValid(new JcaSimpleSignerInfoVerifierBuilder().build(certificateTSA.getPublicKey()))) {
                certDate = new CertDate(nombre, pkcs7.getSigningCertificate(), pkcs7.getSignDate(), pkcs7.getTimeStampDate(), bloqueaDocumento(referenceArray));
            } else {
                certDate = new CertDate(nombre, pkcs7.getSigningCertificate(), pkcs7.getSignDate(), null, bloqueaDocumento(referenceArray));
            }
            certDate.setValid(pkcs7.verifySignatureIntegrityAndAuthenticity());
            certDate.setValidAdd(pdf.checkElementAdded(dict));
            certDate.setPKI(verificarPKI(certDate.getCertificate()));
            certDate.setOCSP(verificarOcsp((X509Certificate) certDate.getCertificate(), certDate.getSignDate()));
            certs.add(certDate);
        }
        return certs;
    }

    public boolean isBloquea() {
        boolean res = false;
        try {
            for (CertDate cert : certificados) {
                if (cert.isBloquea()) {
                    res = true;
                    break;
                }
            }
        } catch (Exception ignore) {
        }
        return res;
    }
}
