/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.validar;

import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;

import java.io.*;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_signingTime;

/**
 *
 * @author ADSIB
 */
public class ValidarPKCS7 extends Validar {
    public ValidarPKCS7(File file) {
        try {
            super.file = file;
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            certificados = listarCertificados(new FileInputStream(file));
        } catch (Exception ignore) {
        }
    }

    public ValidarPKCS7(InputStream is) {
        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            certificados = listarCertificados(is);
        } catch (Exception ignore) {
        }
    }

    @Override
    public String getAbsolutePath() {
        if (file.getName().endsWith(".p7s")) {
            try {
                File f = new File(System.getProperty("java.io.tmpdir"), file.getName().replace(".p7s", ""));
                InputStream is = new FileInputStream(file);
                CMSSignedData signedData = new CMSSignedData(is);
                CMSProcessable sc = signedData.getSignedContent();
                try (FileOutputStream os = new FileOutputStream(f)) {
                    sc.write(os);
                }
                return f.getAbsolutePath();
            } catch (CMSException | IOException ex) {
                Logger.getLogger(ValidarPKCS7.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file.getAbsolutePath();
    }

    @Override
    public void export(File f) {
        try {
            InputStream is = new FileInputStream(file);
            CMSSignedData signedData = new CMSSignedData(is);
            CMSProcessable sc = signedData.getSignedContent();
            try (FileOutputStream os = new FileOutputStream(f)) {
                sc.write(os);
            }
        } catch (CMSException | IOException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    @Override
    public String exportB64(InputStream is) {
        try {
            CMSSignedData signedData = new CMSSignedData(is);
            CMSProcessable sc = signedData.getSignedContent();
            String b64;
            try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
                sc.write(os);
                b64 = Base64.getEncoder().encodeToString(os.toByteArray());
            }
            return b64;
        }   catch (CMSException | IOException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public List<CertDate> listarCertificados(InputStream is) throws Exception {
        List<CertDate> certs = new ArrayList<>();
        try {
            CMSSignedData signedData = new CMSSignedData(is);

            Collection<SignerInformation> firmas = signedData.getSignerInfos().getSigners();

            Integer firma = 1;
            for (SignerInformation signerInfo : firmas) {
                Attribute attribute = signerInfo.getSignedAttributes().get(pkcs_9_at_signingTime);
                Calendar fecha = Calendar.getInstance();
                fecha.setTime(((ASN1UTCTime)attribute.getAttrValues().getObjectAt(0)).getDate());
                // Integridad del documento
                X509Certificate cert = null;
                boolean integrity = false;
                Store store = signedData.getCertificates();
                Collection<X509CertificateHolder> allCerts = store.getMatches(null);
                for (X509CertificateHolder holder : allCerts) {
                    cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
                    if (signerInfo.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                        integrity = true;
                        break;
                    }
                }
                CertDate certDate = new CertDate(firma.toString(), cert, fecha, null, false);
                certDate.setValid(integrity);
                certDate.setPKI(verificarPKI(certDate.getCertificate()));
                certDate.setOCSP(verificarOcsp((X509Certificate) certDate.getCertificate(), certDate.getSignDate()));
                certs.add(certDate);
                firma++;
            }
        } catch (CMSException ignore) { }
        return certs;
    }
}
