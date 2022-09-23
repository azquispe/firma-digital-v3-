/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.firmar;

import com.ganaseguros.token.Token;
import com.ganaseguros.token.TokenHsmCloud;
import com.ganaseguros.validar.MagicBytes;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author ADSIB
 */
public class FirmarPKCS7 implements Firmar {
    private static FirmarPKCS7 firmarPkcs7;
    private final String jwt;
    private final String slot;
    private final String label;
    private final String pass;

    private FirmarPKCS7(String jwt, String slot, String label, String pass) {
        this.jwt = jwt;
        this.slot = slot;
        this.label = label;
        this.pass = pass;
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static FirmarPKCS7 getInstance(String jwt, String slot, String label, String pass) {
        if (firmarPkcs7 == null) {
            firmarPkcs7 = new FirmarPKCS7(jwt, slot, label, pass);
        } else {
            if (firmarPkcs7.slot != slot || !firmarPkcs7.label.equals(label) || !firmarPkcs7.pass.equals(pass)) {
                firmarPkcs7 = new FirmarPKCS7(jwt, slot, label, pass);
            }
        }
        return firmarPkcs7;
    }

    @Override
    public synchronized void firmar(InputStream is, OutputStream os, boolean detached) throws IOException, GeneralSecurityException {
        try {
            Token token = new TokenHsmCloud(jwt);
            token.iniciar(pass);
            PrivateKey privateKey = token.obtenerClavePrivada(label);
            if (privateKey == null) {
                token.salir();
                throw new RuntimeException("No se encontró la clave con alias: " + label);
            }
            X509Certificate x509Certificate = token.obtenerCertificado(label);
            List<Certificate> certlist = new ArrayList<>();
            certlist.add(x509Certificate);
            Store certstore = new JcaCertStore(certlist);
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                    build()).build(signer, (X509Certificate) x509Certificate));
            generator.addCertificates(certstore);
            
            CMSTypedData cmsdata;
            if (MagicBytes.P7S.is(is)) {
                if (detached) {
                    throw new RuntimeException("No puede realizar múltiples firmas con la opción detached.");
                }
                CMSSignedData signedData = new CMSSignedData(is);
                cmsdata = signedData.getSignedContent();
                Store current = signedData.getCertificates();
                generator.addCertificates(current);
                generator.addSigners(signedData.getSignerInfos());
            } else {
                byte[] data = is.readAllBytes();
                cmsdata = new CMSProcessableByteArray(data);
            }
            CMSSignedData signeddata = generator.generate(cmsdata, !detached);
            os.write(signeddata.getEncoded());
            token.salir();
        } catch (OperatorCreationException | CMSException ex) {
            Logger.getLogger(FirmarPKCS7.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void firmar(InputStream is, OutputStream os) throws IOException, GeneralSecurityException {
        firmar(is, os, false);
    }
}
