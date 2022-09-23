/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.validar;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 *
 * @author ADSIB
 */
public class Certificate {
    public static String getPem(byte[] data) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(data));
            Base64.Encoder encoder = Base64.getMimeEncoder(64, "\n".getBytes());
            String pem = "-----BEGIN CERTIFICATE-----\n" + encoder.encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----";
            return pem;
        } catch (CertificateException ex) {
            return null;
        }
    }
}
