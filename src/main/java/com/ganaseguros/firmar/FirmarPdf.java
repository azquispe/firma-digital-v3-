/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.firmar;

import com.ganaseguros.token.ExternalSignatureLocal;
import com.ganaseguros.token.Token;
import com.ganaseguros.token.TokenHsmCloud;
import com.ganaseguros.token.TokenPKCS12;
import com.itextpdf.forms.PdfSigFieldLock;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 *
 * @author ADSIB
 */
public class FirmarPdf implements Firmar {
    private static FirmarPdf firmarPdf;
    private final String jwt;
    private final String slot;
    private final String path;
    private final String label;
    private final String pass;

    private FirmarPdf(String jwt, String slot, String label, String pass) {
        this.jwt = jwt;
        this.slot = slot;
        this.path = null;
        this.label = label;
        this.pass = pass;
    }

    private FirmarPdf(String path, String label, String pass) {
        this.jwt = null;
        this.slot = null;
        this.path = path;
        this.label = label;
        this.pass = pass;
    }

    public static FirmarPdf getInstance(String jwt, String slot, String label, String pass) {
        if (firmarPdf == null) {
            firmarPdf = new FirmarPdf(jwt, slot, label, pass);
        } else {
            if (firmarPdf.slot != slot || !firmarPdf.label.equals(label) || !firmarPdf.pass.equals(pass)) {
                firmarPdf = new FirmarPdf(jwt, slot, label, pass);
            }
        }
        return firmarPdf;
    }

    public static FirmarPdf getInstance(String path, String label, String pass) {
        if (firmarPdf == null) {
            firmarPdf = new FirmarPdf(path, label, pass);
        } else {
            if (!firmarPdf.path.equals(path) || !firmarPdf.label.equals(label) || !firmarPdf.pass.equals(pass)) {
                firmarPdf = new FirmarPdf(path, label, pass);
            }
        }
        return firmarPdf;
    }

    @Override
    public synchronized void firmar(InputStream is, OutputStream os, boolean bloquear,Token token) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(is);
        StampingProperties stamp = new StampingProperties();
        stamp.useAppendMode();
        PdfSigner signer = new PdfSigner(reader, os, stamp);
        if (reader.isEncrypted()) {
            throw new IOException("El documento se encuentra encriptado.");
        }
        if (bloquear) {
            PdfSigFieldLock fieldLock = new PdfSigFieldLock();
            fieldLock.setDocumentPermissions(PdfSigFieldLock.LockPermissions.NO_CHANGES_ALLOWED);
            fieldLock.setFieldLock(PdfSigFieldLock.LockAction.EXCLUDE, new String[]{});
            signer.setFieldLockDict(fieldLock);
        }
        Rectangle rect = new Rectangle(0, 0, 0, 0);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setPageRect(rect);

        IExternalDigest digest = new BouncyCastleDigest();
        /*Token token;
        if (path == null) {
            token = new TokenHsmCloud(jwt);
        } else {
            token = new TokenPKCS12(path);
        }
        token.iniciar(pass);*/
        IExternalSignature signature = new ExternalSignatureLocal(token.obtenerClavePrivada(label), token.getProviderName());
        //IExternalSignature signature = null; // para generar error 2007
        signer.signDetached(digest, signature, token.getCertificateChain(label), null, null, null, 0, PdfSigner.CryptoStandard.CADES);
        token.salir();
        
    }

    /*@Override
    public synchronized void firmar(InputStream is, OutputStream os) throws IOException, GeneralSecurityException {
        firmar(is, os, false);
    }*/

    public static synchronized void firmar(InputStream is, OutputStream os, boolean bloquear, Token token, String label) throws IOException, GeneralSecurityException {
        PdfReader reader = new PdfReader(is);
        StampingProperties stamp = new StampingProperties();
        stamp.useAppendMode();
        PdfSigner signer = new PdfSigner(reader, os, stamp);
        if (reader.isEncrypted()) {
            throw new IOException("El documento se encuentra encriptado.");
        }
        if (bloquear) {
            PdfSigFieldLock fieldLock = new PdfSigFieldLock();
            fieldLock.setDocumentPermissions(PdfSigFieldLock.LockPermissions.NO_CHANGES_ALLOWED);
            fieldLock.setFieldLock(PdfSigFieldLock.LockAction.EXCLUDE, new String[]{});
            signer.setFieldLockDict(fieldLock);
        }
        Rectangle rect = new Rectangle(0, 0, 0, 0);
        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setPageRect(rect);

        IExternalDigest digest = new BouncyCastleDigest();
        IExternalSignature signature = new ExternalSignatureLocal(token.obtenerClavePrivada(label), token.getProviderName());
        signer.signDetached(digest, signature, token.getCertificateChain(label), null, null, null, 0, PdfSigner.CryptoStandard.CADES);
    }
}
