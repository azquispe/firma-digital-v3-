package com.ganaseguros.validar;

import com.ganaseguros.validar.ContentsChecker.Estado;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class CertDate {
    private final String name;
    private final Certificate certificate;
    private final Calendar signDate;
    private final Calendar timeStamp;
    private final boolean bloquea;

    private DatosCertificado datos;

    private boolean valid = false;
    private Estado validAdd = Estado.sin_cambios;
    private boolean pki = false;
    private OCSPData ocsp = new OCSPData(Validar.OCSPState.UNKNOWN, null);

    public CertDate(String name, Certificate certificate, Calendar signDate, Calendar timeStamp, boolean bloquea) {
        this.name = name;
        this.certificate = certificate;
        this.signDate = signDate;
        this.timeStamp = timeStamp;
        this.bloquea = bloquea;

        try {
            datos = new DatosCertificado((X509Certificate) certificate);
        } catch (CertificateEncodingException ignore) {
        }
    }

    public String getName() {
        return name;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public DatosCertificado getDatos() {
        return datos;
    }

    public Date getSignDate() {
        return signDate.getTime();
    }

    public Date getTimeStamp() {
        if (timeStamp == null) {
            return null;
        } else {
            return timeStamp.getTime();
        }
    }

    public boolean isBloquea() {
        return bloquea;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isValidAlerted() {
        switch (validAdd) {
            case sin_cambios:
                return false;
            case widget_firma_agregado:
                return isBloquea();
            default:
                return true;
        }
    }

    public void setValidAdd(Estado validAdd) {
        this.validAdd = validAdd;
    }

    public Estado getValidAdd() {
        return validAdd;
    }

    public void setPKI(boolean pki) {
        this.pki = pki;
    }

    public boolean isPKI() {
        return pki;
    }

    public boolean isActive() {
        if (getTimeStamp() == null) {
            return ((X509Certificate) certificate).getNotBefore().compareTo(getSignDate()) < 0 && ((X509Certificate) certificate).getNotAfter().compareTo(getSignDate()) > 0;
        } else {
            return ((X509Certificate) certificate).getNotBefore().compareTo(getTimeStamp()) < 0 && ((X509Certificate) certificate).getNotAfter().compareTo(getTimeStamp()) > 0;
        }
    }

    public void setOCSP(OCSPData ocsp) {
        this.ocsp = ocsp;
    }

    public OCSPData getOCSP() {
        return ocsp;
    }

    public boolean isOCSP() {
        return ocsp.getState() == Validar.OCSPState.OK || ocsp.getState() == Validar.OCSPState.ALERT;
    }

    public boolean isOk() {
        return isValid() && isPKI() && isActive() && isOCSP();
    }

    public boolean isAlerted() {
        return isValidAlerted() || isActiveAlerted() || isOCSPAlerted();
    }

    public boolean isActiveAlerted() {
        if (getTimeStamp() == null) {
            return !(((X509Certificate) certificate).getNotBefore().compareTo(new Date()) < 0 && ((X509Certificate) certificate).getNotAfter().compareTo(new Date()) > 0);
        } else {
            return false;
        }
    }

    public boolean isOCSPAlerted() {
        return ocsp.getState() == Validar.OCSPState.ALERT;
    }
}
