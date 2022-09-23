package com.ganaseguros.apifirmadorv3.dto;

import com.ganaseguros.validar.CertDate;

import java.text.SimpleDateFormat;
import java.util.Date;

public class CertificadoDto {
    private String ci;
    private String complemento;
    private String nombreSignatario;
    private String cargoSignatario;
    private String organizacionSignatario;
    private String emailSignatario;
    private String nombreECA;
    private String descripcionECA;
    private Date inicioValidez;
    private Date finValidez;
    private Date revocado;

    private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");

    public CertificadoDto(CertDate cert) {
        this.ci = cert.getDatos().getNumeroDocumentoSubject();
        this.complemento = cert.getDatos().getComplementoSubject();
        this.nombreSignatario = cert.getDatos().getNombreComunSubject();
        this.cargoSignatario = cert.getDatos().getCargoSubject();
        this.organizacionSignatario = cert.getDatos().getOrganizacionSubject();
        this.emailSignatario = cert.getDatos().getCorreoSubject();
        this.nombreECA = cert.getDatos().getNombreComunIssuer();
        this.descripcionECA = cert.getDatos().getDescripcionSubject();
        this.inicioValidez = cert.getDatos().getInicioValidez();
        this.finValidez = cert.getDatos().getFinValidez();
        if (cert.getOCSP().getDate() != null) {
            this.revocado = cert.getOCSP().getDate();
        }
    }

    public String getCi() {
        if (complemento == null) {
            return ci;
        } else {
            return ci + "-" + complemento;
        }
    }

    public String getNombreSignatario() {
        return nombreSignatario;
    }

    public String getCargoSignatario() {
        return cargoSignatario;
    }

    public String getOrganizacionSignatario() {
        return organizacionSignatario;
    }

    public String getEmailSignatario() {
        return emailSignatario;
    }

    public String getNombreECA() {
        return nombreECA;
    }

    public String getDescripcionECA() {
        return descripcionECA;
    }
    
    public String getInicioValidez() {
        return dateFormat.format(inicioValidez);
    }

    public String getFinValidez() {
        return dateFormat.format(finValidez);
    }

    public String getRevocado() {
        if (revocado != null) {
            return dateFormat.format(revocado);
        } else {
            return null;
        }
    }
}
