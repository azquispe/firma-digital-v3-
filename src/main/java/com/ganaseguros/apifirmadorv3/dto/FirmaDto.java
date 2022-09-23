package com.ganaseguros.apifirmadorv3.dto;

import java.util.Date;

public class FirmaDto {
    private boolean noModificado;
    private boolean cadenaConfianza;
    private boolean firmadoDuranteVigencia;
    private boolean firmadoAntesRevocacion;
    private boolean versionado;
    private Date timeStamp;
    private Date fechaFirma;
    private CertificadoDto certificado;

    public FirmaDto(boolean noModificado, boolean cadenaConfianza, boolean firmadoDuranteVigencia, boolean firmadoAntesRevocacion, boolean versionado) {
        this.noModificado = noModificado;
        this.cadenaConfianza = cadenaConfianza;
        this.firmadoDuranteVigencia = firmadoDuranteVigencia;
        this.firmadoAntesRevocacion = firmadoAntesRevocacion;
        this.versionado = versionado;
    }

    public boolean isNoModificado() {
        return noModificado;
    }
    public void setNoModificado(boolean noModificado) {
        this.noModificado = noModificado;
    }

    public boolean isCadenaConfianza() {
        return cadenaConfianza;
    }
    public void setCadenaConfianza(boolean cadenaConfianza) {
        this.cadenaConfianza = cadenaConfianza;
    }

    public boolean isFirmadoDuranteVigencia() {
        return firmadoDuranteVigencia;
    }
    public void setFirmadoDuranteVigencia(boolean firmadoDuranteVigencia) {
        this.firmadoDuranteVigencia = firmadoDuranteVigencia;
    }

    public boolean isFirmadoAntesRevocacion() {
        return firmadoAntesRevocacion;
    }
    public void setFirmadoAntesRevocacion(boolean firmadoAntesRevocacion) {
        this.firmadoAntesRevocacion = firmadoAntesRevocacion;
    }

    public boolean isVersionado() {
        return versionado;
    }
    public void setVersionado(boolean versionado) {
        this.versionado = versionado;
    }

    public Date getTimeStamp() {
        return timeStamp;
    }
    public void setTimeStamp(Date timeStamp) {
        this.timeStamp = timeStamp;
    }

    public Date getFechaFirma() {
        return fechaFirma;
    }
    public void setFechaFirma(Date fechaFirma) {
        this.fechaFirma = fechaFirma;
    }

    public CertificadoDto getCertificado() {
        return certificado;
    }
    public void setCertificado(CertificadoDto certificado) {
        this.certificado = certificado;
    }
}
