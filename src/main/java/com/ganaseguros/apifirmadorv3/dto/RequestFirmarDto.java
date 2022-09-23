package com.ganaseguros.apifirmadorv3.dto;

import java.util.List;

public class RequestFirmarDto {
    private List<UsuariosFirmantesDto> listaUsuario;
    private List<String> listaPdf;

    public List<UsuariosFirmantesDto> getListaUsuario() {
        return listaUsuario;
    }

    public void setListaUsuario(List<UsuariosFirmantesDto> listaUsuario) {
        this.listaUsuario = listaUsuario;
    }

    public List<String> getListaPdf() {
        return listaPdf;
    }

    public void setListaPdf(List<String> listaPdf) {
        this.listaPdf = listaPdf;
    }
}
