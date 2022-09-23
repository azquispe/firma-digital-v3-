package com.ganaseguros.apifirmadorv3.dto;

public class UsuariosFirmantesDto {
    private String userName;
    private String pin;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }
}
