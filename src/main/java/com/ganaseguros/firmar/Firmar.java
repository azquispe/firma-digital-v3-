/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.firmar;

import com.ganaseguros.token.Token;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

/**
 *
 * @author ADSIB
 */
public interface Firmar {
    public void firmar(InputStream is, OutputStream os, boolean param, Token token) throws IOException, GeneralSecurityException;
    //public void firmar(InputStream is, OutputStream os) throws IOException, GeneralSecurityException;
}
