/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.validar;

import java.util.Date;

/**
 *
 * @author ADSIB
 */
public class OCSPData {
    private final Validar.OCSPState state;
        private final Date date;

        public OCSPData(Validar.OCSPState state, Date date) {
            this.state = state;
            this.date = date;
        }

        public Validar.OCSPState getState() {
            return state;
        }

        public Date getDate() {
            return date;
        }
}
