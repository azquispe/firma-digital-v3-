/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.ganaseguros.pkcs11;

import java.lang.reflect.Field;

/**
 *
 * @author ADSIB
 */
public class CK_VERSION {
    public CK_VERSION(Object version) {
        try {
            Field f = version.getClass().getDeclaredField("major");
            major = (byte)f.get(version);
            f = version.getClass().getDeclaredField("minor");
            minor = (byte)f.get(version);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BYTE major;
     * </PRE>
     */
    public byte major;  /* integer portion of version number */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_BYTE minor;
     * </PRE>
     */
    public byte minor;  /* 1/100ths portion of version number */

    /**
     * Returns the string representation of CK_VERSION.
     *
     * @return the string representation of CK_VERSION
     */
    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();

        buffer.append(major & 0xff);
        buffer.append('.');
        int m = minor & 0xff;
        if (m < 10) {
            buffer.append('0');
        }
        buffer.append(m);

        return buffer.toString();
    }

}
