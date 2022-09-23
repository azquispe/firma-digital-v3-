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
public class CK_TOKEN_INFO {
    protected long slot;

    public CK_TOKEN_INFO(long slot, Object info) {
        try {
            this.slot = slot;
            Field f = info.getClass().getDeclaredField("label");
            label = (char[])f.get(info);
            f = info.getClass().getDeclaredField("manufacturerID");
            manufacturerID = (char[])f.get(info);
            f = info.getClass().getDeclaredField("model");
            model = (char[])f.get(info);
            f = info.getClass().getDeclaredField("serialNumber");
            serialNumber = (char[])f.get(info);
            f = info.getClass().getDeclaredField("flags");
            flags = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulMaxSessionCount");
            ulMaxSessionCount = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulSessionCount");
            ulSessionCount = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulMaxRwSessionCount");
            ulMaxRwSessionCount = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulRwSessionCount");
            ulRwSessionCount = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulMaxPinLen");
            ulMaxPinLen = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulMinPinLen");
            ulMinPinLen = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulTotalPublicMemory");
            ulTotalPublicMemory = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulFreePublicMemory");
            ulFreePublicMemory = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulTotalPrivateMemory");
            ulTotalPrivateMemory = (long)f.get(info);
            f = info.getClass().getDeclaredField("ulFreePrivateMemory");
            ulFreePrivateMemory = (long)f.get(info);
            f = info.getClass().getDeclaredField("hardwareVersion");
            hardwareVersion = new CK_VERSION(f.get(info));
            f = info.getClass().getDeclaredField("firmwareVersion");
            firmwareVersion = new CK_VERSION(f.get(info));
            f = info.getClass().getDeclaredField("utcTime");
            utcTime = (char[])f.get(info);
        } catch (NoSuchFieldException | SecurityException | IllegalArgumentException | IllegalAccessException ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    public long getSlot() {
        return slot;
    }

    public String getLabel() {
        return new String(label);
    }

    /* label, manufacturerID, and model have been changed from
     * CK_CHAR to CK_UTF8CHAR for v2.11. */
    /**
     * must be blank padded and only the first 32 chars will be used<p>
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_UTF8CHAR label[32];
     * </PRE>
     */
    public char[] label;           /* blank padded */

    /**
     * must be blank padded and only the first 32 chars will be used<p>
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_UTF8CHAR manufacturerID[32];
     * </PRE>
     */
    public char[] manufacturerID;  /* blank padded */

    /**
     * must be blank padded and only the first 16 chars will be used<p>
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_UTF8CHAR model[16];
     * </PRE>
     */
    public char[] model;           /* blank padded */

    /**
     * must be blank padded and only the first 16 chars will be used<p>
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_CHAR serialNumber[16];
     * </PRE>
     */
    public char[] serialNumber;    /* blank padded */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_FLAGS flags;
     * </PRE>
     */
    public long flags;               /* see below */

    /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
     * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
     * changed from CK_USHORT to CK_ULONG for v2.0 */
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulMaxSessionCount;
     * </PRE>
     */
    public long ulMaxSessionCount;     /* max open sessions */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulSessionCount;
     * </PRE>
     */
    public long ulSessionCount;        /* sess. now open */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulMaxRwSessionCount;
     * </PRE>
     */
    public long ulMaxRwSessionCount;   /* max R/W sessions */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulRwSessionCount;
     * </PRE>
     */
    public long ulRwSessionCount;      /* R/W sess. now open */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulMaxPinLen;
     * </PRE>
     */
    public long ulMaxPinLen;           /* in bytes */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulMinPinLen;
     * </PRE>
     */
    public long ulMinPinLen;           /* in bytes */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulTotalPublicMemory;
     * </PRE>
     */
    public long ulTotalPublicMemory;   /* in bytes */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulFreePublicMemory;
     * </PRE>
     */
    public long ulFreePublicMemory;    /* in bytes */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulTotalPrivateMemory;
     * </PRE>
     */
    public long ulTotalPrivateMemory;  /* in bytes */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_ULONG ulFreePrivateMemory;
     * </PRE>
     */
    public long ulFreePrivateMemory;   /* in bytes */

    /* hardwareVersion, firmwareVersion, and time are new for
     * v2.0 */
    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_VERSION hardwareVersion;
     * </PRE>
     */
    public CK_VERSION    hardwareVersion;       /* version of hardware */

    /**
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_VERSION firmwareVersion;
     * </PRE>
     */
    public CK_VERSION    firmwareVersion;       /* version of firmware */

    /**
     * only the first 16 chars will be used
     * <B>PKCS#11:</B>
     * <PRE>
     *   CK_CHAR utcTime[16];
     * </PRE>
     */
    public char[] utcTime;           /* time */

    /**
     * Returns the string representation of CK_TOKEN_INFO.
     *
     * @return the string representation of CK_TOKEN_INFO
     */
    @Override
    public String toString() {
        StringBuilder buffer = new StringBuilder();

        buffer.append(Constants.INDENT);
        buffer.append("label: ");
        buffer.append(new String(label));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("manufacturerID: ");
        buffer.append(new String(manufacturerID));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("model: ");
        buffer.append(new String(model));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("serialNumber: ");
        buffer.append(new String(serialNumber));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("flags: ");
        buffer.append(Functions.tokenInfoFlagsToString(flags));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulMaxSessionCount: ");
        buffer.append((ulMaxSessionCount == PKCS11Constants.CK_EFFECTIVELY_INFINITE)
                  ? "CK_EFFECTIVELY_INFINITE"
                  : (ulMaxSessionCount == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                    ? "CK_UNAVAILABLE_INFORMATION"
                    : String.valueOf(ulMaxSessionCount));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulSessionCount: ");
        buffer.append((ulSessionCount == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulSessionCount));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulMaxRwSessionCount: ");
        buffer.append((ulMaxRwSessionCount == PKCS11Constants.CK_EFFECTIVELY_INFINITE)
                  ? "CK_EFFECTIVELY_INFINITE"
                  : (ulMaxRwSessionCount == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                    ? "CK_UNAVAILABLE_INFORMATION"
                    : String.valueOf(ulMaxRwSessionCount));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulRwSessionCount: ");
        buffer.append((ulRwSessionCount == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulRwSessionCount));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulMaxPinLen: ");
        buffer.append(String.valueOf(ulMaxPinLen));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulMinPinLen: ");
        buffer.append(String.valueOf(ulMinPinLen));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulTotalPublicMemory: ");
        buffer.append((ulTotalPublicMemory == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulTotalPublicMemory));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulFreePublicMemory: ");
        buffer.append((ulFreePublicMemory == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulFreePublicMemory));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulTotalPrivateMemory: ");
        buffer.append((ulTotalPrivateMemory == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulTotalPrivateMemory));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("ulFreePrivateMemory: ");
        buffer.append((ulFreePrivateMemory == PKCS11Constants.CK_UNAVAILABLE_INFORMATION)
                  ? "CK_UNAVAILABLE_INFORMATION"
                  : String.valueOf(ulFreePrivateMemory));
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("hardwareVersion: ");
        buffer.append(hardwareVersion.toString());
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("firmwareVersion: ");
        buffer.append(firmwareVersion.toString());
        buffer.append(Constants.NEWLINE);

        buffer.append(Constants.INDENT);
        buffer.append("utcTime: ");
        buffer.append(new String(utcTime));
        //buffer.append(Constants.NEWLINE);

        return buffer.toString() ;
    }

}
