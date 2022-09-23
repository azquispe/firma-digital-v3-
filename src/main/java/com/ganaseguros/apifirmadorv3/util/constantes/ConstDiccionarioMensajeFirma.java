package com.ganaseguros.apifirmadorv3.util.constantes;

public class ConstDiccionarioMensajeFirma {
    public static final String COD1000 = "COD1000"; // CUANDO TODO SEA CORRECTO
    public static final String COD1000_MENSAJE = "Proceso Completado";
    public static final String COD2000 = "COD2000";
    public static final String COD2000_MENSAJE = "Error desconocido, Comuníquese con Administrador";
    public static final String COD2001 = "COD2001";

    //MENSAJES PARA EL FIRMADO
    public static final String COD2001_MENSAJE = "No existe usuario(s) para firmar";
    public static final String COD2002 = "COD2002";
    public static final String COD2002_MENSAJE = "No existe  Documento(s) para firmar";
    public static final String COD2003 = "COD2003";
    public static final String COD2003_MENSAJE = "No existe Certificado(s) para firmar";
    public static final String COD2004 = "COD2004";
    public static final String COD2004_MENSAJE = "PIN (es) Incorrecto(s)";
    public static final String COD2005 = "COD2005";
    public static final String COD2005_MENSAJE = "No se pudo construir el documento .pdf (Base 64)";
    public static final String COD2007 = "COD2007";
    public static final String COD2007_MENSAJE = "No se pudo firmar el documento 'pdf'";
    public static final String COD2008 = "COD2008";
    public static final String COD2008_MENSAJE = "Se han encontrado errores";

    //ya no se usa
    /*public static final String COD2009 = "COD2009";
    public static final String COD2009_MENSAJE = "No se pudo realizar la verificación de las firmas";*/

    public static final String COD2010 = "COD2010";
    public static final String COD2010_MENSAJE = "Documento ha sido modificado";
    public static final String COD2011 = "COD2011";
    public static final String COD2011_MENSAJE = "Cadena de Confianza del certificado no es valido";
    public static final String COD2012 = "COD2012";
    public static final String COD2012_MENSAJE = "Periodo de Vigencia del certificado no es valido";
    public static final String COD2013 = "COD2013";
    public static final String COD2013_MENSAJE = "Certificado Revocado";



    // MENSAJES PARA VERIFICAR FIRMAS
    public static final String COD2006 = "COD2006";
    public static final String COD2006_MENSAJE = "No existe  Documento(s) para verificar";






















    // ESTOS MENSAJES SON PARA LA VALIDACIÓN DE TOKEN
    public static final String COD5000 = "COD5000";
    public static final String COD5000_MENSAJE = "Autenticación Incorrecta";
    public static final String COD5001 = "COD5001";
    public static final String COD5001_MENSAJE = "Acceso Denegado ";


}
