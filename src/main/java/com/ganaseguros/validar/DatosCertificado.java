package com.ganaseguros.validar;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

public class DatosCertificado {
    private final Map<String, String> subject, issuer;
    private String label;

    //Otros datos
    private X509Certificate cert = null;

    private String policyCert;

    public DatosCertificado() {
        subject = new TreeMap<>();
        issuer = new TreeMap<>();
    }

    /**
     * Constructor por parámetro
     *
     * @param cert Certificado
     * @throws CertificateEncodingException Excepción en la codificación
     */
    public DatosCertificado(X509Certificate cert) throws CertificateEncodingException {
        X500Name x500Name = new JcaX509CertificateHolder(cert).getSubject();
        subject = new TreeMap<>();
        for(RDN rdn : x500Name.getRDNs()) {
            subject.put(rdn.getFirst().getType().getId(), IETFUtils.valueToString(rdn.getFirst().getValue()));
        }
        X500Name x500IssuerName = new JcaX509CertificateHolder(cert).getIssuer();
        issuer = new TreeMap<>();
        for(RDN rdn : x500IssuerName.getRDNs()) {
            issuer.put(rdn.getFirst().getType().getId(), IETFUtils.valueToString(rdn.getFirst().getValue()));
        }
        this.cert = cert;

        byte[] policyBytes = cert.getExtensionValue("2.5.29.32");
        if (policyBytes == null) {
            this.policyCert = null;
        } else {
            try {
                CertificatePolicies policies = CertificatePolicies.getInstance(X509ExtensionUtil.fromExtensionValue(policyBytes));
                PolicyInformation[] policyInformation = policies.getPolicyInformation();
                for (PolicyInformation pInfo : policyInformation) {
                    if (pInfo.getPolicyIdentifier().toString().length() == 34) {
                        this.policyCert = pInfo.getPolicyIdentifier().toString();
                        break;
                    }
                }
            } catch (IOException ex) {
                this.policyCert = null;
                //this.tipoFirma = null;
            }
        }
    }

    /**
     * Constructor con identificador
     * 
     * @param label Etiqueta que identifica al certificado
     * @param cert Certificado 
     * @throws CertificateEncodingException En caso de que el certificado sea inválido.
     */
    public DatosCertificado(String label, X509Certificate cert) throws CertificateEncodingException {
        this(cert);
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public String getTipoDocumentoSubject() {
        return subject.get("2.5.4.46");
    }

    public void setTipoDocumentoSubject(String tipoDocumento) {
        subject.put("2.5.4.46", tipoDocumento);
    }

    public String getNumeroDocumentoSubject() {
        return subject.get("1.3.6.1.1.1.1.0");
    }

    public void setNumeroDocumentoSubject(String numeroDocumento) throws ValueException {
        if (numeroDocumento.length() < 5 || !Pattern.matches("[0-9]+", numeroDocumento)) {
            throw new ValueException("El número de documento debe ser de al menos 5 dígitos.");
        }
        subject.put("1.3.6.1.1.1.1.0", numeroDocumento);
    }

    public String getComplementoSubject() {
        if (subject.containsKey("0.9.2342.19200300.100.1.1")) {
            return subject.get("0.9.2342.19200300.100.1.1");
        }
        return "";
    }

    public void setComplementoSubject(String complemento) throws ValueException {
        if (!Pattern.matches("[0-9a-zA-Z]*", complemento)) {
            throw new ValueException("El complemento solo puede contener letras y números.");
        }
        subject.put("0.9.2342.19200300.100.1.1", complemento);
    }

    public String getNombreComunSubject() {
        return subject.get("2.5.4.3");
    }

    public void setNombreComunSubject(String nombreComun) throws ValueException {
        if (nombreComun.length() < 5) {
            throw new ValueException("Por favor introduzca su nombre.");
        }
        subject.put("2.5.4.3", nombreComun);
    }

    public String getCorreoSubject() {
        if (subject.containsKey("1.2.840.113549.1.9.1")) {
            return subject.get("1.2.840.113549.1.9.1");
        } else {
            if (cert != null) {
                byte[] cdp = cert.getExtensionValue("2.5.29.17");
                if (cdp == null) {
                    return "";
                } else {
                    GeneralNames generalNames;
                    try {
                        generalNames = GeneralNames.getInstance(X509ExtensionUtil.fromExtensionValue(cdp));
                        GeneralName[] gg = generalNames.getNames();
                        for (GeneralName generalName : gg) {
                            return generalName.getName().toString();
                        }
                    } catch (IOException ignore) {
                    }
                }
            }
        }
        return "";
    }

    public void setCorreoSubject(String correo) throws ValueException {
        if (correo.length() < 2 || !Pattern.matches("^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$", correo)) {
            throw new ValueException("Por favor introduzca un correo válido.");
        }
        subject.put("1.2.840.113549.1.9.1", correo);
    }

    public String getOrganizacionSubject() {
        if (subject.containsKey("2.5.4.10")) {
            return subject.get("2.5.4.10");
        }
        return "";
    }

    public void setOrganizacionSubject(String organizacion) throws ValueException {
        if (organizacion.length() < 2) {
            throw new ValueException("Por favor introduzca la razón social de su organización.");
        }
        subject.put("2.5.4.10", organizacion);
    }

    public String getUnidadOrganizacionalSubject() {
        if (subject.containsKey("2.5.4.11")) {
            return subject.get("2.5.4.11");
        }
        return "";
    }

    public void setUnidadOrganizacionalSubject(String unidadOrganizacional) throws ValueException {
        if (unidadOrganizacional.length() < 2) {
            throw new ValueException("Por favor introduzca la unidad organizacional.");
        }
        subject.put("2.5.4.11", unidadOrganizacional);
    }

    public String getCargoSubject() {
        if (subject.containsKey("2.5.4.12")) {
            return subject.get("2.5.4.12");
        }
        return "";
    }

    public void setCargoSubject(String cargo) throws ValueException {
        if (cargo.length() < 2) {
            throw new ValueException("Por favor introduzca su cargo.");
        }
        subject.put("2.5.4.12", cargo);
    }

    public String getNitSubject() {
        if (subject.containsKey("2.5.4.5")) {
            return subject.get("2.5.4.5");
        } else {
            return "";
        }
    }

    public void setNitSubject(String nit) {
        subject.put("2.5.4.5", nit);
    }

    public String getDescripcionSubject() {
        return subject.get("2.5.4.13");
    }

    public void setDescripcionSubject(String descripcion) {
        subject.put("2.5.4.13", descripcion);
    }

    public String getPaisSubject() {
        return subject.get("2.5.4.6");
    }

    public void setPaisSubject(String pais) {
        subject.put("2.5.4.6", pais);
    }

    public String getNombreComunIssuer() {
        return issuer.get("2.5.4.3");
    }

    public String getOrganizacionIssuer() {
        return issuer.get("2.5.4.10");
    }

    public Date getInicioValidez() {
        return cert.getNotBefore();
    }

    public Date getFinValidez() {
        return cert.getNotAfter();
    }

    public String getPersona() {
        if (policyCert != null && policyCert.length() == 34) {
            switch (policyCert.charAt(31)) {
                case '0':
                    return "Certificado de Persona Jurídica";
                case '1':
                    return "Certificado de Persona Natural";
                default:
                    return null;
            }
        }
        return null;
    }

    public String getAlmacenamiento() {
        if (policyCert != null && policyCert.length() == 34) {
            switch (policyCert.charAt(29)) {
                case '0':
                    return "Nivel de Seguridad Normal (Emitido por Software)";
                case '1':
                    return "Nivel de Seguridad Alto (Emitido por Hardware)";
                default:
                    return null;
            }
        }
        return null;
    }

    public String getTipoFirma() {
        if (policyCert != null && policyCert.length() == 34) {
            switch (policyCert.charAt(33)) {
                case '0':
                    return "Firma Simple";
                case '1':
                    return "Firma Automática";
            }
        }
        return null;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public X509Certificate buildCert(KeyPair keyPair) throws OperatorCreationException, CertIOException, CertificateException {
        X500NameBuilder nameBuilder = new X500NameBuilder(RFC4519Style.INSTANCE);
        for (Map.Entry<String, String> e : subject.entrySet()) {
            nameBuilder.addRDN(new ASN1ObjectIdentifier(e.getKey()), e.getValue());
        }
        X500Name x500Name = nameBuilder.build();
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 1000L * 60L * 60L * 60L * 24L * 365L);
        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500Name, BigInteger.valueOf(notBefore.getTime()), notBefore, notAfter, x500Name, keyPair.getPublic());
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()));
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(keyPair.getPublic()));
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certificateBuilder.build(contentSigner));
    }

    /**
     * Creates the hash value of the public key.
     *
     * @param publicKey of the certificate
     *
     * @return SubjectKeyIdentifier hash
     *
     * @throws OperatorCreationException Excepción durante la creación
     */
    private SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    /**
     * Creates the hash value of the authority public key.
     *
     * @param publicKey of the authority certificate
     *
     * @return AuthorityKeyIdentifier hash
     *
     * @throws OperatorCreationException Excepción durante la creación
     */
    private AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)
            throws OperatorCreationException
    {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

    public class ValueException extends Exception {
        public ValueException(String message) {
            super(message);
        }
    }

    @Override
    public String toString() {
        if (getCargoSubject().equals("")) {
            return getNombreComunSubject();
        } else {
            return getNombreComunSubject() + "\n" + getCargoSubject();
        }
    }
}
