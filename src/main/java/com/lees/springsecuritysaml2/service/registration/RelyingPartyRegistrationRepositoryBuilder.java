package com.lees.springsecuritysaml2.service.registration;


import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Identityprovider.Verification;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Registration;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties.Registration.Signing;
import org.springframework.core.io.Resource;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class RelyingPartyRegistrationRepositoryBuilder {

    private final static RelyingPartyRegistrationRepositoryBuilder INSTANCE;
    static {
        INSTANCE = new RelyingPartyRegistrationRepositoryBuilder();
    }

    public static RelyingPartyRegistrationRepository build(final Saml2RelyingPartyProperties properties) {
        List<RelyingPartyRegistration> registrations = properties.getRegistration().entrySet().stream().
            map(INSTANCE::asRegistration).collect(Collectors.toList());
        return new InMemoryRelyingPartyRegistrationRepository(registrations);
    }

    private RelyingPartyRegistration asRegistration(final Map.Entry<String, Registration> entry) {

        String id = entry.getKey();
        Saml2RelyingPartyProperties.Registration properties = entry.getValue();
        boolean signRequest = properties.getIdentityprovider().getSinglesignon().isSignRequest();
        this.validateSigningCredentials(properties, signRequest);

        String entityId = "com:lees:john:spring:sp";
        String webSsoEndpoint = "https://idp.ssocircle.com:443/sso/SSORedirect/metaAlias/publicidp";

        RelyingPartyRegistration.Builder builder = RelyingPartyRegistration.withRegistrationId(id);
        builder.assertionConsumerServiceUrlTemplate("{baseUrl}/login/saml2/sso/{registrationId}");
        builder.localEntityIdTemplate(entityId);
        builder.providerDetails((details) -> details.webSsoUrl(webSsoEndpoint));
        builder.providerDetails((details) -> details.entityId(entityId));
        builder.providerDetails((details) -> details.binding(properties.getIdentityprovider().getSinglesignon().getBinding()));
        builder.providerDetails((details) -> details.signAuthNRequest(signRequest));
        builder.credentials((credentials) -> credentials.addAll(this.asCredentials(properties)));
        return builder.build();
    }

    private void validateSigningCredentials(final Registration properties, final boolean signRequest) {
        if (signRequest) {
            Assert.state(!properties.getSigning().getCredentials().isEmpty(),
                    "Signing credentials must not be empty when authentication requests require signing.");
        }
    }

    private List<Saml2X509Credential> asCredentials(final Registration properties) {
        List<Saml2X509Credential> credentials = new ArrayList<>();
        properties.getSigning().getCredentials().stream().map(this::asSigningCredential).forEach(credentials::add);
        properties.getIdentityprovider().getVerification().getCredentials().stream().map(
                this::asVerificationCredential).forEach(credentials::add);
        return credentials;
    }

    private Saml2X509Credential asSigningCredential(final Signing.Credential properties) {
        RSAPrivateKey privateKey = this.readPrivateKey(properties.getPrivateKeyLocation());
        X509Certificate certificate = this.readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(privateKey, certificate, Saml2X509Credential.Saml2X509CredentialType.SIGNING,
                Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
    }

    private Saml2X509Credential asVerificationCredential(final Verification.Credential properties) {
        X509Certificate certificate = this.readCertificate(properties.getCertificateLocation());
        return new Saml2X509Credential(certificate, Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION,
                Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);
    }

    private RSAPrivateKey readPrivateKey(final Resource location) {
        Assert.state(location != null, "No private key location specified");
        Assert.state(location.exists(), "Private key location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return RsaKeyConverters.pkcs8().convert(inputStream);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

    private X509Certificate readCertificate(final Resource location) {
        Assert.state(location != null, "No certificate location specified");
        Assert.state(location.exists(), "Certificate  location '" + location + "' does not exist");
        try (InputStream inputStream = location.getInputStream()) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex);
        }
    }

}