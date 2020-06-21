package com.lees.springsecuritysaml2.auth;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;


public class Saml2AuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            try {
                Saml2AuthenticationToken auth = (Saml2AuthenticationToken) authentication;
                String xml = auth.getSaml2Response();
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document document = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
                Element element = document.getDocumentElement();
                Response response = (Response) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().
                    getUnmarshaller(element).unmarshall(element);
                Assertion assertion = response.getAssertions().get(0);
                List<Attribute> attributes = new ArrayList<>();
                assertion.getAttributeStatements().stream().
                    forEach(attributeStatement -> attributes.addAll(attributeStatement.getAttributes()));
                Collection<? extends GrantedAuthority> authorities = attributes.stream().
                    map(attribute -> new SimpleGrantedAuthority("ROLE_" + attribute.getName())).
                    collect(Collectors.toList());
                return new Saml2Authentication(()->assertion.getSubject().getNameID().getValue(), xml, authorities);
            } catch (Exception ex) {
                return null;
            }
    }

    @Override
    public boolean supports(Class<?> authentication) {
            return authentication != null && Saml2AuthenticationToken.class.isAssignableFrom(authentication);
    }

}