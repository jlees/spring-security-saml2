package com.lees.springsecuritysaml2.config;

import com.lees.springsecuritysaml2.auth.Saml2AuthenticationProvider;
import com.lees.springsecuritysaml2.service.registration.RelyingPartyRegistrationRepositoryBuilder;
import org.springframework.boot.autoconfigure.security.saml2.Saml2RelyingPartyProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository(Saml2RelyingPartyProperties properties) {
        return RelyingPartyRegistrationRepositoryBuilder.build(properties);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authenticationProvider(new Saml2AuthenticationProvider());

        http.authorizeRequests(authz -> authz
                .mvcMatchers("/login").permitAll() // here
                .anyRequest().authenticated())
                .saml2Login(saml2 -> saml2.loginPage("/login"));// and here
    }

}