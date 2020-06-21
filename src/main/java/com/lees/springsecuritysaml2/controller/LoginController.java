package com.lees.springsecuritysaml2.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


@Controller
public class LoginController {

    @GetMapping("/")
    public String getIndexPage(Model model) throws Exception {
        Saml2Authentication auth = (Saml2Authentication) SecurityContextHolder.getContext().getAuthentication();
        List<String> roleNames = auth.getAuthorities().stream().
            map(authority -> authority.getAuthority()).
            collect(Collectors.toList());
        model.addAttribute("username", auth.getName());
        model.addAttribute("roleNames", roleNames);
        return "index";
    }

    @Autowired
    private RelyingPartyRegistrationRepository relyingParties;

    @GetMapping("/login")
    public void login(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String registrationId = "ssocircle";
        relyingParties.findByRegistrationId(registrationId).getProviderDetails().getWebSsoUrl();
        response.sendRedirect("/saml2/authenticate/" + registrationId);
    }

}