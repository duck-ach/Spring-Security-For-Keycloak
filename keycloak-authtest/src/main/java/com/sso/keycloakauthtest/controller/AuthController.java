package com.sso.keycloakauthtest.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@Controller
public class AuthController {

    @GetMapping("/")
    public String index() {

        return "index";
    }

    @GetMapping("/result")
    public String result(Principal principal, Model model, HttpServletRequest request) {

        Map<String,Object> strobj = new HashMap<>();
        Enumeration e = request.getHeaderNames();
        while ( e.hasMoreElements() ) {
            String names = (String)e.nextElement();
            String value = request.getHeader(names);
            strobj.put(names, value);
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        model.addAttribute("header", strobj);
        System.out.println("인증방식 = " + auth);
        if (auth != null && auth.isAuthenticated()) {
            if (principal instanceof OAuth2AuthenticationToken oAuthUser) {
                model.addAttribute("authType", "OIDC");
                model.addAttribute("name", oAuthUser.getName());
            } else if (principal instanceof Saml2Authentication) {
                Saml2Authentication samlPrincipal = (Saml2Authentication)auth;
                model.addAttribute("authType", "SAML");
                model.addAttribute("name", samlPrincipal.getName());
            } else {
                model.addAttribute("authType", "UNKNOWN");
                model.addAttribute("name", principal.getName());
            }
        }
        return "result";
    }
}