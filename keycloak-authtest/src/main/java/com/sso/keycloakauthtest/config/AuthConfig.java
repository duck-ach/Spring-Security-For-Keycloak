package com.sso.keycloakauthtest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * OIDC and SAML (SP) Configuration
 */
@Configuration
public class AuthConfig {


    // OIDC
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration keycloakOidc = ClientRegistration.withRegistrationId("keycloak-oidc")
                .clientId("spring-oidc-client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .authorizationUri("http://localhost:8080/realms/myrealm/protocol/openid-connect/auth")
                .tokenUri("http://localhost:8080/realms/myrealm/protocol/openid-connect/token")
                .userInfoUri("http://localhost:8080/realms/myrealm/protocol/openid-connect/userinfo")
                .userNameAttributeName("preferred_username")
                .jwkSetUri("http://localhost:8080/realms/myrealm/protocol/openid-connect/certs")
                .issuerUri("http://localhost:8080/realms/myrealm")
                .clientName("Keycloak OIDC")
                .build();

        return new InMemoryClientRegistrationRepository(keycloakOidc);
    }

    // SAML(SP)
    @Bean
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws Exception {

        // SP가 사용할 X.509 인증서 설정
        X509Certificate spCert = loadCertificate("classpath:cert/sp.crt");
        PrivateKey spKey = loadPrivateKey("classpath:cert/sp.key");

        // SP가 사용할 서명/복호화 설정
        Saml2X509Credential signingCredential = new Saml2X509Credential(spKey, spCert, Saml2X509Credential.Saml2X509CredentialType.SIGNING);
        Saml2X509Credential decryptionCredential = new Saml2X509Credential(spKey, spCert, Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);

        // Keycloak 의 IdP 인증서 (SAML Metadata 에서 추출)
        X509Certificate idpCert = loadCertificate("classpath:cert/idp.crt");
        
        RelyingPartyRegistration registration = RelyingPartyRegistration

                // 내부 Spring 에서 사용하는 ID (/saml2/authenticate/legacy-saml)
                .withRegistrationId("legacy-saml")

                // ClientId (Keycloak 설정의 Client ID에 해당)
                .entityId("legacy-saml")

                // SP가 Assertion 을 받을 URL (Keycloak 설정의 Master SAML Processing URL에 해당)
                .assertionConsumerServiceLocation("http://localhost:8080/login/saml2/sso/legacy-saml") // acs

                // SP가 SAML Request 에 서명할 때 사용할 Credential
                .signingX509Credentials(c -> c.add(signingCredential))

                // SP가 SAML Response 복호화에 사용할 Credential
                .decryptionX509Credentials(c -> c.add(decryptionCredential))

                // IdP의 메타데이터에 해당하는 정보
                .assertingPartyDetails(party -> party
                        // Keycloak의 Realm SAML Entity ID
                        .entityId("https://kc1.pream.com:8443/realms/master")

                        // Keycloak의 SSO 엔드포인트 URL
                        .singleSignOnServiceLocation("https://kc1.pream.com:8443/realms/master/protocol/saml")

                        // Keycloak의 클라이언트 설정에서 "Sign Documents"가 꺼져 있다면 false
                        .wantAuthnRequestsSigned(false)

                        // IdP(Keycloak)가 서명한 SAML Assertion을 검증할 때 사용하는 공개키
                        .verificationX509Credentials(c -> c.add(
                                new Saml2X509Credential(idpCert, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION)
                        ))
                )
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    // Spring Security
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Filter Request 설정
                .authorizeHttpRequests(auth -> auth
                        // permit 설정
                        .requestMatchers("/", "/index.html", "/css/**", "/js/**").permitAll()
                        // 위 permit 외에는 인증 필요
                        .anyRequest().authenticated()
                )
                .saml2Login(saml -> saml
                        // 로그인 페이지 설정
                        .loginPage("/saml2/authenticate/legacy-saml")
                        // 로그인 성공 후 URL 설정
                        .defaultSuccessUrl("/result", true)

                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )
                .csrf(csrf -> csrf.disable()); // 개발 중에는 CSRF 꺼두세요

        return http.build();
    }

    // Certificate
    private X509Certificate loadCertificate(String location) throws Exception {
        Resource resource = new DefaultResourceLoader().getResource(location);
        try (InputStream in = resource.getInputStream()) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(in);
        }
    }

    // PrivateKey
    private PrivateKey loadPrivateKey(String location) throws Exception {
        Resource resource = new DefaultResourceLoader().getResource(location);
        String key = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
}
