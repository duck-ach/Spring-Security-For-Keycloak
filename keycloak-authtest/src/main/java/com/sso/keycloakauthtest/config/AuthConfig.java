package com.sso.keycloakauthtest.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
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
        ClientRegistration keycloakOidc = ClientRegistration.withRegistrationId("legacy-oidc") // Spring Security가 내부적으로 어떤 OIDC 클라이언트인지 식별하기 위해 사용하는 ID
                .clientId("legacy-oidc") // Keycloak Client ID
                .clientSecret("LOr6n00hkg43qrUyAcSYfHGkxKhBZQIU") // Keycloak Client Secret
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // 클라이언트가 토큰 요청할 때 사용하는 인증 방식
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST) // 클라이언트가 토큰 요청할 때 사용하는 인증 방식
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) // OAuth2 인증 방식 지정
                .redirectUri("http://localhost:8080/login/oauth2/code/legacy-oidc") // 인증 후 Keycloak이 리디렉션하는 URI
                .scope("openid", "profile", "email") // 요청할 권한의 범위 (required openid)
                .authorizationUri("https://kc1.pream.com:8443/realms/master/protocol/openid-connect/auth") // 인증 코드 요청을 위한 Keycloak의 인증 URL
                .tokenUri("https://kc1.pream.com:8443/realms/master/protocol/openid-connect/token") // 인증 코드로 Access Token을 발급받는 URL
                .userInfoUri("https://kc1.pream.com:8443/realms/master/protocol/openid-connect/userinfo") // Access Token을 이용해서 사용자 정보를 조회하는 URL
                .userNameAttributeName("preferred_username") // Spring Security에서 사용자 이름으로 사용할 속성
                .jwkSetUri("https://kc1.pream.com:8443/realms/master/protocol/openid-connect/certs") // JWT 토큰 서명을 검증하기 위한 공개키를 담고 있는 URL
                .issuerUri("https://kc1.pream.com:8443/realms/master") // 발급자(issuer) URI로, 토큰의 유효성을 검증할 때 사용
                .build();
        System.out.println("keycloakOidc = " + keycloakOidc);

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

                        // Keycloak의 SLO 엔드포인트 URL
                        .singleLogoutServiceLocation("https://kc1.pream.com:8443/realms/master/protocol/saml")
                        .singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT)

                        // Keycloak의 클라이언트 설정에서 "Sign Documents"가 꺼져 있다면 false
                        .wantAuthnRequestsSigned(false)

                        // IdP(Keycloak)가 서명한 SAML Assertion을 검증할 때 사용하는 공개키
                        .verificationX509Credentials(c -> c.add(
                                new Saml2X509Credential(idpCert, Saml2X509Credential.Saml2X509CredentialType.VERIFICATION)
                        ))
                )
                .build();
        System.out.println("SAML registration = " + registration);

        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    // 로그아웃 성공 시 IDP에 SLO 요청 보내는 핸들러
    @Bean
    public LogoutSuccessHandler oidcAndSamlLogoutSuccessHandler(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        return (request, response, authentication) -> {
            if (authentication instanceof Saml2Authentication samlAuth) {
                // 기존 SAML SLO 처리 로직
                RelyingPartyRegistration registration = relyingPartyRegistrationRepository.findByRegistrationId("legacy-saml");
                OpenSaml4LogoutRequestResolver resolver = new OpenSaml4LogoutRequestResolver(relyingPartyRegistrationRepository);
                Saml2LogoutRequest logoutRequest = resolver.resolve(request, samlAuth);
                if (logoutRequest == null) {
                    response.sendRedirect("/");
                    return;
                }
                String samlRequest = URLEncoder.encode(logoutRequest.getSamlRequest(), StandardCharsets.UTF_8);
                String sloEndpoint = registration.getAssertingPartyDetails().getSingleLogoutServiceLocation();
                String relayState = URLEncoder.encode("/", StandardCharsets.UTF_8);
                String redirectUrl = sloEndpoint + "?SAMLRequest=" + samlRequest + "&RelayState=" + relayState;
                response.sendRedirect(redirectUrl);

            } else if(authentication instanceof OAuth2AuthenticationToken oauth2Auth)  {
                // OIDC SLO 처리
                OidcUser oidcUser = (OidcUser) oauth2Auth.getPrincipal();
                String idTokenValue = oidcUser.getIdToken().getTokenValue();
                System.out.println("logout.idTokenValue = " + idTokenValue);
                String logoutUrl = "https://kc1.pream.com:8443/realms/master/protocol/openid-connect/logout"
                        + "?id_token_hint=" + URLEncoder.encode(idTokenValue, StandardCharsets.UTF_8)
                        + "&post_logout_redirect_uri=" + URLEncoder.encode("http://localhost:8080/", StandardCharsets.UTF_8);
                System.out.println("logoutUrl = " + logoutUrl);
                response.sendRedirect(logoutUrl);
            }
        };
    }

    // Spring Security
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) throws Exception {

        http
                // Filter Request 설정
                .authorizeHttpRequests(auth -> auth
                        // permit 설정
                        .requestMatchers("/", "/index.html", "/css/**", "/js/**", "/login/oauth2/code/**", "/oauth2/authorization/**").permitAll()
                        // 위 permit 외에는 인증 필요
                        .anyRequest().authenticated()
                )
                // OIDC
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/oauth2/authorization/legacy-oidc") // OIDC 로그인 진입점 (필요 시 설정)
                        .defaultSuccessUrl("/result", true)
                )
                // SAML
                .saml2Login(saml -> saml
                        // 로그인 페이지 설정
                        .loginPage("/saml2/authenticate/legacy-saml")
                        // 로그인 성공 후 URL 설정
                        .defaultSuccessUrl("/result", true)

                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .logoutSuccessHandler(oidcAndSamlLogoutSuccessHandler(relyingPartyRegistrationRepository))
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                )

                .csrf(csrf -> csrf.disable()); // 개발 중에는 CSRF OFF

        // OAuth2LoginAuthenticationFilter 로그 찍기
        http.addFilterBefore(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
                    throws ServletException, IOException {
                System.out.println(">>> Request URI: " + request.getRequestURI());
                filterChain.doFilter(request, response);
            }
        }, OAuth2LoginAuthenticationFilter.class);


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
