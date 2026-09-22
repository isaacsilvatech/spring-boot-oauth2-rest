package br.com.isaacsilva.tech.oauth2.application.controller;

import br.com.isaacsilva.tech.oauth2.infra.security.authorization.oauth2.google.GoogleOAuth2Service;
import jakarta.annotation.security.PermitAll;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/login/google")
@PermitAll
public class GoogleOAuth2Controller {

    private final GoogleOAuth2Service service;

    public GoogleOAuth2Controller(GoogleOAuth2Service service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Void> redirecionar() {
        String url = service.gerarUrl();
        var headers = new HttpHeaders();
        headers.setLocation(URI.create(url));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/autorizado")
    public ResponseEntity<String> obterToken(@RequestParam("code") String code) {
        var token = service.getApplicationAcessToken(code);
        return ResponseEntity.ok(token);
    }
}
