package br.com.isaacsilva.tech.oauth2.application.controller;

import br.com.isaacsilva.tech.oauth2.infra.security.authorization.oauth2.github.GitHubOAuth2Service;
import jakarta.annotation.security.PermitAll;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/login/github")
@PermitAll
public class GitHubOAuth2Controller {

    private static final Logger log = LoggerFactory.getLogger(GitHubOAuth2Controller.class);
    private final GitHubOAuth2Service service;

    public GitHubOAuth2Controller(GitHubOAuth2Service service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Void> redirecionarGitHub() {
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
