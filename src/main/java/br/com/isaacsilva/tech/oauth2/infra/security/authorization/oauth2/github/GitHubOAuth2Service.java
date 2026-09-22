package br.com.isaacsilva.tech.oauth2.infra.security.authorization.oauth2.github;

import br.com.isaacsilva.tech.oauth2.infra.security.authentication.TokenService;
import br.com.isaacsilva.tech.oauth2.infra.security.authentication.UsuarioLogadoDto;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.Map;

@Service
public class GitHubOAuth2Service {

    private final GithubOAuth2Properties properties;
    private final RestClient restClient;

    private final TokenService tokenService;

    public GitHubOAuth2Service(GithubOAuth2Properties properties, TokenService tokenService) {
        this.properties = properties;
        this.restClient = RestClient.create();
        this.tokenService = tokenService;
    }

    public String gerarUrl() {
        return UriComponentsBuilder.fromUriString(properties.urlAuthorize())
                .queryParam("client_id", properties.id())
                .queryParam("redirect_uri", properties.redirectUri())
                .queryParam("scope", properties.scope())
                .toUriString();
    }

    private String obterToken(String code) {
        var resposta = restClient.post()
                .uri(properties.urlAcessToken())
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .body(Map.of(
                        "code", code,
                        "client_id", properties.id(),
                        "client_secret", properties.secret(),
                        "redirect_uri", properties.redirectUri()
                ))
                .retrieve().body(GitHubAcessToken.class);

        return resposta.acessToken();
    }

    private DadosEmail obterEmail(String code) {
        var token = obterToken(code);

        var resposta = restClient.get().uri(properties.urlEmail())
                .headers(headers -> {
                    headers.setBearerAuth(token);
                    headers.set("X-GitHub-Api-Version", "2026-03-10");
                    headers.set("Accept", "application/vnd.github+json");
                })
                .retrieve()
                .body(DadosEmail[].class);

        return Arrays.stream(resposta).filter(d -> d.primary() && d.verified()).findFirst().orElse(null);
    }

    public String getApplicationAcessToken(String code) {
        DadosEmail dados = obterEmail(code);
        return tokenService.genarateAccessToken(new UsuarioLogadoDto(dados.email()));
    }
}

@ConfigurationProperties(prefix = "application.api.security.oauth2.github.client")
record GithubOAuth2Properties(
        String urlAuthorize,
        String urlAcessToken,
        String id,
        String secret,
        String redirectUri,
        String scope,
        String urlUser,
        String urlEmail,
        String responseType
) {
}

@Configuration
@EnableConfigurationProperties(GithubOAuth2Properties.class)
class GithubOAuth2Config {
}

record GitHubAcessToken(@JsonProperty("access_token") String acessToken) {
}

record DadosEmail(String email, Boolean primary, Boolean verified, String visibility) {
}