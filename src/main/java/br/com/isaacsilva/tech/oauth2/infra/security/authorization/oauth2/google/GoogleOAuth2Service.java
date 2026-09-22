package br.com.isaacsilva.tech.oauth2.infra.security.authorization.oauth2.google;

import br.com.isaacsilva.tech.oauth2.domain.usuario.Usuario;
import br.com.isaacsilva.tech.oauth2.infra.security.authentication.TokenService;
import br.com.isaacsilva.tech.oauth2.infra.security.authentication.UsuarioLogadoDto;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Map;

@Service
public class GoogleOAuth2Service {

    private final GoogleOAuth2Properties properties;
    private final RestClient restClient;

    private final TokenService tokenService;

    public GoogleOAuth2Service(GoogleOAuth2Properties properties, TokenService tokenService) {
        this.properties = properties;
        this.restClient = RestClient.create();
        this.tokenService = tokenService;
    }

    public String gerarUrl() {
        return UriComponentsBuilder.fromUriString(properties.urlAuthorize())
                .queryParam("client_id", properties.id())
                .queryParam("redirect_uri", properties.redirectUri())
                .queryParam("scope", properties.scope())
                .queryParam("response_type", properties.responseType())
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
                        "redirect_uri", properties.redirectUri(),
                        "grant_type", properties.gratType()
                ))
                .retrieve().body(GoogleOAuth2AcessToken.class);

        return resposta.tokenId();
    }

    private String obterEmail(String code) {
        var tokenId = obterToken(code);
        return tokenService.getEmailFromToken(tokenId);
    }

    public String getApplicationAcessToken(String code) {
        String email = obterEmail(code);
        return tokenService.genarateAccessToken(new UsuarioLogadoDto(email));
    }
}

@ConfigurationProperties(prefix = "application.api.security.oauth2.google.client")
record GoogleOAuth2Properties(
        String urlAuthorize,
        String urlAcessToken,
        String id,
        String secret,
        String redirectUri,
        String scope,
        String responseType,
        String gratType
) {
}

@Configuration
@EnableConfigurationProperties(GoogleOAuth2Properties.class)
class GoogleOAuth2Config {
}

@JsonIgnoreProperties
record GoogleOAuth2AcessToken(@JsonProperty("id_token") String tokenId) {
}