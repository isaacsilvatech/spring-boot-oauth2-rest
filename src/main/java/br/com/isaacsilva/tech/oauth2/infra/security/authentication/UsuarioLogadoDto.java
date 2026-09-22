package br.com.isaacsilva.tech.oauth2.infra.security.authentication;

import br.com.isaacsilva.tech.oauth2.domain.usuario.Usuario;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class UsuarioLogadoDto implements UserDetails {

    private final Usuario usuario;

    public UsuarioLogadoDto(String email) {
        this.usuario = new Usuario();
        this.usuario.setEmail(email);
    }

    @Override
    public String getPassword() {
        return usuario.getSenha();
    }

    @Override
    public String getUsername() {
        return usuario.getSenha();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }
}
