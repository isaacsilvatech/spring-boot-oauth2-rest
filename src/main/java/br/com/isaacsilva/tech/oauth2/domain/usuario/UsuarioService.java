package br.com.isaacsilva.tech.oauth2.domain.usuario;

import br.com.isaacsilva.tech.oauth2.infra.security.authentication.UsuarioLogadoDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UsuarioService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmailIgnoreCase(email).orElseThrow(() -> new UsernameNotFoundException("O usuário não foi encontrado!"));;
        return new UsuarioLogadoDto(usuario);
    }
}
