package med.voll.web_application.infra.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import med.voll.web_application.domain.usuario.Usuario;
import med.voll.web_application.domain.usuario.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
/*
* -- OncePerRequestFilter:
*
* No código, podemos perceber que o filtro é criado a partir do OncePerRequestFilter, que garante que o filtro seja
* executado apenas uma vez por requisição HTTP, mesmo que outros filtros também estejam presentes na cadeia de filtros.
* Ou seja, mesmo que a requisição seja encaminhada para outros filtros ou camadas dentro da aplicação, o OncePerRequestFilter
* garante que a lógica de filtragem será aplicada apenas uma vez, evitando reprocessamento.
*/
@Component
public class FiltroAlteracaoSenha extends OncePerRequestFilter {
    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (request.getRequestURI().contains(".css") || request.getRequestURI().contains(".png")) {
            chain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated() && !request.getRequestURI().equals("/alterar-senha")) {
            Usuario usuario = (Usuario) auth.getPrincipal();
            if (!usuario.getSenhaAlterada()) {
                response.sendRedirect("/alterar-senha");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
