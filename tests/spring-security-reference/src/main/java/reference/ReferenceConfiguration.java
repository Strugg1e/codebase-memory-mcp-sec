package reference;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class ReferenceConfiguration {
    @Bean @Order(2)
    SecurityFilterChain narrow(HttpSecurity http) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/api/admin/**"));
        http.authorizeHttpRequests(a -> a.anyRequest().hasRole("ADMIN"));
        return http.build();
    }
    @Bean @Order(1)
    SecurityFilterChain wide(HttpSecurity http) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/api/**"));
        http.authorizeHttpRequests(a -> a
            .requestMatchers(new AntPathRequestMatcher("/api/public")).permitAll()
            .requestMatchers(new AntPathRequestMatcher("/api/write", "POST")).hasAuthority("write")
            .requestMatchers(new AntPathRequestMatcher("/api/rules/**")).permitAll()
            .requestMatchers(new AntPathRequestMatcher("/api/rules/admin")).hasRole("ADMIN")
            .anyRequest().authenticated());
        return http.build();
    }
    @Bean @Order(3)
    SecurityFilterChain strings(HttpSecurity http) throws Exception {
        http.securityMatcher("/string/**");
        http.authorizeHttpRequests(a -> a.requestMatchers(HttpMethod.POST, "/string/write").denyAll().anyRequest().permitAll());
        return http.build();
    }
    @Bean @Order(4)
    SecurityFilterChain limited(HttpSecurity http) throws Exception {
        http.securityMatcher(new AntPathRequestMatcher("/limited/**"));
        http.authorizeHttpRequests(a -> a.requestMatchers(new AntPathRequestMatcher("/limited/read")).hasRole("ADMIN"));
        return http.build();
    }
    @Bean
    WebSecurityCustomizer ignored() {
        return web -> web.ignoring().requestMatchers(new AntPathRequestMatcher("/static/**"));
    }
}
