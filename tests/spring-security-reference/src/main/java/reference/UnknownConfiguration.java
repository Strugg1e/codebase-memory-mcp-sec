package reference;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class UnknownConfiguration {
    @Bean RequestMatcher headerMatcher() { return request -> "on".equals(request.getHeader("X-Test")); }
    @Bean @Order(1)
    SecurityFilterChain custom(HttpSecurity http, RequestMatcher headerMatcher) throws Exception {
        http.securityMatcher(headerMatcher);
        http.authorizeHttpRequests(a -> a.anyRequest().denyAll());
        return http.build();
    }
    @Bean @Order(2)
    SecurityFilterChain fallback(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return http.build();
    }
}
