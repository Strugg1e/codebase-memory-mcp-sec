package reference;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

/** Runs only checked-in fixtures, no HTTP listener, target repository, or database. */
public final class SecurityOracle {
    private static final Authentication GUEST = new AnonymousAuthenticationToken("test", "guest", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private static final Authentication MEMBER = UsernamePasswordAuthenticationToken.authenticated("member", "test", AuthorityUtils.createAuthorityList("read"));
    private static final Authentication ADMIN = UsernamePasswordAuthenticationToken.authenticated("admin", "test", AuthorityUtils.createAuthorityList("ROLE_ADMIN", "read", "write"));
    @SuppressWarnings("unchecked")
    private static Map<String,Object> observe(AnnotationConfigWebApplicationContext context, String config, String method, String path, String header) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path); request.setPathInfo(null);
        if (header != null) request.addHeader("X-Test", header);
        FilterChainProxy proxy = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
        Map<String,Object> out = new LinkedHashMap<>();
        out.put("config",config); out.put("method",method); out.put("path",path); out.put("header",header);
        SecurityFilterChain selected = null;
        for (SecurityFilterChain chain : proxy.getFilterChains()) if (chain.matches(request)) { selected=chain; break; }
        if (selected == null) { out.put("status","no_chain"); return out; }
        if (selected.getFilters().isEmpty()) { out.put("status","ignored"); return out; }
        String bean = null;
        for (Map.Entry<String,SecurityFilterChain> item : context.getBeansOfType(SecurityFilterChain.class).entrySet()) if (item.getValue()==selected) bean=item.getKey();
        if (bean==null) throw new AssertionError("Selected chain is not a registered fixture bean");
        out.put("status","selected"); out.put("factory",bean);
        AuthorizationFilter filter = selected.getFilters().stream().filter(f -> f instanceof AuthorizationFilter).map(f -> (AuthorizationFilter)f).findFirst().orElseThrow();
        AuthorizationManager<HttpServletRequest> manager = filter.getAuthorizationManager();
        // Fixed-version test inspection: use the actual manager's registered mappings, not a second source parser.
        Field mappings = manager.getClass().getDeclaredField("mappings"); mappings.setAccessible(true);
        List<RequestMatcherEntry<?>> entries = (List<RequestMatcherEntry<?>>) mappings.get(manager);
        int index=-1;
        for(int i=0;i<entries.size();i++) if(entries.get(i).getRequestMatcher().matches(request)){index=i;break;}
        out.put("rule_index",index);
        out.put("guest_granted",manager.authorize(() -> GUEST,request).isGranted());
        out.put("member_granted",manager.authorize(() -> MEMBER,request).isGranted());
        out.put("admin_granted",manager.authorize(() -> ADMIN,request).isGranted());
        return out;
    }
    private static String json(Object value) {
        if (value==null) return "null";
        if (value instanceof String s) return "\""+s.replace("\\","\\\\").replace("\"","\\\"")+"\"";
        if (value instanceof Map<?,?> map) { List<String> parts=new ArrayList<>(); map.forEach((k,v)->parts.add(json(k)+":"+json(v))); return "{"+String.join(",",parts)+"}"; }
        if (value instanceof List<?> list) { List<String> parts=new ArrayList<>(); list.forEach(v->parts.add(json(v))); return "["+String.join(",",parts)+"]"; }
        return value.toString();
    }
    public static void main(String[] args) throws Exception {
        List<Map<String,Object>> cases=new ArrayList<>();
        try(AnnotationConfigWebApplicationContext c=new AnnotationConfigWebApplicationContext()) {
            c.setServletContext(new MockServletContext());c.register(ReferenceConfiguration.class);c.refresh();
            for(String[] request:new String[][]{{"GET","/api/public"},{"GET","/api/admin/orders"},{"GET","/api/write"},{"POST","/api/write"},{"GET","/api/rules/admin"},{"GET","/api"},{"HEAD","/api/public"},{"GET","/static/logo"},{"GET","/static"},{"GET","/outside"},{"GET","/API/public"},{"GET","/api/public/"},{"POST","/string/write"},{"GET","/string/write"},{"GET","/limited/read"},{"GET","/limited/absent"}})
                cases.add(observe(c,"ReferenceConfiguration.java",request[0],request[1],null));
        }
        try(AnnotationConfigWebApplicationContext c=new AnnotationConfigWebApplicationContext()) {
            c.setServletContext(new MockServletContext());c.register(UnknownConfiguration.class);c.refresh();
            cases.add(observe(c,"UnknownConfiguration.java","GET","/api/x","on"));
            cases.add(observe(c,"UnknownConfiguration.java","GET","/api/x","off"));
        }
        System.out.println(json(Map.of("spring_security_version","6.5.0","cases",cases)));
    }
}
