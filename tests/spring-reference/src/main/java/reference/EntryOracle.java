package reference;
import java.util.Collection;
import java.util.ArrayList;
import java.util.Collections;
import org.springframework.core.SpringVersion;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.StaticWebApplicationContext;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.pattern.PathPatternParser;

/** Execute only the checked-in fixture; no HTTP listener or audited target. */
public final class EntryOracle {
    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\"";
    }
    private static String array(Collection<?> values) {
        var strings = new ArrayList<String>();
        for (Object value : values) strings.add(quote(value.toString()));
        Collections.sort(strings);
        return "[" + String.join(",", strings) + "]";
    }
    public static void main(String[] args) {
        if (!"6.2.6".equals(SpringVersion.getVersion())) throw new IllegalStateException("Unpinned Spring version");
        try (var context = new StaticWebApplicationContext()) {
            context.setServletContext(new MockServletContext());
            context.registerSingleton("matrix", MatrixController.class);
            context.registerSingleton("root", RootController.class);
            context.registerSingleton("notAController", NoController.class);
            context.refresh();
            var mapping = new RequestMappingHandlerMapping();
            mapping.setPatternParser(new PathPatternParser());
            mapping.setApplicationContext(context);
            mapping.afterPropertiesSet();
            var rows = new ArrayList<String>();
            mapping.getHandlerMethods().forEach((info, handler) -> rows.add(
                "{\"class_name\":" + quote(handler.getBeanType().getSimpleName()) +
                ",\"handler\":" + quote(handler.getMethod().getName()) +
                ",\"paths\":" + array(info.getPatternValues()) +
                ",\"methods\":" + array(info.getMethodsCondition().getMethods()) +
                ",\"params\":" + array(info.getParamsCondition().getExpressions()) +
                ",\"headers\":" + array(info.getHeadersCondition().getExpressions()) +
                ",\"consumes\":" + array(info.getConsumesCondition().getExpressions()) +
                ",\"produces\":" + array(info.getProducesCondition().getExpressions()) + "}"));
            Collections.sort(rows);
            System.out.println("{\"spring_version\":\"6.2.6\",\"handlers\":[" + String.join(",", rows) + "]}");
        }
    }
}
