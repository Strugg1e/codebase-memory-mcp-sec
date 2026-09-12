package reference;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.ibatis.builder.xml.XMLMapperBuilder;
import org.apache.ibatis.mapping.BoundSql;
import org.apache.ibatis.mapping.ParameterMapping;
import org.apache.ibatis.session.Configuration;

/** Only the checked-in fixtures are interpreted; no database or arbitrary input. */
public final class TemplateOracle {
    private static String quote(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
    private static String result(Configuration cfg, String kind, String owner, String method, boolean present) {
        Map<String,Object> params = new LinkedHashMap<>();
        params.put("id", 7L); params.put("tenant", present ? "MB_SENTINEL" : null);
        BoundSql bound = cfg.getMappedStatement(owner + "." + method).getBoundSql(params);
        List<String> names = new ArrayList<>();
        for (ParameterMapping p : bound.getParameterMappings()) names.add(quote(p.getProperty()));
        return "{\"kind\":" + quote(kind) + ",\"owner\":" + quote(owner)
            + ",\"method\":" + quote(method) + ",\"tenant_present\":" + present
            + ",\"sql\":" + quote(bound.getSql()) + ",\"parameters\":[" + String.join(",", names) + "]}";
    }
    public static void main(String[] args) throws Exception {
        // This path is part of this repository's test fixture, not caller-controlled.
        Configuration xml = new Configuration();
        try (InputStream in = Files.newInputStream(Path.of("tests/mybatis-reference/fixtures/XmlMapper.xml"))) {
            new XMLMapperBuilder(in, xml, "fixture.xml", xml.getSqlFragments()).parse();
        }
        Configuration annotations = new Configuration(); annotations.addMapper(data.AnnotationMapper.class);
        List<String> cases = new ArrayList<>();
        for (String method : List.of("plain", "quoted", "comments", "included", "conditional", "choice", "cdata", "escaped")) {
            cases.add(result(xml, "xml", "data.XmlMapper", method, true));
            if (method.equals("conditional") || method.equals("choice")) cases.add(result(xml, "xml", "data.XmlMapper", method, false));
        }
        for (String method : List.of("plain", "quoted", "array", "comments"))
            cases.add(result(annotations, "annotation", "data.AnnotationMapper", method, true));
        System.out.println("{\"mybatis_version\":\"3.5.19\",\"cases\":[" + String.join(",", cases) + "]}");
    }
}
