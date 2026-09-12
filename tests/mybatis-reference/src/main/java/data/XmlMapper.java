package data;
import org.apache.ibatis.annotations.Param;
public interface XmlMapper {
    Object plain(@Param("id") long id, @Param("tenant") String tenant);
    Object quoted(@Param("id") long id, @Param("tenant") String tenant);
    Object comments(@Param("id") long id, @Param("tenant") String tenant);
    Object included(@Param("id") long id, @Param("tenant") String tenant);
    Object conditional(@Param("id") long id, @Param("tenant") String tenant);
    Object choice(@Param("id") long id, @Param("tenant") String tenant);
    Object cdata(@Param("id") long id, @Param("tenant") String tenant);
    Object escaped(@Param("id") long id, @Param("tenant") String tenant);
    Object escaped_cdata(@Param("id") long id, @Param("tenant") String tenant);
    Object escaped_include(@Param("id") long id, @Param("tenant") String tenant);
    Object escaped_hash(@Param("id") long id, @Param("tenant") String tenant);
}
