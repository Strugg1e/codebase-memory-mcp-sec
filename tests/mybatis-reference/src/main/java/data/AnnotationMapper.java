package data;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
public interface AnnotationMapper {
    @Select("SELECT * FROM orders WHERE id=#{id} AND tenant_id=#{tenant}")
    Object plain(@Param("id") long id, @Param("tenant") String tenant);
    @Select("SELECT * FROM orders WHERE id=#{id} AND tenant_id='${tenant}'")
    Object quoted(@Param("id") long id, @Param("tenant") String tenant);
    @Select({"SELECT * FROM orders", "WHERE id=#{id}", "AND tenant_id=#{tenant}"})
    Object array(@Param("id") long id, @Param("tenant") String tenant);
    @Select("SELECT '#{tenant}' FROM orders WHERE id=#{id} /* ${tenant} */")
    Object comments(@Param("id") long id, @Param("tenant") String tenant);
}
