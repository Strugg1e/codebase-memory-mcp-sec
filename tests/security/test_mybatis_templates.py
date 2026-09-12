"""Real-parser/MCP template regressions. No target OGNL or SQL is executed."""
from __future__ import annotations
import json
import unittest
import test_operation as base

SQL = 'SELECT * FROM orders WHERE id = #{id} AND tenant_id = #{tenant}'


def mapper(sql=SQL, annotation='Select', array=False):
    expr = '{' + ', '.join(json.dumps(s, ensure_ascii=False) for s in sql) + '}' if array else json.dumps(sql, ensure_ascii=False)
    return base.MAPPER.replace('import org.apache.ibatis.annotations.Param;',
        f'import org.apache.ibatis.annotations.Param; import org.apache.ibatis.annotations.{annotation};').replace(
        'Object load(', f'@{annotation}({expr}) Object load(')


class Templates(unittest.TestCase):
    def session(self, **kwargs):
        s=base.Session(self, **kwargs); self.addCleanup(s.close); return s
    def xml(self, sql=SQL, extra='', **kw):
        x=f'<mapper namespace="data.OrderMapper"><select id="load" resultType="map">{sql}</select>{extra}</mapper>'
        return self.session(xml=x, **kw).inspect()
    def annotation(self, source=None, **kw):
        s=self.session(mapper=source or mapper(), **kw)
        return s.call('inspect_operation_context', {**s.anchor(), 'mapper_path':'OrderMapper.java','mapping_format':'annotation'})
    def marks(self, r): return r['mybatis']['parameter_occurrences']
    def assert_refs(self, s, r):
        def visit(v):
            if isinstance(v,dict):
                if {'path','sha256','start_byte','end_byte','text_prefix'} <= v.keys():
                    data=s.sources[v['path']].encode(); self.assertEqual(base.digest(data),v['sha256'])
                    raw=data[v['start_byte']:v['end_byte']];self.assertTrue(raw.decode().startswith(v['text_prefix']))
                    if not v['text_truncated']:self.assertEqual(raw.decode(),v['text_prefix'])
                for x in v.values():visit(x)
            elif isinstance(v,list):
                for x in v:visit(x)
        visit(r)
    def test_xml_simple_markers_and_links(self):
        r=self.xml(); self.assertEqual([p['argument_index'] for p in self.marks(r)], [0,1])
        self.assertEqual(r['mybatis']['template_analysis']['stage'],'template_before_sql_lexing')
        for p in self.marks(r):self.assertEqual(p['value_origin_ref']['argument_index'],p['argument_index'])
    def test_quoted_substitution(self):
        r=self.xml(SQL.replace('#{tenant}',"'${tenant}'"));p=self.marks(r)[1]
        self.assertEqual(p['form'],'text_substitution_marker');self.assertEqual(p['argument_index'],1)
    def test_line_comment_substitution(self):
        self.assertEqual(len(self.marks(self.xml(SQL+' -- ${tenant}\n'))),3)
    def test_block_comment_bound_parameter(self):
        self.assertEqual(len(self.marks(self.xml(SQL+' /* #{tenant} */'))),3)
    def test_xml_comment_not_a_template(self):
        self.assertEqual(len(self.marks(self.xml(SQL+' <!-- #{tenant} -->'))),2)
    def test_cdata_preserves_markers(self):
        self.assertEqual(len(self.marks(self.xml('<![CDATA['+SQL+" AND n='${tenant}']]>") )),3)
    def test_xml_escaped_dollar_survives_property_phase(self):
        r=self.xml(SQL+r' AND note=\${tenant}');self.assertEqual(len(self.marks(r)),3)
        self.assertEqual(self.marks(r)[-1]['processing'],'xml_property_unescape_then_substitution_candidate')
        self.assertEqual(self.marks(r)[-1]['argument_index'],1)
        self.assertEqual(len(r['mybatis']['template_analysis']['escaped_markers']),1)
    def test_double_dollar_escape_is_not_assumed_safe(self):
        r=self.xml(SQL+r' AND note=\\${tenant}');p=self.marks(r)[-1]
        self.assertEqual(p['binding_status'],'preprocessing_not_resolved');self.assertNotIn('argument_index',p)
        self.assertIn('xml_escape_stages_not_resolved',r['gaps'])
    def test_xml_dollar_preprocessing_assumption_visible(self):
        p=self.marks(self.xml(SQL+' ${tenant}'))[-1]
        self.assertEqual(p['parameter_binding_assumption'],'marker_survives_configuration_property_phase')
    def test_annotation_has_no_xml_property_phase(self):
        r=self.annotation(mapper(SQL+' ${tenant}'))
        self.assertEqual(r['mybatis']['template_analysis']['input_kind'],'plain_annotation_literals')
        self.assertNotIn('parameter_binding_assumption',self.marks(r)[-1])
    def test_escaped_include_dollar_retains_site(self):
        r=self.xml('<include refid="a"/>',extra=r"<sql id='a'>SELECT '\${tenant}'</sql>")
        p=self.marks(r)[0];self.assertEqual(p['argument_index'],1);self.assertEqual(len(p['include_sites']),1)
    def test_escaped_cdata_dollar_recovered(self):
        r=self.xml(r"<![CDATA[SELECT '\${tenant}' WHERE id=#{id}]]>")
        self.assertEqual([p['argument_index'] for p in self.marks(r)],[1,0])
    def test_escaped_dollar_at_start_of_segment(self):
        r=self.xml(r'\${tenant}');self.assertEqual(self.marks(r)[0]['argument_index'],1)
    def test_escaped_dollar_exact_source_reference(self):
        s=self.session(xml=base.XML.replace('#{tenant}',r"'\${tenant}'"));r=s.inspect();self.assert_refs(s,r)
        self.assertEqual(self.marks(r)[-1]['escape_source']['text_prefix'],r'\${')
    def test_multiple_escape_prefix_bounded(self):
        r=self.xml(SQL+' ' + '\\'*600+'${tenant}');p=self.marks(r)[-1]
        self.assertTrue(p['escape_source']['text_truncated']);self.assertNotIn('argument_index',p)
    def test_escaped_hash_opener(self):
        self.assertEqual(len(self.marks(self.xml(SQL+r' AND note=\#{tenant}'))),2)
    def test_escaped_close_unknown(self):
        r=self.xml(SQL+r' AND note=${tenant\}x}')
        self.assertIn('escaped_template_expression_not_normalized',r['gaps']);self.assertNotIn('argument_index',self.marks(r)[-1])
    def test_unterminated_marker_gap(self):
        r=self.xml(SQL+' ${tenant');self.assertIn('unterminated_or_cross_segment_template_marker',r['gaps'])
    def test_empty_expression_not_bound(self):
        p=self.marks(self.xml(SQL+' ${}'))[-1];self.assertEqual(p['binding_status'],'unresolved')
    def test_ognl_not_executed(self):
        r=self.xml(SQL+' ${@java.lang.System@getProperty("user.home")}')
        self.assertNotIn('argument_index',self.marks(r)[-1]);self.assertIn('template_expression_not_resolved',r['gaps'])
    def test_whitespace_parameter_name(self):
        self.assertEqual(self.marks(self.xml(SQL.replace('#{tenant}','#{ tenant }')))[1]['argument_index'],1)
    def test_jdbc_options(self):
        self.assertEqual(self.marks(self.xml(SQL.replace('#{tenant}','#{tenant,jdbcType=BIGINT}')))[1]['argument_index'],1)
    def test_text_substitution_comma_not_parameter_option(self):
        self.assertNotIn('argument_index',self.marks(self.xml(SQL+' ${tenant,jdbcType=BIGINT}'))[-1])
    def test_dotted_path_not_whole_argument(self):
        p=self.marks(self.xml(SQL.replace('#{tenant}','#{tenant.owner.id}')))[1]
        self.assertEqual(p['property_path'],'.owner.id');self.assertEqual(p['root_argument_index'],1)
        self.assertNotIn('argument_index',p);self.assertNotIn('value_origin_ref',p)
    def test_indexed_property_unresolved(self):
        self.assertNotIn('argument_index',self.marks(self.xml(SQL+' #{tenant[0]}'))[-1])
    def test_reserved_parameter_unresolved(self):
        r=self.xml(SQL.replace('#{tenant}','${_parameter}'),mapper=base.MAPPER.replace('@Param("tenant")','@Param("_parameter")'))
        self.assertNotIn('argument_index',self.marks(r)[1]);self.assertIn('reserved_binding_context_not_resolved',r['gaps'])
    def test_missing_param_preserves_marker(self):
        r=self.xml(mapper=base.MAPPER.replace('@Param("tenant") ',''));self.assertEqual(len(self.marks(r)),2)
        self.assertNotIn('argument_index',self.marks(r)[1])
    def test_duplicate_param_no_binding(self):
        r=self.xml(mapper=base.MAPPER.replace('@Param("tenant")','@Param("id")'))
        self.assertTrue(all('argument_index' not in p for p in self.marks(r)))
    def test_long_expression_truncated_not_dropped(self):
        r=self.xml(SQL+' ${'+'x'*900+'}');p=self.marks(r)[-1]
        self.assertTrue(p['source']['text_truncated']);self.assertNotIn('argument_index',p)
    def test_nested_marker_stages_unknown(self):
        r=self.xml(SQL+' ${tenant + "#{id}"}')
        self.assertIn('nested_template_stages_not_resolved',r['gaps'])
    def test_marker_budget_explicit(self):
        r=self.xml('SELECT '+', '.join('#{id}' for _ in range(150)))
        self.assertEqual(len(self.marks(r)),128);self.assertTrue(r['truncated'])
    def test_if_condition_associated(self):
        r=self.xml('SELECT * FROM orders <where><if test="tenant != null">tenant_id=#{tenant}</if></where>')
        c=self.marks(r)[0]['xml_conditions'][0];self.assertEqual(c['xml_element'],'if');self.assertEqual(c['text_prefix'],'"tenant != null"')
    def test_choose_branches_keep_identity(self):
        r=self.xml('SELECT * FROM orders <choose><when test="tenant != null">WHERE t=#{tenant}</when><otherwise>WHERE id=#{id}</otherwise></choose>')
        a,b=self.marks(r);self.assertEqual(a['argument_index'],1);self.assertEqual(b['argument_index'],0)
        self.assertEqual(a['xml_conditions'][0]['choice_group'],b['xml_conditions'][0]['choice_group'])
        self.assertEqual(b['xml_conditions'][0]['branch_semantics'],'no_preceding_when_matched')
    def test_foreach_does_not_bind_alias(self):
        r=self.xml(SQL+'<foreach collection="items" item="tenant">#{tenant}</foreach>')
        self.assertEqual(self.marks(r)[-1]['binding_status'],'dynamic_scope_not_bound')
    def test_bind_disables_all_positions(self):
        r=self.xml(SQL+'<bind name="tenant" value="1"/>')
        self.assertTrue(all('argument_index' not in p for p in self.marks(r)))
    def test_static_include_records_site(self):
        r=self.xml('SELECT * FROM orders <include refid="scope"/>',extra='<sql id="scope">WHERE t=#{tenant}</sql>')
        p=self.marks(r)[0];self.assertEqual(p['argument_index'],1);self.assertEqual(len(p['include_sites']),1)
    def test_qualified_local_include(self):
        self.assertEqual(self.marks(self.xml('<include refid="data.OrderMapper.scope"/>',extra='<sql id="scope">SELECT #{tenant}</sql>'))[0]['argument_index'],1)
    def test_repeated_include_separate_occurrences(self):
        r=self.xml('<include refid="scope"/><include refid="scope"/>',extra='<sql id="scope">SELECT #{tenant}</sql>')
        a,b=self.marks(r);self.assertEqual(a['source'],b['source']);self.assertNotEqual(a['include_sites'],b['include_sites'])
    def test_nested_include_keeps_condition(self):
        r=self.xml('<if test="tenant != null"><include refid="a"/></if>',extra='<sql id="a"><include refid="b"/></sql><sql id="b">SELECT #{tenant}</sql>')
        p=self.marks(r)[0];self.assertEqual(len(p['include_sites']),2);self.assertEqual(len(p['xml_conditions']),1)
    def test_include_missing_gap(self):
        r=self.xml(SQL+'<include refid="absent"/>');self.assertIn('include_missing_ambiguous_or_database_variant',r['gaps'])
        self.assertTrue(all('argument_index' not in p for p in self.marks(r)))
    def test_include_duplicate_gap(self):
        r=self.xml('<include refid="a"/>',extra='<sql id="a">#{id}</sql><sql id="a">#{tenant}</sql>')
        self.assertIn('include_missing_ambiguous_or_database_variant',r['gaps'])
    def test_include_cycle_bounded(self):
        r=self.xml('<include refid="a"/>',extra='<sql id="a"><include refid="a"/></sql>');self.assertIn('include_cycle',r['gaps'])
    def test_include_external_not_inferred(self):
        r=self.xml('<include refid="other.Mapper.a"/>');self.assertIn('external_include_not_selected',r['gaps'])
    def test_include_properties_unknown(self):
        r=self.xml('<include refid="a"><property name="tenant" value="1"/></include>',extra='<sql id="a">SELECT #{tenant}</sql>')
        self.assertIn('include_properties_or_expression_not_supported',r['gaps'])
    def test_include_bind_disables_outer(self):
        r=self.xml(SQL+'<include refid="a"/>',extra='<sql id="a"><bind name="tenant" value="1"/></sql>')
        self.assertTrue(all('argument_index' not in p for p in self.marks(r)))
    def test_include_depth_limit(self):
        extras=''.join(f'<sql id="s{i}"><include refid="s{i+1}"/></sql>' for i in range(10))+'<sql id="s10">#{tenant}</sql>'
        r=self.xml('<include refid="s0"/>',extra=extras);self.assertTrue(r['truncated']);self.assertIn('include_depth_limit',r['gaps'])
    def test_unknown_xml_element_conservative(self):
        r=self.xml(SQL+'<custom>#{tenant}</custom>');self.assertIn('xml_template_element_not_supported',r['gaps'])
        self.assertNotIn('argument_index',self.marks(r)[0])
    def test_entity_split_gap(self):
        r=self.xml(SQL+' AND z=${ten&#97;nt}')
        self.assertIn('xml_template_entities_not_decoded',r['gaps'])
    def test_select_head_and_table(self):
        r=self.xml();self.assertEqual(r['mybatis']['sql_operation'],'SELECT');self.assertEqual(r['mybatis']['leading_table_candidate']['text_prefix'],'orders')
    def test_update_write_candidate(self):
        r=self.xml('UPDATE orders SET tenant_id=#{tenant} WHERE id=#{id}')
        self.assertEqual([v['role_candidate'] for v in r['mybatis']['comparison_candidates']],['write_assignment','comparison'])
    def test_or_never_guaranteed(self):
        r=self.xml(SQL.replace(' AND ',' OR '));self.assertTrue(all(not v['guaranteed_scope'] for v in r['mybatis']['comparison_candidates']))
    def test_comparison_links_template_marker(self):
        r=self.xml();self.assertEqual([v['template_occurrence_index'] for v in r['mybatis']['comparison_candidates']],[0,1])
    def test_incomplete_include_not_classified(self):
        r=self.xml(SQL+'<include refid="missing"/>');self.assertEqual(r['mybatis']['sql_operation'],'unknown')
    def test_annotation_plain(self):
        r=self.annotation();self.assertEqual(r['mybatis']['status'],'explicit_annotation_candidate')
        self.assertEqual([p['argument_index'] for p in self.marks(r)],[0,1])
    def test_annotation_array(self):
        r=self.annotation(mapper(['SELECT * FROM orders','WHERE id=#{id}','AND tenant_id=#{tenant}'],array=True))
        self.assertEqual([p['argument_index'] for p in self.marks(r)],[0,1]);self.assertEqual(len(r['mybatis']['sql_segments']),3)
    def test_xml_annotation_same_marker_semantics(self):
        a=self.xml();b=self.annotation(); keys=['form','argument_index','parameter_name','property_path']
        self.assertEqual([{k:p[k] for k in keys} for p in self.marks(a)],[{k:p[k] for k in keys} for p in self.marks(b)])
    def test_annotation_quoted_substitution(self):
        self.assertEqual(self.marks(self.annotation(mapper(SQL.replace('#{tenant}',"'${tenant}'"))))[-1]['argument_index'],1)
    def test_annotation_named_value(self):
        r=self.annotation(mapper().replace('@Select(', '@Select(value='));self.assertEqual(len(self.marks(r)),2)
    def test_annotation_wrong_import(self):
        r=self.annotation(mapper().replace('org.apache.ibatis.annotations.Select','fake.Select'));self.assertEqual(r['mybatis']['status'],'unresolved')
    def test_annotation_fully_qualified(self):
        r=self.annotation(mapper().replace('import org.apache.ibatis.annotations.Select;','').replace('@Select(', '@org.apache.ibatis.annotations.Select('));self.assertEqual(len(self.marks(r)),2)
    def test_annotation_multiple_statements_unknown(self):
        r=self.annotation(mapper().replace('@Select(', '@Select("SELECT 1") @Select('));self.assertEqual(r['mybatis']['status'],'unresolved')
    def test_annotation_provider_not_executed(self):
        r=self.annotation(mapper().replace('import org.apache.ibatis.annotations.Select;', 'import org.apache.ibatis.annotations.Select; import org.apache.ibatis.annotations.SelectProvider;').replace('@Select(', '@SelectProvider(type=Evil.class, method="run") @Select('))
        self.assertEqual(r['mybatis']['status'],'unresolved');self.assertIn('annotation_provider_not_executed',r['gaps'])
    def test_annotation_custom_language_unknown(self):
        r=self.annotation(mapper().replace('@Select(', '@org.apache.ibatis.annotations.Lang(Evil.class) @Select('));self.assertEqual(r['mybatis']['status'],'unresolved')
    def test_annotation_escape_not_guessed(self):
        r=self.annotation(mapper(SQL+'\n'));self.assertIn('annotation_string_escape_or_text_block_not_decoded',r['gaps'])
    def test_annotation_script_not_treated_as_plain_sql(self):
        r=self.annotation(mapper('<script>'+SQL+'<if test="tenant != null"> AND x=1</if></script>'))
        self.assertTrue(r['mybatis']['template_analysis']['input_incomplete']);self.assertFalse(self.marks(r))
    def test_annotation_constant_not_evaluated(self):
        r=self.annotation(mapper().replace(json.dumps(SQL),'SQL_CONSTANT'));self.assertIn('annotation_sql_requires_plain_string_literals',r['gaps'])
    def test_annotation_attribute_not_silently_ignored(self):
        r=self.annotation(mapper().replace('@Select(', '@Select(databaseId="pg", value='));self.assertIn('annotation_attributes_not_resolved',r['gaps'])
        self.assertTrue(all('argument_index' not in p for p in self.marks(r)))
    def test_annotation_array_incomplete_disables_binding(self):
        r=self.annotation(mapper().replace(json.dumps(SQL),'{"SELECT #{id}", SQL_CONSTANT}'))
        self.assertNotIn('argument_index',self.marks(r)[0])
    def test_annotation_split_marker_gap(self):
        r=self.annotation(mapper(['SELECT #{','tenant}'],array=True));self.assertIn('unterminated_or_cross_segment_template_marker',r['gaps'])
    def test_annotation_declared_kind_not_actual_sql(self):
        r=self.annotation(mapper('UPDATE orders SET tenant_id=#{tenant} WHERE id=#{id}'))
        self.assertEqual(r['mybatis']['declared_operation'],'SELECT');self.assertEqual(r['mybatis']['sql_operation'],'UPDATE')
    def test_annotation_no_mapper_body_guessed(self):
        r=self.annotation(mapper().replace('Object load(', 'default Object load(').replace('long tenantId);','long tenantId) { return null; }'))
        self.assertEqual(r['mybatis']['reason'],'mapper_method_has_implementation')
    def test_annotation_exact_source_refs(self):
        s=self.session(mapper=mapper(SQL+" AND name='中文'"));r=s.call('inspect_operation_context',{**s.anchor(),'mapper_path':'OrderMapper.java','mapping_format':'annotation'});self.assert_refs(s,r)
    def test_xml_include_exact_source_refs(self):
        x=base.XML.replace('#{tenant}', '<include refid="t"/>').replace('</mapper>','<sql id="t">#{tenant}</sql></mapper>')
        s=self.session(xml=x);self.assert_refs(s,s.inspect())
    def test_values_view_has_index_lookup_not_array_offset(self):
        s=self.session();r=s.inspect(view='values',argument_index=1)
        p=self.marks(r)[1];self.assertEqual(p['value_origin_ref']['match_field'],'index');self.assertEqual(r['arguments'][0]['index'],1)
    def test_summary_full_roundtrip(self):
        s=self.session();small=s.inspect(view='summary');again=s.call(small['full_request']['tool'],small['full_request']['arguments'])
        self.assertEqual(again,s.inspect())
    def test_annotation_identity_separate_from_xml(self):
        s=self.session(mapper=mapper());a=s.inspect();b=s.call('inspect_operation_context',{**s.anchor(),'mapper_path':'OrderMapper.java','mapping_format':'annotation'})
        self.assertNotEqual(a['context_id'],b['context_id'])
    def test_annotation_disallows_xml_and_wrong_format(self):
        s=self.session(mapper=mapper());args={**s.anchor(),'mapper_path':'OrderMapper.java','mapping_path':'OrderMapper.xml','mapping_format':'annotation'}
        self.assertEqual(s.call('inspect_operation_context',args,ok=False)['error']['code'],'annotation_requires_mapper_only')
        args['mapping_format']='automatic';self.assertEqual(s.call('inspect_operation_context',args,ok=False)['error']['code'],'invalid_mapping_format')
    def test_annotation_parse_count(self):
        s=self.session(mapper=mapper());s.call('inspect_operation_context',{**s.anchor(),'mapper_path':'OrderMapper.java','mapping_format':'annotation'})
        self.assertEqual(s.call('get_snapshot_info')['operation_context']['parse_attempts'],2)
    def test_mutation_kills_value_origin(self):
        s=self.session(caller=base.CALLER.replace('return mapper','tenantId = 0; return mapper'));r=s.inspect()
        self.assertEqual(self.marks(r)[1]['argument_index'],1)
        flow=r['arguments'][1]['local_value_flow'];self.assertEqual(flow['formal_parameter_indices'],[])
        self.assertTrue(flow['literal_possible'])
        self.assertEqual(r['authorization_verdict'],'not_evaluated')

if __name__=='__main__':unittest.main()
