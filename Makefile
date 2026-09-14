.DEFAULT_GOAL := all

# CBM Sec is the default product. The upstream build remains explicitly selectable.
include Makefile.security

.PHONY: help docs-check check
help:
	@printf '%s\n' 'CBM Sec：make 构建安全工具；make test 运行专项回归。' \
	  'make docs-check 检查文档和仓库入口；make check 执行文档检查及专项回归。' \
	  'make clean 仅清理安全构建产物；上游兼容构建须显式指定 Makefile.cbm。'

docs-check:
	$(PYTHON) scripts/check_cbm_sec_docs.py

check: docs-check test
