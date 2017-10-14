coalesce.cmo: ssa.cmo pp.cmo debug.cmi checks.cmi cfg.cmi BatListFull.cmo \
    ast.cmo coalesce.cmi
coalesce.cmx: ssa.cmx pp.cmx debug.cmx checks.cmx cfg.cmx BatListFull.cmx \
    ast.cmx coalesce.cmi
