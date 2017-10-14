input.cmo: typecheck.cmi parser.cmo grammar_private_scope.cmo BatListFull.cmo \
    asmir_rdisasm.cmi asmir.cmi input.cmi
input.cmx: typecheck.cmx parser.cmx grammar_private_scope.cmx BatListFull.cmx \
    asmir_rdisasm.cmx asmir.cmx input.cmi
