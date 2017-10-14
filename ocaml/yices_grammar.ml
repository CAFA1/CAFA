type token =
  | VAR of (string)
  | VAL of (Big_int_Z.big_int)
  | SEMICOLON
  | LBRACKET
  | RBRACKET
  | EQUAL
  | MODEL
  | ASSERT
  | SDASHES
  | DASHES
  | QUESTIONMARKS
  | INVALID
  | VALID
  | DEFAULT
  | COMMA
  | PERIOD
  | EOF

open Parsing;;
let yytransl_const = [|
  259 (* SEMICOLON *);
  260 (* LBRACKET *);
  261 (* RBRACKET *);
  262 (* EQUAL *);
  263 (* MODEL *);
  264 (* ASSERT *);
  265 (* SDASHES *);
  266 (* DASHES *);
  267 (* QUESTIONMARKS *);
  268 (* INVALID *);
  269 (* VALID *);
  270 (* DEFAULT *);
  271 (* COMMA *);
  272 (* PERIOD *);
    0 (* EOF *);
    0|]

let yytransl_block = [|
  257 (* VAR *);
  258 (* VAL *);
    0|]

let yylhs = "\255\255\
\001\000\001\000\003\000\003\000\005\000\005\000\005\000\005\000\
\005\000\006\000\006\000\002\000\004\000\000\000"

let yylen = "\002\000\
\005\000\002\000\000\000\002\000\005\000\005\000\003\000\002\000\
\008\000\001\000\001\000\001\000\001\000\002\000"

let yydefred = "\000\000\
\000\000\000\000\012\000\013\000\014\000\000\000\000\000\000\000\
\002\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\008\000\000\000\004\000\000\000\000\000\007\000\001\000\000\000\
\000\000\000\000\006\000\005\000\010\000\011\000\000\000\000\000\
\000\000\009\000"

let yydgoto = "\002\000\
\005\000\006\000\013\000\007\000\014\000\031\000"

let yysindex = "\003\000\
\251\254\000\000\000\000\000\000\000\000\250\254\009\000\252\254\
\000\000\008\255\014\255\015\255\006\255\252\254\002\255\009\255\
\000\000\019\000\000\000\011\255\019\255\000\000\000\000\016\255\
\017\255\000\255\000\000\000\000\000\000\000\000\018\255\000\255\
\020\255\000\000"

let yyrindex = "\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\021\255\
\000\000\000\000\000\000\000\000\000\000\021\255\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\
\000\000\000\000"

let yygindex = "\000\000\
\000\000\000\000\010\000\000\000\000\000\250\255"

let yytablesize = 31
let yytable = "\010\000\
\008\000\029\000\020\000\001\000\011\000\021\000\003\000\004\000\
\009\000\012\000\030\000\024\000\025\000\015\000\016\000\018\000\
\017\000\022\000\023\000\026\000\027\000\028\000\032\000\019\000\
\034\000\033\000\000\000\000\000\000\000\000\000\003\000"

let yycheck = "\004\001\
\007\001\002\001\001\001\001\000\009\001\004\001\012\001\013\001\
\000\000\014\001\011\001\001\001\002\001\006\001\001\001\010\001\
\002\001\009\001\000\000\001\001\005\001\005\001\005\001\014\000\
\005\001\032\000\255\255\255\255\255\255\255\255\010\001"

let yynames_const = "\
  SEMICOLON\000\
  LBRACKET\000\
  RBRACKET\000\
  EQUAL\000\
  MODEL\000\
  ASSERT\000\
  SDASHES\000\
  DASHES\000\
  QUESTIONMARKS\000\
  INVALID\000\
  VALID\000\
  DEFAULT\000\
  COMMA\000\
  PERIOD\000\
  EOF\000\
  "

let yynames_block = "\
  VAR\000\
  VAL\000\
  "

let yyact = [|
  (fun _ -> failwith "parser")
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 4 : 'goodresult) in
    let _3 = (Parsing.peek_val __caml_parser_env 2 : 'assertions) in
    Obj.repr(
# 27 "yices_grammar.mly"
                                         ( Some(_3) )
# 124 "yices_grammar.ml"
               : (string * Big_int_Z.big_int) list option))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'badresult) in
    Obj.repr(
# 28 "yices_grammar.mly"
                ( None )
# 131 "yices_grammar.ml"
               : (string * Big_int_Z.big_int) list option))
; (fun __caml_parser_env ->
    Obj.repr(
# 32 "yices_grammar.mly"
              ( [] )
# 137 "yices_grammar.ml"
               : 'assertions))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 1 : 'assertion) in
    let _2 = (Parsing.peek_val __caml_parser_env 0 : 'assertions) in
    Obj.repr(
# 33 "yices_grammar.mly"
                         ( match _1 with | None -> _2 | Some(x) -> x::_2 )
# 145 "yices_grammar.ml"
               : 'assertions))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _4 = (Parsing.peek_val __caml_parser_env 1 : Big_int_Z.big_int) in
    Obj.repr(
# 38 "yices_grammar.mly"
                                  ( Some(_3, _4) )
# 153 "yices_grammar.ml"
               : 'assertion))
; (fun __caml_parser_env ->
    let _3 = (Parsing.peek_val __caml_parser_env 2 : string) in
    let _4 = (Parsing.peek_val __caml_parser_env 1 : string) in
    Obj.repr(
# 40 "yices_grammar.mly"
                                    ( None )
# 161 "yices_grammar.ml"
               : 'assertion))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 1 : string) in
    Obj.repr(
# 42 "yices_grammar.mly"
                        ( None )
# 168 "yices_grammar.ml"
               : 'assertion))
; (fun __caml_parser_env ->
    let _2 = (Parsing.peek_val __caml_parser_env 0 : Big_int_Z.big_int) in
    Obj.repr(
# 44 "yices_grammar.mly"
                ( None )
# 175 "yices_grammar.ml"
               : 'assertion))
; (fun __caml_parser_env ->
    let _4 = (Parsing.peek_val __caml_parser_env 4 : string) in
    let _5 = (Parsing.peek_val __caml_parser_env 3 : 'val_opt) in
    let _7 = (Parsing.peek_val __caml_parser_env 1 : 'val_opt) in
    Obj.repr(
# 46 "yices_grammar.mly"
                                                                  ( None )
# 184 "yices_grammar.ml"
               : 'assertion))
; (fun __caml_parser_env ->
    let _1 = (Parsing.peek_val __caml_parser_env 0 : Big_int_Z.big_int) in
    Obj.repr(
# 50 "yices_grammar.mly"
      ( )
# 191 "yices_grammar.ml"
               : 'val_opt))
; (fun __caml_parser_env ->
    Obj.repr(
# 51 "yices_grammar.mly"
                  ( )
# 197 "yices_grammar.ml"
               : 'val_opt))
; (fun __caml_parser_env ->
    Obj.repr(
# 55 "yices_grammar.mly"
          ( )
# 203 "yices_grammar.ml"
               : 'goodresult))
; (fun __caml_parser_env ->
    Obj.repr(
# 59 "yices_grammar.mly"
        ( )
# 209 "yices_grammar.ml"
               : 'badresult))
(* Entry main *)
; (fun __caml_parser_env -> raise (Parsing.YYexit (Parsing.peek_val __caml_parser_env 0)))
|]
let yytables =
  { Parsing.actions=yyact;
    Parsing.transl_const=yytransl_const;
    Parsing.transl_block=yytransl_block;
    Parsing.lhs=yylhs;
    Parsing.len=yylen;
    Parsing.defred=yydefred;
    Parsing.dgoto=yydgoto;
    Parsing.sindex=yysindex;
    Parsing.rindex=yyrindex;
    Parsing.gindex=yygindex;
    Parsing.tablesize=yytablesize;
    Parsing.table=yytable;
    Parsing.check=yycheck;
    Parsing.error_function=parse_error;
    Parsing.names_const=yynames_const;
    Parsing.names_block=yynames_block }
let main (lexfun : Lexing.lexbuf -> token) (lexbuf : Lexing.lexbuf) =
   (Parsing.yyparse yytables 1 lexfun lexbuf : (string * Big_int_Z.big_int) list option)
