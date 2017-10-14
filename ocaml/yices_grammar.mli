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

val main :
  (Lexing.lexbuf  -> token) -> Lexing.lexbuf -> (string * Big_int_Z.big_int) list option
