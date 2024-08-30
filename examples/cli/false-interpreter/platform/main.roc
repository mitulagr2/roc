platform "false-interpreter"
    requires {} { main : Str -> Task {} I64 }
    exposes []
    packages {}
    imports []
    provides [mainForHost]

mainForHost : Str -> Task {} I64
mainForHost = \file -> main file
