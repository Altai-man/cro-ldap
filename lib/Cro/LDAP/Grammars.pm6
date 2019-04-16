grammar Common {
    token UTFMB { <UTF2> | <UTF3> | <UTF4> }
    token UTF0 { <[ \x80..\xBF ]> }
    token UTF2 { <[ \xC2..\xDF ]> <UTF0> }
    token UTF3 {
        | [ <[\xE0]> <[\xA0..\xBF]> <UTF0> ]
        | [ <[\xE1..\xEC]> <UTF0> ** 2 ]
        | [ \xED <[\x80..\x9F]> <UTF0> ]
        | [ <[\xEE..\xEF]> <UTF0> ** 2 ]
    }
    token UTF4 {
        | [ \xF0 <[\x90..\xBF]> <UTF0> ** 2 ]
        | [ <[\xF1..\xF3]> <UTF0> ** 3 ]
        | \xF4 [ <[\x80..\x8F]> <UTF0> ** 2 ]
    }

    token hex { <digit> | <[\x41..\x46 \x61..\x66]> }

    regex descr { <leadkey> <keychar>*? }
    token leadkey { <[a..zA..Z]> }
    token keychar { <[-a..zA..Z0..9]> }

    token numericoid { <number> [ "." <number> ]? }
    token number { <[0..9]> | [ <[1..9]> <[0..9]> ] }
}

grammar Attributes {
    regex attributeDescription { <attributeType> <options> }
    regex attributeType { <oid> }
    regex oid { <Common::descr> | <Common::numericoid> }
    token options { [ ';' <option> ]*? }
    token option { <[- \x41..\x5A \x61..\x7A \x30..\x39]> } # -A..Za..z0..9
}
