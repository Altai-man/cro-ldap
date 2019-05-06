use Cro::LDAP::Grammars;

grammar Cro::LDAP::DN::Grammar {
    token TOP { ^ <relativeDN>* % ',' $ }
    regex relativeDN { <attributeTypeAndValue>+? % "+" }
    regex attributeTypeAndValue { <attrType> "=" <attrValue> }
    token attrType { <Common::descr> | <Common::numericoid> }
    regex attrValue { <string> | <hexstr> }

    regex string { [ [<leadchar> | <pair>] [ [ <stringchar> | <pair> ]*? [ <trailchar> | <pair> ] ]? ]? }

    token pair { "\\" [ "\\" | <special> | <hexpair> ] }
    token special { <escaped> | <[\ #=]> }
    token escaped { <["+,;<>]> }
    token hexstr { '#' <hexpair> }
    token hexpair { <Common::hex> ** 2 }

    token leadchar { <LUTF1> | <Common::UTFMB> }
    token LUTF1 { <[ \x01..\x1F \x21 \x24..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }

    token trailchar { <TUTF1> | <Common::UTFMB> }
    token TUTF1 { <[ \x01..\x1F \x21 \x23..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }

    token stringchar { <SUTF1> | <Common::UTFMB> }
    token SUTF1 { <[ \x01..\x21 \x23..\x2A \x2D..\x3A \x3D \x3F..\x5B \x5D..\x7F ]> }
}
