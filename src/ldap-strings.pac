%extern{
#include "zeek/binpac_zeek.h"
%}

%code{
zeek::StringValPtr binpac::LDAP::LDAP_Conn::extract_string(LDAP_string* s)
	{
	if ( s->unicode() == false )
		{
		int length = s->a()->size();
		auto buf = std::make_unique<char[]>(length);

		for ( int i = 0; i < length; i++)
			{
			unsigned char t = (*(s->a()))[i];
			buf[i] = t;
			}

		if ( length > 0 && buf[length-1] == 0x00 )
			length--;

		return zeek::make_intrusive<zeek::StringVal>(length, buf.get());
		}
	}

zeek::StringValPtr binpac::LDAP::LDAP_Conn::ldap_string2stringval(LDAP_string* s)
	{
	return extract_string(s);
	}
%}

refine connection LDAP_Conn += {
	%member{
		zeek::StringValPtr extract_string(LDAP_string* s);
		zeek::StringValPtr ldap_string2stringval(LDAP_string* s);
	%}
};


type LDAP_ascii_string = uint8[] &until($element == 0x00);


type LDAP_string(unicode: bool, offset: int) = case unicode of {
#	true  -> u: LDAP_unicode_string(offset);
	false -> a: LDAP_ascii_string;
};