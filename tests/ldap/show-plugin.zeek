# @TEST-EXEC: zeek -NN Zeek::LDAP |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
