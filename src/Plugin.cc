#include "Plugin.h"
#include "analyzer/Component.h"



namespace plugin { namespace Zeek_LDAP { Plugin plugin; } }

using namespace plugin::Zeek_LDAP;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::analyzer::Component("LDAP", zeek::analyzer::ldap::LDAP::InstantiateAnalyzer));
	zeek::plugin::Configuration config;
	config.name = "Zeek::LDAP";
	config.description = "LDAP protocol support from Zeek";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
