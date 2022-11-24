
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginLDAP)

include(ZeekPlugin)

zeek_plugin_begin(Zeek LDAP)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/LDAP.cc)
zeek_plugin_bif(src/events.bif)
zeek_plugin_dist_files(README CHANGES VERSION)
zeek_plugin_pac(src/ldap.pac src/ldap-analyzer.pac src/ldap-protocol.pac src/ldap-strings.pac)
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
