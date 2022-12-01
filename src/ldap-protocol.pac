type LDAP_PDU(is_orig:  bool) = record{
    messageid:       uint32;
    protocolOp:      ProtocolOp;   
}

type ProtocolOp(protocolOp: LDAP_string(false, offsetof(BindRequest))) = record{
        "BindRequest"        ->  bindRequest:            LDAP_string(false, offsetof(BindRequest));
        "BindResponset"         ->  bindResponse:           LDAP_string(false, offsetof(BindResponse));
        "UnbindRequest"         ->  unbindRequest:          LDAP_string(false, offsetof(UnbindRequest));
        "SearchRequest"         ->  searchRequest:          LDAP_string(false, offsetof(SearchRequest));
        "SearchResultEntry"     ->  searchResultEntry:      LDAP_string(false, offsetof(SearchResultEntry));
        "SearchResultDone"      ->  searchResultDone:       LDAP_string(false, offsetof(SearchResultDone));
        "SearchResultReference" ->  searchResultReference:  LDAP_string(false, offsetof(SearchResultReference));
        "ModifyRequest"         ->  modifyRequest:          LDAP_string(false, offsetof(ModifyRequest));
        "ModifyResponset"       ->  modifyResponse:         LDAP_string(false, offsetof(ModifyResponse));
        "AddRequest"            ->  addRequest:             LDAP_string(false, offsetof(AddRequest));
        "AddResponse"           ->  addResponse:            LDAP_string(false, offsetof(AddResponse));
        "DelRequest"            ->  delRequest:             LDAP_string(false, offsetof(DelRequest));
        "DelResponse"           ->  delResponse:            LDAP_string(false, offsetof(DelResponse));
        "ModifyDNRequest"       ->  modifyDNRequest:        LDAP_string(false, offsetof(ModifyDNRequest));
        "ModifyDNResponse)"     ->  modifyDNResponse:       LDAP_string(false, offsetof(ModifyDNResponse));
        "CompareRequest"        ->  compareRequest:         LDAP_string(false, offsetof(CompareRequest));
        "CompareResponse"       ->  compareResponse:        LDAP_string(false, offsetof(CompareResponse));
        "AbandonRequest"        ->  abandonRequest:         LDAP_string(false, offsetof(AbandonRequest));
        "ExtendedRequest"       ->  extendedRequest:        LDAP_string(false, offsetof(ExtendedRequest));
        "ExtendedResponse"      ->  extendedResponse:       LDAP_string(false, offsetof(ExtendedResponse));
        "IntermediateResponse"  ->  intermediateResponse:   LDAP_string(false, offsetof(IntermediateResponse));
}