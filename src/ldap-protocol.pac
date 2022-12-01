type LDAP_PDU(is_orig:  bool) = record{
    messageid:       uint32;
    protocolOp:      ProtocolOp;   
}

type ProtocolOp = record{
        bindRequest:            LDAP_string(false, offsetof(BindRequest));
        bindResponse:           LDAP_string(false, offsetof(BindResponse));
        unbindRequest:          LDAP_string(false, offsetof(UnbindRequest));
        searchRequest:          LDAP_string(false, offsetof(SearchRequest));
        searchResultEntry:      LDAP_string(false, offsetof(SearchResultEntry));
        searchResultDone:       LDAP_string(false, offsetof(SearchResultDone));
        searchResultReference:  LDAP_string(false, offsetof(SearchResultReference));
        modifyRequest:          LDAP_string(false, offsetof(ModifyRequest));
        modifyResponse:         LDAP_string(false, offsetof(ModifyResponse));
        addRequest:             LDAP_string(false, offsetof(AddRequest));
        addResponse:            LDAP_string(false, offsetof(AddResponse));
        delRequest:             LDAP_string(false, offsetof(DelRequest));
        delResponse:            LDAP_string(false, offsetof(DelResponse));
        modifyDNRequest:        LDAP_string(false, offsetof(ModifyDNRequest));
        modifyDNResponse:       LDAP_string(false, offsetof(ModifyDNResponse));
        compareRequest:         LDAP_string(false, offsetof(CompareRequest));
        compareResponse:        LDAP_string(false, offsetof(CompareResponse));
        abandonRequest:         LDAP_string(false, offsetof(AbandonRequest));
        extendedRequest:        LDAP_string(false, offsetof(ExtendedRequest));
        extendedResponse:       LDAP_string(false, offsetof(ExtendedResponse));
        intermediateResponse:   LDAP_string(false, offsetof(IntermediateResponse));
}