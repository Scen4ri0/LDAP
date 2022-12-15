type LDAP_PDU(is_orig: bool, application: uint16) = record{
        somedata:       uint32;
        messageID:      uint8;
        opcode:         uint8;
        potocolOp:      ProtocolOp(opcode);
}

type ProtocolOp(appliaction:    uint16) = case appliaction of{
        0x60   ->  protocolOp:   BindRequest;
        0x61   ->  protocolOp:   BindResponse;
        0x42   ->  protocolOp:   UnbindRequest;
        0x63   ->  protocolOp:   SearchRequest;
        0x65   ->  protocolOp:   SearchResultDone;
 }



     
type ResultCode(rc: uint16) = case of rc{
        0x00 -> resultCode:      uint8 = 0;# "success";                         
        0x20 -> resultCode:      uint8 = 20;# "noSuchObject";             
}

       

type BindRequest = record {
        protocolOp:     uint8 = 60;
        somedata:       uint8;
        somedata:       uint8;
        somedata:       uint8;
        version:        uint32;
        data :          bytestring &restofdata;
}

type BindResponse(rc: uint16) = record {
        protocolOp:     uint8 = 61;
        somedata:       uint8;
        somedata:       uint8;
        somedata:       uint8;
        rc:             uint8;
        resultCode:     ResultCode(rc);
        data :          bytestring &restofdata;
}

type UnbindRequest = record{
        protocolOp:     uint8 = 42;
        data :          bytestring &restofdata;
}

type SearchRequest = record{
        protocolOp:     uint8 = 63;
        somedata:       uint32;
        somedata:       uint8;
        sc:             uint8;
        scope:          Scope(sc);
        somedata:       uint16;
        da:             uint8;
        derefAliases:   DerefAliases(da) ;
        somedata:       uint16;
        sizeLimit:      uint8;
        somedata:       uint16;
        timeLimit:      uint8;
        somedata:       uint16;
        typesOnly:      bool;
        data :          bytestring &restofdata;
}


type Scope(sc: uint8) = case sc of{
        0x00 -> scope:        uint8 = 0;# "baseObject";
        0x01 -> scope:        uint8 = 1;# = "singleLevel";
        0x02 -> scope:        uint8 = 2;# = "wholeSubtree";
}

type DerefAliases(da: uint8) = case da of {
        0x00 ->   derefAliases:       uint8 = 0;# "neverDerefAliases";       
        0x01 ->   derefAliases:       uint8 = 1;# "derefInSearching";        
        0x02 ->   derefAliases:       uint8 = 2;# "derefFindingBaseObj";     
        0x03 ->   derefAliases:       uint8 = 3;# "derefAlways";             
}

type SearchResultDone(rc: uint16) = record{
        protocolOp:     uint8 = 6;
        somedata:       uint8;
        somedata:       uint8;
        somedata:       uint8;
        rc:             uint8;
        resultCode:     ResultCode(rc);
        data :          bytestring &restofdata;
}


