module LDAP;

export {
    const protocolOp_types = {
        [60] = "BindRequest",
        [61] = "BindResponse",
        [42] = "UnbindRequest",
        [63] = "SearchRequest",
        [65] = "SearchResultDone",    
    }&default = function(n: count): string {return fmt("unknown-message-type-%d", n);};

    const resultCode_types = {
        [0] = "success",
        [20] = "noSuchObject",  
    }&default = function(n: count): string {return fmt("unknown-message-type-%d", n);};

    const Scope_types = {
        [0] = "baseObject",
        [1] = "singleLevel",
        [2] = "wholeSubtree",   
    }&default = function(n: count): string {return fmt("unknown-message-type-%d", n);};

    const DerefAliases_types = {
        [0] = "neverDerefAliases",
        [1] = "derefInSearching",
        [2] = "derefFindingBaseObj",
        [3] = "derefAlways",  
    }&default = function(n: count): string {return fmt("unknown-message-type-%d", n);};
}