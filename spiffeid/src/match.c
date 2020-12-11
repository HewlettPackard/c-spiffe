#include "../include/match.h"

match_err_t spiffeid_ApplyMatcher(const spiffeid_Matcher *matcher, const spiffeid_ID id)
{
    match_err_t err = MATCH_OK;

    if(matcher->type == MATCH_ANY)
    {
    
        return MATCH_OK;
    }
    else if(matcher->type == MATCH_ONEOF)
    {
        const spiffeid_ID *ids = matcher->ids;
        for(size_t i = 0, size = arrlenu(ids); i < size; ++i)
        {
            if(strcmp(id.path, ids[i].path) || strcmp(id.td.name, ids[i].td.name))
                return MATCH_UNEXPECTED_ID;
        }
        return MATCH_OK;
    }
    else if(matcher->type == MATCH_MEMBEROF)
    {
        if(strcmp(id.td.name, matcher->td.name))
            return MATCH_UNEXPECTED_TD;
        return MATCH_OK;
    }

    return MATCH_OK;
}

spiffeid_Matcher* spiffeid_MatchAny()
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ANY;
    return matcher;
}

spiffeid_Matcher* spiffeid_MatchID(const spiffeid_ID id)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ONEOF;
    spiffeid_ID new_id;
    new_id.path = string_push(NULL, id.path);
    new_id.td.name = string_push(NULL, id.td.name);

    arrput(matcher->ids, new_id);
    return matcher;
}

spiffeid_Matcher* spiffeid_MatchOneOf(int n_args, ...)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ONEOF;

    va_list args;
    va_start(args, n_args);

    for(int i = 0; i < n_args; ++i)
    {
        spiffeid_ID id = va_arg(args, spiffeid_ID);

        spiffeid_ID new_id;
        new_id.path = string_push(NULL, id.path);
        new_id.td.name = string_push(NULL, id.td.name);

        arrput(matcher->ids, new_id);
    }

    return matcher;
}

spiffeid_Matcher* spiffeid_MatchMemberOf(const spiffeid_TrustDomain td)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_MEMBEROF;
    matcher->td.name = string_push(NULL, td.name);

    return matcher;
}