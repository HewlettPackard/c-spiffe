#include "c-spiffe/spiffeid/match.h"
#include "c-spiffe/spiffeid/trustdomain.h"

match_err_t spiffeid_ApplyMatcher(const spiffeid_Matcher *matcher,
                                  const spiffeid_ID id)
{
    if(matcher->type == MATCH_ANY) {
        return MATCH_OK;
    } else if(matcher->type == MATCH_ONEOF) {
        const spiffeid_ID *ids = matcher->ids;
        for(size_t i = 0, size = arrlenu(ids); i < size; ++i) {
            if(!strcmp(id.path, ids[i].path)
               && !strcmp(id.td.name, ids[i].td.name))
                return MATCH_OK;
        }
        return MATCH_UNEXPECTED_ID;
    } else if(matcher->type == MATCH_MEMBEROF) {
        if(strcmp(id.td.name, matcher->td.name))
            return MATCH_UNEXPECTED_TD;
        return MATCH_OK;
    }

    return MATCH_OK;
}

spiffeid_Matcher *spiffeid_MatchAny()
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ANY;
    return matcher;
}

spiffeid_Matcher *spiffeid_MatchID(const spiffeid_ID id)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ONEOF;
    spiffeid_ID new_id;
    new_id.path = string_new(id.path);
    new_id.td.name = string_new(id.td.name);

    arrput(matcher->ids, new_id);
    return matcher;
}

spiffeid_Matcher *spiffeid_MatchOneOf(int n_args, ...)
{
    va_list args;
    va_start(args, n_args);

    spiffeid_Matcher *matcher = spiffeid_vMatchOneOf(n_args, args);

    va_end(args);

    return matcher;
}

spiffeid_Matcher *spiffeid_vMatchOneOf(int n_args, va_list args)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_ONEOF;

    for(int i = 0; i < n_args; ++i) {
        spiffeid_ID id = va_arg(args, spiffeid_ID);

        spiffeid_ID new_id;
        new_id.path = string_new(id.path);
        new_id.td.name = string_new(id.td.name);

        arrput(matcher->ids, new_id);
    }

    return matcher;
}

spiffeid_Matcher *spiffeid_MatchMemberOf(const spiffeid_TrustDomain td)
{
    spiffeid_Matcher *matcher = malloc(sizeof *matcher);
    memset(matcher, 0, sizeof *matcher);

    matcher->type = MATCH_MEMBEROF;
    matcher->td.name = string_new(td.name);

    return matcher;
}

void spiffeid_Matcher_Free(spiffeid_Matcher *matcher)
{
    if(matcher) {
        for(size_t i = 0, size = arrlenu(matcher->ids); i < size; ++i) {
            spiffeid_ID_Free(matcher->ids + i);
        }
        arrfree(matcher->ids);
        spiffeid_TrustDomain_Free(&(matcher->td));

        free(matcher);
    }
}
