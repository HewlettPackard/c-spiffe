#include <cjose/cjose.h>
#include "svid.h"

string_t jwtsvid_SVID_Marshal(jwtsvid_SVID *svid)
{
    if(svid)
    {
        return svid->token;
    }

    return NULL;
}