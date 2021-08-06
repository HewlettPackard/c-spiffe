#include "c-spiffe/spiffetls/option.h"

void spiffetls_DialOption_apply(spiffetls_DialOption option,
                                spiffetls_dialConfig *config)
{
    option(config);
}
