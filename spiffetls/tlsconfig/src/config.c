#include "config.h"

tlsconfig_Trace *__trace;

void tlsconfig_Option_apply(tlsconfig_Option *op, tlsconfig_options *options)
{
    if(op->type == TLSCONFIG_FUNC) {
        op->source.func(options);
    }
}

tlsconfig_Option *tlsconfig_OptionFromFunc(tlsconfig_option fn)
{
    tlsconfig_Option *option = malloc(sizeof *option);
    option->type = TLSCONFIG_FUNC;
    option->source.func = fn;

    return option;
}

tlsconfig_options *tlsconfig_newOptions(tlsconfig_Option **opts)
{
    tlsconfig_options *out = malloc(sizeof *out);
    memset(out, 0, sizeof *out);

    for(size_t i = 0, size = arrlenu(opts); i < size; ++i) {
        tlsconfig_Option_apply(opts[i], out);
    }
    return out;
}

static void setTrace(tlsconfig_options *opts) { opts->trace = __trace; }

tlsconfig_Option *tlsconfig_WithTrace(const tlsconfig_Trace *trace)
{
    __trace = trace;
    return tlsconfig_OptionFromFunc(setTrace);
}

// func TLSClientConfig(bundle x509bundle.Source, authorizer Authorizer, opts
// ...Option) *tls.Config {
SSL *tlsconfig_TLSClientConfig(x509bundle_Source *bundle,
                               tlsconfig_Authorizer *authorizer,
                               tlsconfig_Option **opts)
{
}