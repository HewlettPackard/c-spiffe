import os
import sys
import json
import base64

PARENT_PATH = os.path.abspath("..")
if PARENT_PATH not in sys.path:
    sys.path.insert(0, PARENT_PATH)

from hamcrest import assert_that, is_
from OpenSSL import crypto


#@given(u'I up the spire server')
#def step_impl(context):
#    docker-compose up


@when(u'I get Spiffe id')
def step_impl(context):
    context.spiffeid_value = context.spiffe_id


@then(u'I check that Spiffe id is returned')
def step_impl(context):
    assert_that(context.spiffeid_value, is_(context.SPIFFE_ID_))


@when(u'I get token')
def step_impl(context):
    context.token_value = context.token


@then(u'I check that token is returned')
def step_impl(context):
    assert_that(context.token_value, is_(context.token)


@then(u'I veriry that svid as X509 model')
def step_impl(context):
    certificate = open('..\\common\\assets\\good-cert-and-key.pem', 'r')
    cert_data = certificate.read()
    certificate_ = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    store = crypto.X509Store()

    for _cert in trusted_certs:
        cert_file = open('..\\assets\\good-key-and-cert.pem', 'r')
        cert_data = cert_file.read()
        client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
        store.add_cert(client_certificate)

    store_ctx = crypto.X509StoreContext(store, certificate)

    store_ctx.verify_certificate()
