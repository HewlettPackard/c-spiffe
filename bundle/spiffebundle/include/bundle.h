#ifndef __INCLUDE_SPIFFEBUNDLE_BUNDLE_H__
#define __INCLUDE_SPIFFEBUNDLE_BUNDLE_H__

#include <time.h>
#include <threads.h>
#include <openssl/x509.h>
#include "../../jwtbundle/include/bundle.h"
#include "../../x509bundle/include/bundle.h"
#include "../../../spiffeid/include/trustdomain.h"
#include "../../../utils/include/util.h"

typedef struct spiffebundle_Bundle
{
    //bundle trust domain
    spiffeid_TrustDomain td;
    ///TODO: implement a RW mutex instead
    //read write mutex
    mtx_t mtx;
    //time duration (...)
    struct timespec *refreshHint;
    //sequence number
    uint64_t *seqNumber;
    //hash of jwt authorities
    map_string_EVP_PKEY *jwtAuths;
    //STB array of x509 certificates
    X509 **x509Certs;
} spiffebundle_Bundle;

// func New(trustDomain spiffeid.TrustDomain) *Bundle {
spiffebundle_Bundle* spiffebundle_New(const spiffeid_TrustDomain td);
// func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
spiffebundle_Bundle* spiffebundle_Load(const spiffeid_TrustDomain td, 
                                        const string_t path, 
                                        err_t *err);
// func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
spiffebundle_Bundle* spiffebundle_Read(const spiffeid_TrustDomain td,
                                        void *reader,
                                        err_t *err);
// func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
spiffebundle_Bundle* spiffebundle_Parse(const spiffeid_TrustDomain td,
                                        const byte *bundleBytes,
                                        err_t *err);
// func FromX509Bundle(x509Bundle *x509bundle.Bundle) *Bundle {
spiffebundle_Bundle* spiffebundle_FromX509Bundle(const x509bundle_Bundle *bundle);
// func FromJWTBundle(jwtBundle *jwtbundle.Bundle) *Bundle {
spiffebundle_Bundle* spiffebundle_FromJWTBundle(const jwtbundle_Bundle *bundle);
// func FromX509Authorities(trustDomain spiffeid.TrustDomain, x509Authorities []*x509.Certificate) *Bundle {
spiffebundle_Bundle* spiffebundle_FromX509Authorities(const spiffeid_TrustDomain td,
                                                        const X509 **auths);
// func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
spiffebundle_Bundle* spiffebundle_FromJWTBundle(const spiffeid_TrustDomain td,
                                                const map_string_EVP_PKEY *auths);
// func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
spiffeid_TrustDomain spiffebundle_Bundle_TrustDomain(const spiffebundle_Bundle *b);
// func (b *Bundle) X509Authorities() []*x509.Certificate {
X509** spiffebundle_Bundle_X509Authorities(spiffebundle_Bundle *b);
// func (b *Bundle) AddX509Authority(x509Authority *x509.Certificate) {
void spiffebundle_Bundle_AddX509Authority(spiffebundle_Bundle *b, X509 *auth);
// func (b *Bundle) RemoveX509Authority(x509Authority *x509.Certificate) {
void spiffebundle_Bundle_RemoveX509Authority(spiffebundle_Bundle *b, X509 *auth);
// func (b *Bundle) HasX509Authority(x509Authority *x509.Certificate) bool {
bool spiffebundle_Bundle_HasX509Authority(spiffebundle_Bundle *b, X509 *auth);
// func (b *Bundle) SetX509Authorities(authorities []*x509.Certificate) {
void spiffebundle_Bundle_SetX509Authorities(spiffebundle_Bundle *b, X509 **auths);
// func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
map_string_EVP_PKEY* spiffebundle_Bundle_JWTAuthorities(spiffebundle_Bundle *b);
// func (b *Bundle) FindJWTAuthority(keyID string) (crypto.PublicKey, bool) {
EVP_PKEY* spiffebundle_Bundle_FindJWTAuthority(spiffebundle_Bundle *b, 
                                                const string_t keyID, 
                                                bool *suc);
// func (b *Bundle) HasJWTAuthority(keyID string) bool {
bool spiffebundle_Bundle_HasJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID);
// func (b *Bundle) AddJWTAuthority(keyID string, jwtAuthority crypto.PublicKey) error {
err_t spiffebundle_Bundle_AddJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID,
                                            EVP_PKEY *auth);
// func (b *Bundle) RemoveJWTAuthority(keyID string) {
void spiffebundle_Bundle_RemoveJWTAuthority(spiffebundle_Bundle *b, 
                                            const string_t keyID);
// func (b *Bundle) SetJWTAuthorities(jwtAuthorities map[string]crypto.PublicKey) {
void spiffebundle_Bundle_SetJWTAuthorities(spiffebundle_Bundle *b,
                                            map_string_EVP_PKEY *auths);
// func (b *Bundle) Empty() bool {
bool spiffebundle_Bundle_Empty(spiffebundle_Bundle *b);
// func (b *Bundle) RefreshHint() (refreshHint time.Duration, ok bool) {
struct timespec spiffebundle_Bundle_RefreshHint(spiffebundle_Bundle *b, bool *suc);
// func (b *Bundle) SetRefreshHint(refreshHint time.Duration) {
void spiffebundle_Bundle_SetRefreshHint(spiffebundle_Bundle *b,
                                        const timespec refHint);
// func (b *Bundle) ClearRefreshHint() {
void spiffebundle_Bundle_ClearRefreshHint(spiffebundle_Bundle *b);
// func (b *Bundle) SequenceNumber() (uint64, bool) {
uint64_t spiffebundle_Bundle_SequenceNumber(spiffebundle_Bundle *b, bool *suc);
// func (b *Bundle) SetSequenceNumber(sequenceNumber uint64) {
void spiffebundle_Bundle_SetSequenceNumber(spiffebundle_Bundle *b, uint64_t seqNumber);
// func (b *Bundle) ClearSequenceNumber() {
void spiffebundle_Bundle_ClearSequenceNumber(spiffebundle_Bundle *b);
// func (b *Bundle) Marshal() ([]byte, error) {
byte* spiffebundle_Bundle_Marshal(spiffebundle_Bundle *b, err_t *err);
// func (b *Bundle) Clone() *Bundle {
spiffebundle_Bundle* spiffebundle_Bundle_Clone(spiffebundle_Bundle *b);
// func (b *Bundle) X509Bundle() *x509bundle.Bundle {
x509bundle_Bundle* spiffebundle_Bundle_X509Bundle(spiffebundle_Bundle *b);
// func (b *Bundle) JWTBundle() *jwtbundle.Bundle {
jwtbundle_Bundle* spiffebundle_Bundle_JWTBundle(spiffebundle_Bundle *b);
// func (b *Bundle) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
spiffebundle_Bundle* spiffebundle_Bundle_GetBundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
// func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
x509bundle_Bundle* spiffebundle_Bundle_GetX509BundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
// func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
jwtbundle_Bundle* spiffebundle_Bundle_GetJWTBundleForTrustDomain(
                                                spiffebundle_Bundle *b,
                                                const spiffeid_TrustDomain td,
                                                err_t *err);
// func (b *Bundle) Equal(other *Bundle) bool {
bool spiffebundle_Bundle_Equal(const spiffebundle_Bundle *b1, 
                                const spiffebundle_Bundle *b2);
// func refreshHintEqual(a, b *time.Duration) bool {
bool spiffebundle_refreshHintEqual(const struct timespec *t1,
                                    const struct timespec *t2);
// func sequenceNumberEqual(a, b *uint64) bool {
bool spiffebundle_sequenceNumberEqual(const uint64_t *a,
                                        const uint64_t *b);
// func copyRefreshHint(refreshHint *time.Duration) *time.Duration {
struct timespec* spiffebundle_copyRefreshHint(const struct timespec *ts);
// func copySequenceNumber(sequenceNumber *uint64) *uint64 {
uint64_t* spiffebundle_copySequenceNumber(const uint64_t *seqNum);

#endif