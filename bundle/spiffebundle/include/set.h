#ifndef __INCLUDE_SPIFFEBUNDLE_SET_H__
#define __INCLUDE_SPIFFEBUNDLE_SET_H__

#include "bundle.h"
#include "../../../utils/include/util.h"

typedef struct map_string_spiffebundle_Bundle
{
    string_t key;
    spiffebundle_Bundle *value;
} map_string_spiffebundle_Bundle;

typedef struct spiffebundle_Set
{
    mtx_t mtx;
    map_string_spiffebundle_Bundle *bundles;
} spiffebundle_Set;

// func NewSet(bundles ...*Bundle) *Set {
spiffebundle_Set* spiffebundle_NewSet(int n_args, ...);
// func (s *Set) Add(bundle *Bundle) {
void spiffebundle_Set_Add(spiffebundle_Set *s, spiffebundle_Bundle *bundle);
// func (s *Set) Remove(trustDomain spiffeid.TrustDomain) {
void spiffebundle_Set_Remove(spiffebundle_Set *s, const spiffeid_TrustDomain td);
// func (s *Set) Has(trustDomain spiffeid.TrustDomain) bool {
bool spiffebundle_Set_Has(spiffebundle_Set *s, const spiffeid_TrustDomain td);
// func (s *Set) Get(trustDomain spiffeid.TrustDomain) (*Bundle, bool) {
spiffebundle_Bundle* spiffebundle_Set_Get(spiffebundle_Set *s, 
                                    const spiffeid_TrustDomain td,
                                    bool *suc);
// func (s *Set) Bundles() []*Bundle {
spiffebundle_Bundle** spiffebundle_Set_Bundles(spiffebundle_Set *s);
// func (s *Set) Len() int {
uint32_t spiffebundle_Set_Len(spiffebundle_Set *s);
// func (s *Set) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
spiffebundle_Bundle* spiffebundle_Set_GetBundleForTrustDomain(
                                    spiffebundle_Set *s, 
                                    const spiffeid_TrustDomain td,
                                    err_t *err);
// func (s *Set) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
x509bundle_Bundle* spiffebundle_Set_GetX509BundleForTrustDomain(
                                    spiffebundle_Set *s, 
                                    const spiffeid_TrustDomain td,
                                    err_t *err);
// func (s *Set) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
jwtbundle_Bundle* spiffebundle_Set_GetJWTBundleForTrustDomain(
                                    spiffebundle_Set *s, 
                                    const spiffeid_TrustDomain td,
                                    err_t *err);

#endif