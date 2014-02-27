/*
  SSSD

  ad_gpo.c

  Authors:
  Yassir Elley <yelley@redhat.com>

  Copyright (C) 2013 Red Hat

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
12345678901234567890123456789012345678901234567890123456789012345678901234567890            
*/

#include <security/pam_modules.h>
#include "util/util.h"
#include "providers/data_provider.h"
#include "providers/dp_backend.h"
#include "providers/ad/ad_access.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_gpo.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap.h"

#define AD_AT_DN "distinguishedName"
#define AD_AT_UAC "userAccountControl"
#define AD_AT_CONFIG_NC "configurationNamingContext"
#define AD_AT_GPLINK "gPLink"
#define AD_AT_GPOPTIONS "gpOptions"
#define AD_AT_NT_SEC_DESC "nTSecurityDescriptor"
#define AD_AT_CN "cn"
#define AD_AT_DISPLAY_NAME "displayName"
#define AD_AT_FILE_SYS_PATH "gPCFileSysPath"
#define AD_AT_VERSION_NUMBER "versionNumber"
#define AD_AT_MACHINE_EXT_NAMES "gPCMachineExtensionNames"
#define AD_AT_USER_EXT_NAMES "gPCUserExtensionNames"
#define AD_AT_FUNC_VERSION "gPCFunctionalityVersion"
#define AD_AT_FLAGS "flags"

#define UAC_WORKSTATION_TRUST_ACCOUNT 0x00001000
#define AD_AGP_GUID "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
#define AD_AUTHENTICATED_USERS_SID "S-1-5-11"
#define SID_MAX_LEN 1024

#define GPO_VERSION_USER(x) (x >> 16)
#define GPO_VERSION_MACHINE(x) (x & 0xffff)

bool string_to_sid(struct dom_sid *sidout, const char *sidstr);
int dom_sid_string_buf(const struct dom_sid *sid, char *buf, int buflen);
bool dom_sid_equal(const struct dom_sid *sid1, const struct dom_sid *sid2);

enum ndr_err_code
ndr_pull_security_descriptor(struct ndr_pull *ndr,
                             int ndr_flags,
                             struct security_descriptor *r);

struct gp_som {
    char *som_dn;
    struct gp_gplink **gplink_list;
};

struct gp_gplink {
    char *gpo_dn;
    bool enforced;
};

struct gp_gpo {
    struct security_descriptor *gpo_sd;
    char *gpo_dn;
    char *gpo_guid;
    char *gpo_display_name;
    char *gpo_file_sys_path;
    uint32_t gpo_container_version_number;
    char **gpo_cse_guids;
    int gpo_func_version;
    int gpo_flags;
};

enum ace_eval_status {
    AD_GPO_ACE_DENIED,
    AD_GPO_ACE_ALLOWED,
    AD_GPO_ACE_NEUTRAL
};

/* 
 * This function retrieves the SIDs corresponding to the input user and returns
 * the user_sid, group_sids, and group_size in their respective output params.
 *
 * Note: since pam_authenticate() must complete successfully before the
 * gpo access checks are called, we can safely assume that the user/computer has
 * been authenticated. As such, this function always adds the
 * AD_AUTHENTICATED_USERS_SID to the group_sids.
 */
static errno_t
ad_gpo_get_sids(TALLOC_CTX *mem_ctx,
                char *user,
                struct sss_domain_info *domain,
                const char **_user_sid,
                const char ***_group_sids,
                int *_group_size)
{
    struct ldb_result *res;
    int ret = 0;
    int i = 0;
    int numgroupsids = 0;
    const char *mysid = NULL;
    const char **groupsids = NULL;

    /* first result from sysdb_initgroups is user_sid; rest are group_sids */
    ret = sysdb_initgroups(mem_ctx, domain, user, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_initgroups failed: [%d](%s)\n",
               ret, strerror(ret)));
        return ret;
    }

    mysid = ldb_msg_find_attr_as_string(res->msgs[0], 
                                        SYSDB_SID_STR, NULL);
    numgroupsids = (res->count) - 1;

    /* we use (numgroupsids + 1) to leave room for AD_AUTHENTICATED_USERS_SID */
    groupsids = malloc((numgroupsids + 1) * sizeof(char*));
    for (i = 0; i < numgroupsids; i++) {
        groupsids[i] = malloc(SID_MAX_LEN * sizeof(char));
        groupsids[i] = ldb_msg_find_attr_as_string(res->msgs[i+1], 
                                                   SYSDB_SID_STR, NULL);
    }

    groupsids[i] = malloc(SID_MAX_LEN * sizeof(char));
    groupsids[i] = AD_AUTHENTICATED_USERS_SID;
    
    *_group_size = numgroupsids + 1;
    *_group_sids = groupsids;
    *_user_sid = mysid;
    return EOK;
}

/* 
 * This function determines whether the input ACE includes any of the
 * client's SIDs. The boolean result is assigned to the _included output param.
 */
static errno_t
ad_gpo_ace_includes_client_sid(const char *user_sid,
                               const char **group_sids,
                               int group_size,
                               struct security_ace *ace,
                               bool *_included)
{
    int i = 0;
    char *buf = NULL;
    struct dom_sid ace_dom_sid;
    struct dom_sid user_dom_sid;
    struct dom_sid group_dom_sid;
    
    ace_dom_sid = ace->trustee;
    
    buf = malloc(SID_MAX_LEN);
    
    dom_sid_string_buf(&ace_dom_sid, buf, SID_MAX_LEN);

    if (!string_to_sid(&user_dom_sid, user_sid)) {
        DEBUG(SSSDBG_OP_FAILURE, ("string_to_sid failed\n"));
        return EINVAL;
    }

    if (dom_sid_equal(&ace_dom_sid, &user_dom_sid)) {
        *_included = true;
        return EOK;
    }
    
    for (i=0; i<group_size; i++){
        if (!string_to_sid(&group_dom_sid, group_sids[i])) {
            DEBUG(SSSDBG_OP_FAILURE, ("string_to_sid failed\n"));
            return EINVAL;
        }
        if (dom_sid_equal(&ace_dom_sid, &group_dom_sid)) {
            *_included = true;
            return EOK;
        }
    }
    
    *_included = false;
    return EOK;
}


/* 
 * This function determines whether use of the extended right 
 * named "ApplyGroupPolicy" (AGP) is allowed, by comparing the specified
 * user_sid and group_sids against the specified access control entry (ACE).
 * This function returns ALLOWED, DENIED, or NEUTRAL depending on whether
 * the ACE explictly allows, explicitly denies, or does neither.
 * 
 * The ACE evaluation algorithm is specified in [MS-ADTS] 5.1.3.3.4:
 * - Deny access by default
 * - If the "Inherit Only" (IO) flag is set in the ACE, skip the ACE.
 * - If the SID in the ACE does not match any SID in the requester's
 *   security context, skip the ACE
 * - If the ACE type is "Object Access Allowed", the access right
 *   RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 *   field in the ACE is either not present OR contains a GUID value equal
 *   to AGP, then grant requested control access right. Stop access checking.
 * - If the ACE type is "Object Access Denied", the access right
 * - RIGHT_DS_CONTROL_ACCESS (CR) is present in M, and the ObjectType
 * - field in the ACE is either not present OR contains a GUID value equal
 * - to AGP, then deny the requested control access right. Stop access checking.
 */
static enum ace_eval_status ad_gpo_evaluate_ace(struct security_ace *ace,
                                                const char *user_sid,
                                                const char **group_sids,
                                                int group_size)
{
    bool agp_included = false;
    bool included = false;
    int ret = 0;
    struct security_ace_object object;
    struct GUID ext_right_agp_guid;
    
    if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
        return AD_GPO_ACE_NEUTRAL;
    }

    ret = ad_gpo_ace_includes_client_sid(user_sid, group_sids, group_size, ace, 
                                             &included);

    if (ret != EOK) {
        return AD_GPO_ACE_DENIED;
    }

    if (!included) {
        return AD_GPO_ACE_NEUTRAL;
    }

    object = ace->object.object;
    GUID_from_string(AD_AGP_GUID, &ext_right_agp_guid);

    if (object.flags & SEC_ACE_OBJECT_TYPE_PRESENT) {
        if (GUID_equal(&object.type.type, &ext_right_agp_guid)) {
            agp_included = true;    
        }
    } else {
        agp_included = false;
    }

    if (ace->access_mask & SEC_ADS_CONTROL_ACCESS) {
        if (agp_included) {
            if (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT) {
                return AD_GPO_ACE_ALLOWED;
            } else if (ace->type == SEC_ACE_TYPE_ACCESS_DENIED_OBJECT) {
                return AD_GPO_ACE_DENIED;
            }
        }
    }

    return AD_GPO_ACE_DENIED;
}

/* 
 * This function parses the input data blob and assigns the resulting
 * security_descriptor object to the _gpo_sd output parameter.
 */
static errno_t ad_gpo_parse_sd(TALLOC_CTX *mem_ctx,
                               uint8_t *data,
                               size_t length,
                               struct security_descriptor **_gpo_sd)
{

    struct ndr_pull *ndr_pull = NULL;
    struct security_descriptor sd;
    DATA_BLOB blob;

    blob.data = data;
    blob.length = length;

    ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ndr_pull_init_blob() failed.\n"));
        return EINVAL;
    }

    ndr_pull_security_descriptor(ndr_pull, NDR_SCALARS|NDR_BUFFERS, &sd);

    *_gpo_sd = talloc_memdup(mem_ctx, &sd, sizeof(struct security_descriptor));

    return EOK;
}

/* 
 * This function extracts the GPO's DACL (discretionary access control list)
 * from the GPO's specified security descriptor, and determines whether
 * the GPO is applicable to the policy target, by comparing the specified
 * user_sid and group_sids against each access control entry (ACE) in the DACL.
 * The boolean result is assigned to the _access_allowed output parameter.
 */
static errno_t ad_gpo_evaluate_dacl(TALLOC_CTX *mem_ctx,
                                    struct security_acl *dacl,
                                    const char *user_sid,
                                    const char **group_sids,
                                    int group_size,
                                    bool *_access_allowed)
{
    uint32_t num_aces = 0;
    enum ace_eval_status ace_status;
    int i = 0;
    struct security_ace *ace = NULL;

    num_aces = dacl->num_aces;

    /* 
     * [MS-ADTS] 5.1.3.3.4:
     * If the DACL does not have any ACE, then deny the requester the
     * requested control access right.
     */
    if (num_aces == 0) {
        *_access_allowed = false;
        return EOK;
    }

    for (i = 0; i < dacl->num_aces; i ++) {
        ace = &dacl->aces[i];

        ace_status = ad_gpo_evaluate_ace(ace, user_sid, group_sids, group_size);

        switch (ace_status) {
        case AD_GPO_ACE_NEUTRAL:
            continue;
        case AD_GPO_ACE_ALLOWED:
            *_access_allowed = true;
            return EOK;
        case AD_GPO_ACE_DENIED:
            *_access_allowed = false;
            return EOK;
        }
    }

    *_access_allowed = false;
    return EOK;
}

/* 
 * This function takes an input gpo_list, filters out any gpo that is
 * not applicable to the policy target and assigns the result to the
 * _filtered_gpo_list output parameter. The filtering algorithm is
 * defined in [MS-GPOL] 3.2.5.1.6
 */
static errno_t
ad_gpo_filter_gpo_list(TALLOC_CTX *mem_ctx, 
                       char *user,
                       struct sss_domain_info *domain,
                       struct gp_gpo **gpo_list,
                       struct gp_gpo ***_filtered_gpo_list)
{
    int i = 0;
    int ret = 0;
    struct gp_gpo *gpo = NULL;
    struct security_descriptor *sd = NULL;
    struct security_acl *dacl = NULL;
    const char *user_sid = NULL;
    const char **group_sids = NULL;
    int group_size = 0;
    int gpo_dn_idx = 0;
    int num_gpos = 0;
    bool access_allowed = false;
    struct gp_gpo **filtered_gpo_list = NULL;

    ret = ad_gpo_get_sids(mem_ctx, user, domain, &user_sid,
                          &group_sids, &group_size);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to retrieve SIDs: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    while (gpo_list[num_gpos]) {
        num_gpos++;
    }

    filtered_gpo_list = talloc_array(mem_ctx, struct gp_gpo *, num_gpos + 1);
    if (filtered_gpo_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_gpos; i++) {

        access_allowed = false;
        gpo = gpo_list[i];
        sd = gpo->gpo_sd;
        dacl = gpo->gpo_sd->dacl;

        DEBUG(SSSDBG_TRACE_ALL, ("gpo_dn:%s\n", gpo->gpo_dn));

        /* gpo_func_version must be set to version 2 */
        if (gpo->gpo_func_version != 2) {
            DEBUG(SSSDBG_TRACE_ALL,
                  ("GPO not applicable to target per security filtering\n"));
            continue;
        }

        /* gpo_flags value of 2 means that GPO's computer portion is disabled */
        if (gpo->gpo_flags == 2) {
            DEBUG(SSSDBG_TRACE_ALL,
                  ("GPO not applicable to target per security filtering\n"));
            continue;
        }

        /* 
         * [MS-ADTS] 5.1.3.3.4:
         * If the security descriptor has no DACL or its "DACL Present" bit
         * is not set, then grant requester the requested control access right.
         */

        if ((!(sd->type & SEC_DESC_DACL_PRESENT)) || (dacl == NULL)) {
            DEBUG(SSSDBG_TRACE_ALL, ("DACL is not present\n"));
            access_allowed = true;
            break;
        }

        ad_gpo_evaluate_dacl(mem_ctx, dacl, user_sid, group_sids,
                             group_size, &access_allowed);
        if (access_allowed) {
            DEBUG(SSSDBG_TRACE_ALL, 
                  ("GPO applicable to target per security filtering\n"));
            filtered_gpo_list[gpo_dn_idx] = talloc_steal(mem_ctx, gpo);
            gpo_dn_idx++;
        } else {
            DEBUG(SSSDBG_TRACE_ALL, 
                  ("GPO not applicable to target per security filtering\n"));
        }
    }

    filtered_gpo_list[gpo_dn_idx] = NULL;

    *_filtered_gpo_list = talloc_steal(mem_ctx, filtered_gpo_list);

    ret = EOK;

 done:
    return ret;
}

/* 
 * This function populates the _cse_list output parameter by parsing the
 * input raw_machine_ext_names_value into an array of cse_guid strings.
 *
 * The raw_machine_ext_names_value is a single string in the following format:
 * "[{cse_guid_1}{tool_guid1}]...[{cse_guid_n}{tool_guid_n}]"
 */
static errno_t
ad_gpo_parse_machine_ext_names(TALLOC_CTX *mem_ctx,
                               char *raw_machine_ext_names_value,
                               char ***_cse_guid_list)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *copy;
    char *first;
    char *last;
    char *cse_guid;
    char *tool_guid;
    char delim = ']';
    char **cse_guid_list;
    int i;
    int ret;
    int cse_guid_count = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    copy = raw_machine_ext_names_value;
    if (copy == NULL) {    
        ret = ENOMEM;
        goto done;
    }

    while ((copy = strchr(copy, delim))) {
        if (copy == NULL) break;
        copy++;
        cse_guid_count++;
    }

    if (cse_guid_count == 0) {
        ret = EINVAL;
        goto done;
    }

    cse_guid_list = talloc_array(tmp_ctx, char *, cse_guid_count + 1);
    if (cse_guid_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    copy = raw_machine_ext_names_value;
    for (i = 0; i < cse_guid_count; i++) {
        first = copy + 1;
        last = strchr(first, delim);
        if (last == NULL) {
            break;
        }
        *last = '\0';
        last++;
        cse_guid = first;
        first ++;
        tool_guid = strchr(first, '{');
        if (tool_guid == NULL) {
            break;
        }
        *tool_guid = '\0';
        cse_guid_list[i] = talloc_strdup(cse_guid_list, cse_guid);
        copy = last;
    }
    cse_guid_list[i] = NULL;

    *_cse_guid_list = talloc_steal(mem_ctx, cse_guid_list);
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/* 
 * This function returns the parent of an LDAP DN 
 */
static char *ad_gpo_parent_dn(const char *dn)
{
    char *p;

    if (dn == NULL) {
        return NULL;
    }

    p = strchr(dn, ',');
    if (p == NULL) {
        return NULL;
    }

    return p+1;
}

/* 
 * This function examines the gp_gplink objects in each gp_som object specified
 * in the input som_list, and populates the _gpo_list output parameter's
 * gpo_dn fields with prioritized list of GPO DNs. Prioritization ensures that:
 * - GPOs linked to an OU will be applied after GPOs linked to a Domain,
 *   which will be applied after GPOs linked to a Site.
 * - multiple GPOs linked to a single SOM are applied in their link order
 *   (i.e. 1st GPO linked to SOM is applied after 2nd GPO linked to SOM, etc).
 * - enforced GPOs are applied after unenforced GPOs.
 *
 * As such, the _gpo_list output's dn fields looks like (all in link order):
 * [unenforced {Site, Domain, OU}; enforced {Site, Domain, OU}]
 *
 * Note that in the case of conflicting policy settings, GPOs appearing later 
 * in the list will trump GPOs appearing earlier in the list.
 */
static errno_t
ad_gpo_populate_gpo_list(TALLOC_CTX *mem_ctx, 
                         struct gp_som **som_list,
                         struct gp_gpo ***_gpo_list)
{

    TALLOC_CTX *tmp_ctx = NULL;
    struct gp_som *gp_som = NULL;
    struct gp_gplink *gp_gplink = NULL;
    struct gp_gpo **gpo_list = NULL;
    char **enforced_gpo_dns = NULL;
    char **unenforced_gpo_dns = NULL;
    int num_gpos = 0;
    int gpo_dn_idx = 0;  
    int num_enforced = 0;
    int enforced_idx = 0;
    int num_unenforced = 0;
    int unenforced_idx = 0;
    int i = 0;
    int j = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    while (som_list[i]) {
        gp_som = som_list[i];
        j = 0;
        while (gp_som->gplink_list[j]) {
            gp_gplink = gp_som->gplink_list[j];
            if (gp_gplink == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("unexpected null gp_gplink\n"));
                ret = EINVAL;
                goto done;
            }
            if (gp_gplink->enforced){
                num_enforced++;
            } else {
                num_unenforced++;
            }
            j++;
        }
        i++;
    }

    num_gpos = num_enforced + num_unenforced;

    if (num_gpos == 0) {
        *_gpo_list = NULL;
        ret = EOK;
        goto done;
    }
    
    enforced_gpo_dns = talloc_array(tmp_ctx, char *, num_enforced + 1);
    if (enforced_gpo_dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    unenforced_gpo_dns = talloc_array(tmp_ctx, char *, num_unenforced + 1);
    if (unenforced_gpo_dns == NULL) {
        ret = ENOMEM;
        goto done;
    }

    i = 0;
    while (som_list[i]) {
        gp_som = som_list[i];
        j = 0;
        while (gp_som->gplink_list[j]) {
            gp_gplink = gp_som->gplink_list[j];
            if (gp_gplink == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("unexpected null gp_gplink\n"));
                ret = EINVAL;
                goto done;
            }
            if (gp_gplink->enforced){
                enforced_gpo_dns[enforced_idx] = talloc_strdup(enforced_gpo_dns, 
                                                     gp_gplink->gpo_dn);
                if (enforced_gpo_dns[enforced_idx] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                enforced_idx++;
            } else {
                unenforced_gpo_dns[unenforced_idx] =
                    talloc_strdup(unenforced_gpo_dns, gp_gplink->gpo_dn);
                if (unenforced_gpo_dns[unenforced_idx] == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                unenforced_idx++;
            }
            j++;
        }
        i++;
    }
    enforced_gpo_dns[num_enforced] = NULL;
    unenforced_gpo_dns[num_unenforced] = NULL;

    gpo_list = talloc_array(tmp_ctx, struct gp_gpo *, num_gpos + 1);
    if (gpo_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    gpo_dn_idx = 0;
    for (i = num_unenforced - 1; i >= 0; i--) {
        gpo_list[gpo_dn_idx] = talloc_zero(gpo_list, struct gp_gpo);
        if (gpo_list[gpo_dn_idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        gpo_list[gpo_dn_idx]->gpo_dn = talloc_strdup(gpo_list[gpo_dn_idx],
                                                     unenforced_gpo_dns[i]);
        if (gpo_list[gpo_dn_idx]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }
        DEBUG(SSSDBG_TRACE_FUNC, ("gpo_list[%d]->gpo_dn: %s\n", gpo_dn_idx,
                                  gpo_list[gpo_dn_idx]->gpo_dn));
        gpo_dn_idx++;
    }

    for (i = 0; i < num_enforced; i++) {

        gpo_list[gpo_dn_idx] = talloc_zero(gpo_list, struct gp_gpo);
        if (gpo_list[gpo_dn_idx] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        gpo_list[gpo_dn_idx]->gpo_dn = talloc_strdup(gpo_list[gpo_dn_idx],
                                                     enforced_gpo_dns[i]);
        if (gpo_list[gpo_dn_idx]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_FUNC, ("gpo_list[%d]->gpo_dn: %s\n", gpo_dn_idx, 
                                  gpo_list[gpo_dn_idx]->gpo_dn));
        gpo_dn_idx++;
    }

    gpo_list[gpo_dn_idx] = NULL;

    *_gpo_list = talloc_steal(mem_ctx, gpo_list);

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/* 
 * This function populates the _gplink_list output parameter by parsing the
 * input raw_gplink_value into an array of gp_gplink objects, each consisting of
 * a GPO DN and bool enforced field. 
 *
 * The raw_gplink_value is single string consisting of multiple gplink strings.
 * The raw_gplink_value is in the following format:
 *  "[GPO_DN_1;GPLinkOptions_1]...[GPO_DN_n;GPLinkOptions_n]"
 * 

 * Each gplink string consists of a GPO DN and a GPLinkOptions field (which
 * indicates whether its associated GPO DN is ignored, unenforced, or enforced).
 * If a GPO DN is flagged as ignored, it is discarded and will not be added to
 * the _gplink_list. If the allow_enforced_only input is true, AND a GPO DN is
 * flagged as unenforced, it will also be discarded.
 * 
 * Example: if raw_gplink_value="[OU=Sales,DC=FOO,DC=COM;0][DC=FOO,DC=COM;2]"
 *   and allow_enforced_only=FALSE, then the output would consist of following:
 *    _gplink_list[0]: {GPO DN: "OU=Sales,DC=FOO,DC=COM", enforced: FALSE}
 *    _gplink_list[1]: {GPO DN: "DC=FOO,DC=COM",          enforced: TRUE}
 */
static errno_t
ad_gpo_populate_gplink_list(TALLOC_CTX *mem_ctx,
                            char *som_dn,
                            char *raw_gplink_value,
                            struct gp_gplink ***_gplink_list,
                            bool allow_enforced_only) 
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *copy;
    char *first;
    char *last;
    char *dn;
    char *gplink_options;
    char delim = ']';
    struct gp_gplink **gplink_list;
    int i;
    int ret;
    int gplink_number;
    int gplink_count = 0;
    int num_enabled = 0;

    DEBUG(SSSDBG_TRACE_ALL, ("som_dn: %s\n", som_dn));
    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    copy = raw_gplink_value;
    if (copy == NULL) {    
        ret = ENOMEM;
        goto done;
    }

    while ((copy = strchr(copy, delim))) {
        if (copy == NULL) break;
        copy++;
        gplink_count++;
    }

    if (gplink_count == 0) {
        ret = EINVAL;
        goto done;
    }

    gplink_list = talloc_array(tmp_ctx, struct gp_gplink *, gplink_count + 1);
    if (gplink_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    num_enabled = 0;
    copy = raw_gplink_value;
    for (i = 0; i < gplink_count; i++) {
        first = copy + 1;
        last = strchr(first, delim);
        if (last == NULL) {
            break;
        }
        *last = '\0';
        last++;
        dn = first;
        if ( strncasecmp(dn, "LDAP://", 7)== 0 ) {
            dn = dn + 7;
        }
        gplink_options = strchr(first, ';');
        if (gplink_options == NULL) {
            break;
        }
        *gplink_options = '\0';
        gplink_options++;

        gplink_number = atoi(gplink_options);
        DEBUG(SSSDBG_TRACE_ALL, 
              ("gplink_list[%d]: [%s; %d]\n", num_enabled, dn, gplink_number));

        if ((gplink_number == 1) || (gplink_number ==3)){
            /* ignore flag is set */
            DEBUG(SSSDBG_TRACE_ALL, ("ignored gpo skipped\n"));
            copy = last;
            continue;
        }

        if (allow_enforced_only && (gplink_number == 0)) {
            /* unenforced flag is set; only enforced gpos allowed */
            DEBUG(SSSDBG_TRACE_ALL, ("unenforced gpo skipped\n"));
            copy = last;
            continue;
        }

        gplink_list[num_enabled] = talloc_zero(gplink_list, struct gp_gplink);
        if (gplink_list[num_enabled] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        gplink_list[num_enabled]->gpo_dn =
            talloc_strdup(gplink_list[num_enabled], dn);

        if (gplink_list[num_enabled]->gpo_dn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (gplink_number == 0){
            gplink_list[num_enabled]->enforced = 0;
            num_enabled++;
        } else if (gplink_number == 2) {
            gplink_list[num_enabled]->enforced = 1;
            num_enabled++;
        } else {
            ret = EINVAL;
            goto done;
        }

        copy = last;
    }
    gplink_list[num_enabled] = NULL;

    *_gplink_list = talloc_steal(mem_ctx, gplink_list);
    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

/* 
 * This function populates the _som_list output parameter by parsing the input
 * DN into a list of gp_som objects. This function essentially repeatedly
 * appends the input DN's parent to the SOM List (if the parent starts with
 * "OU=" or "DC="), until the first "DC=" component is reached.
 * Example: if input DN is "CN=MyComputer,CN=Computers,OU=Sales,DC=FOO,DC=COM",
 * then SOM List has 2 SOM entries: {[OU=Sales,DC=FOO,DC=COM], [DC=FOO, DC=COM]} 
 */

static errno_t
ad_gpo_populate_som_list(TALLOC_CTX *mem_ctx, 
                         char *target_dn,
                         int *_num_soms,
                         struct gp_som ***_som_list) 
{
    TALLOC_CTX *tmp_ctx = NULL;
    int ret;
    int rdn_count = 0;
    int som_idx = 0;
    struct gp_som **som_list;
    char *parent_dn = NULL;
    char *tmp_dn = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }
      
    tmp_dn = target_dn;
    while ((parent_dn = ad_gpo_parent_dn(tmp_dn))){
        rdn_count++;
        tmp_dn = parent_dn;
    }

    if (rdn_count == 0) {
        *_som_list = NULL;
        ret = EOK;
        goto done;
    }

    /* assume the worst-case, in which every parent is a SOM */
    /* include space for Site SOM and NULL: rdn_count + 1 + 1 */
    som_list = talloc_array(tmp_ctx, struct gp_som *, rdn_count + 1 + 1);
    if (som_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* first, populate the OU and Domain SOMs */
    tmp_dn = target_dn;
    while ((parent_dn = ad_gpo_parent_dn(tmp_dn))){

        if (strncasecmp(parent_dn, "OU=", strlen("OU=")) == 0) {
            som_list[som_idx] = talloc_zero(som_list, struct gp_som);
            if (som_list[som_idx] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            som_list[som_idx]->som_dn = talloc_strdup(som_list[som_idx],
                                                      parent_dn);
            if (som_list[som_idx]->som_dn == NULL) {
                ret = ENOMEM;
                goto done;
            }
            som_idx++;
        } else if (strncasecmp(parent_dn, "DC=", strlen("DC=")) == 0) {
            som_list[som_idx] = talloc_zero(som_list, struct gp_som);
            if (som_list[som_idx] == NULL) {
                ret = ENOMEM;
                goto done;
            }
            som_list[som_idx]->som_dn = talloc_strdup(som_list[som_idx],
                                                      parent_dn);
            if (som_list[som_idx]->som_dn == NULL) {
                ret = ENOMEM;
                goto done;
            }

            som_idx++;
            break;
        }
      
        tmp_dn = parent_dn;
    }

    som_list[som_idx] = NULL;

    *_num_soms = som_idx;

    *_som_list = talloc_steal(mem_ctx, som_list);

    ret = EOK;

 done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ad_gpo_access_state {
    struct tevent_context *ev;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op; 
    struct sdap_options *opts;
    int timeout;
    struct sss_domain_info *domain;
    char *domain_dn;
    char *user;
    char *ad_hostname;
    char *target_dn;
    struct gp_gpo **filtered_gpo_list;
};

static void ad_gpo_connect_done(struct tevent_req *subreq);
static void ad_gpo_target_dn_retrieval_done(struct tevent_req *subreq);
static void ad_gpo_process_som_done(struct tevent_req *subreq);
static void ad_gpo_process_gpo_done(struct tevent_req *subreq);


struct tevent_req *ad_gpo_process_gpo_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev,
                                           struct sdap_id_op *sdap_op,
                                           struct sdap_options *opts,
                                           int timeout,
                                           struct gp_som **som_list);
int ad_gpo_process_gpo_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_gpo ***gpo_list);
struct tevent_req *ad_gpo_process_som_send(TALLOC_CTX *mem_ctx,
                                           struct tevent_context *ev, 
                                           struct sdap_id_conn_ctx *conn,
                                           struct sdap_id_op *sdap_op,
                                           struct sdap_options *opts,
                                           int timeout,
                                           char *domain_name,
                                           char *domain_dn,
                                           char *target_dn);
int ad_gpo_process_som_recv(struct tevent_req *req,
                            TALLOC_CTX *mem_ctx,
                            struct gp_som ***som_list);

struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
                   struct tevent_context *ev,
                   struct sss_domain_info *domain,
                   struct ad_access_ctx *ctx,
                   char *user)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_access_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->domain = domain;
    state->filtered_gpo_list = NULL;
    state->ev = ev;
    state->user = user;
    state->ad_hostname = dp_opt_get_string(ctx->ad_options, AD_HOSTNAME);
    state->opts = ctx->sdap_access_ctx->id_ctx->opts;
    state->timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);
    state->conn = ad_get_dom_ldap_conn(ctx->ad_id_ctx, domain);
    state->sdap_op = sdap_id_op_create(state, state->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed.\n"));
        ret = ENOMEM;
        goto immediately;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_gpo_connect_done, req);

    return req;

 immediately:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    tevent_req_error(req, ret);
    tevent_req_post(req, ev);

    return req;
}

static void
ad_gpo_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    char* filter;
    char *sam_account_name;
    int dp_error;
    errno_t ret;

    const char *attrs[] = {AD_AT_DN, AD_AT_UAC, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Failed to connect to AD server: [%d](%s)\n",
               ret, strerror(ret)));

        tevent_req_error(req, ret);
        return;
    }

    sam_account_name = talloc_asprintf(state, "%s$", state->ad_hostname);
    if (sam_account_name == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("sam_account_name is %s\n", sam_account_name));

    /* Convert the domain name into domain DN */
    ret = domain_to_basedn(state, state->domain->name, &state->domain_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Cannot convert domain name [%s] to base DN [%d]: %s\n",
               state->domain->name, ret, strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    /* SDAP_OC_USER objectclass covers both users and computers */
    filter = talloc_asprintf(state,
                             "(&(objectclass=%s)(%s=%s))",
                             state->opts->user_map[SDAP_OC_USER].name,
                             state->opts->user_map[SDAP_AT_USER_NAME].name,
                             sam_account_name);

    if (filter == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   state->domain_dn, LDAP_SCOPE_SUBTREE,
                                   filter, attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_target_dn_retrieval_done, req);
}

static void
ad_gpo_target_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    int dp_error;
    size_t reply_count;
    struct sysdb_attrs **reply;
    const char *target_dn = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get policy target's DN: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    /* make sure there is only one non-NULL reply returned */

    if (reply_count < 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("No DN retrieved for policy target.\n"));
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("Multiple replies for policy target\n"));
        ret = ERR_INTERNAL;
        goto done;      
    } else if (reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("reply_count is 1, but reply is NULL\n"));
        ret = ERR_INTERNAL;
        goto done;
    } 
    
    /* reply[0] holds requested attributes of single reply */    
    ret = sysdb_attrs_get_string(reply[0], AD_AT_DN, &target_dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    state->target_dn = talloc_strdup(state, target_dn);
    if (state->target_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    uint32_t uac;
    ret = sysdb_attrs_get_uint32_t(reply[0], AD_AT_UAC, &uac);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_uint32_t failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    /* we only support computer policy targets, not users */
    if (!(uac & UAC_WORKSTATION_TRUST_ACCOUNT)) {
        ret = EINVAL;
        goto done;
    }

    state->target_dn = talloc_strdup(state, target_dn);
    if (state->target_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    subreq = ad_gpo_process_som_send(state,
                                     state->ev,
                                     state->conn,
                                     state->sdap_op,
                                     state->opts,
                                     state->timeout,
                                     state->domain->name,
                                     state->domain_dn,
                                     state->target_dn);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_gpo_process_som_done, req);

 done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void
ad_gpo_process_som_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    struct gp_som **som_list;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = ad_gpo_process_som_recv(subreq, state, &som_list);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get som list: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    subreq = ad_gpo_process_gpo_send(state,
                                     state->ev,
                                     state->sdap_op,
                                     state->opts,
                                     state->timeout,
                                     som_list);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_gpo_process_gpo_done, req);

 done:

    if (ret != EOK) {
        tevent_req_error(req, ret);
    }
}

static void
ad_gpo_process_gpo_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    int dp_error;
    struct gp_gpo **gpo_list = NULL;
    int i = 0;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = ad_gpo_process_gpo_recv(subreq, state, &gpo_list);

    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

    if (ret != EOK) {
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get GPO list: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    } 
     
    ret = ad_gpo_filter_gpo_list(state, state->user, state->domain,
                                 gpo_list, &state->filtered_gpo_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to filter GPO list: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    } 

    i = 0;
    while (state->filtered_gpo_list[i]) {
        DEBUG(SSSDBG_TRACE_FUNC, ("filtered_gpo_list[%d]->gpo_dn is %s\n", i, 
                                  state->filtered_gpo_list[i]->gpo_dn));
        i++;
    }

    if (state->filtered_gpo_list[0] == NULL) {
        DEBUG(SSSDBG_TRACE_FUNC, ("filtered_gpo_list is empty\n"));
    }

    /* TBD: initiate SMB retrieval */
    DEBUG(SSSDBG_TRACE_FUNC, ("time for SMB retrieval\n"));

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

errno_t
ad_gpo_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ad_gpo_process_som_state {
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op; 
    struct sdap_options *opts;
    int timeout;
    bool allow_enforced_only;
    char *site_name;
    char *site_dn;
    char *domain_dn;
    struct gp_som **som_list;
    int som_index;
    int num_soms;
};

static void ad_gpo_site_name_retrieval_done(struct tevent_req *subreq);
static void ad_gpo_site_dn_retrieval_done(struct tevent_req *subreq);
static errno_t ad_gpo_get_som_attrs_step(struct tevent_req *req);
static void ad_gpo_get_som_attrs_done(struct tevent_req *subreq);

struct tevent_req *
ad_gpo_process_som_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev, 
                        struct sdap_id_conn_ctx *conn,
                        struct sdap_id_op *sdap_op,
                        struct sdap_options *opts,
                        int timeout,
                        char *domain_name,
                        char *domain_dn,
                        char *target_dn)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_gpo_process_som_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_process_som_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->sdap_op = sdap_op;
    state->opts = opts;
    state->timeout = timeout;
    state->domain_dn = domain_dn;
    state->som_index = -1;
    state->allow_enforced_only = 0;

    ret = ad_gpo_populate_som_list(state, target_dn,
                                   &state->num_soms, &state->som_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to retrieve SOM List : [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto immediately;
    }

    if (state->som_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("target dn must have at least one parent\n"));
        ret = EINVAL;
        goto immediately;
    }

    subreq = ad_master_domain_send(state, state->ev, conn, 
                                   state->sdap_op, domain_name);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ad_master_domain_send failed.\n"));
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_gpo_site_name_retrieval_done, req);

    return req;

 immediately:

    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void
ad_gpo_site_name_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    char *flat_name;
    char *site;
    char *master_sid;
    char *forest;
    const char *attrs[] = {AD_AT_CONFIG_NC, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    /* gpo code only cares about the site name */
    ret = ad_master_domain_recv(subreq, state,
                                &flat_name, &master_sid, &site, &forest);
    talloc_zfree(subreq);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot retrieve master domain info\n"));
        tevent_req_error(req, ENOENT);
        return;
    }

    state->site_name = talloc_asprintf(state, "cn=%s", site);
    if (state->site_name == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_site_dn_retrieval_done, req);
}

static void
ad_gpo_site_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    int dp_error;
    int i = 0;
    size_t reply_count;
    struct sysdb_attrs **reply;
    const char *configNC;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    ret = sdap_get_generic_recv(subreq, state,
                                &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get configNC: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    /* make sure there is only one non-NULL reply returned */

    if (reply_count < 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("No configNC retrieved\n"));
        ret = ENOENT;
        goto done;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("Multiple replies for configNC\n"));
        ret = ERR_INTERNAL;
        goto done;      
    } else if (reply == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("reply_count is 1, but reply is NULL\n"));
        ret = ERR_INTERNAL;
        goto done;
    } 
    
    /* reply[0] holds requested attributes of single reply */    
    ret = sysdb_attrs_get_string(reply[0], AD_AT_CONFIG_NC, &configNC);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }
    state->site_dn =
        talloc_asprintf(state, "%s,cn=Sites,%s", state->site_name, configNC);
    if (state->site_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* note that space was allocated for site_dn when allocating som_list */
    state->som_list[state->num_soms] =
        talloc_zero(state->som_list, struct gp_som);
    if (state->som_list[state->num_soms] == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->som_list[state->num_soms]->som_dn =
        talloc_strdup(state->som_list[state->num_soms], state->site_dn);

    if (state->som_list[state->num_soms]->som_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->num_soms++;
    state->som_list[state->num_soms] = NULL;

    i = 0;
    while (state->som_list[i]) {
        DEBUG(SSSDBG_TRACE_FUNC, ("som_list[%d]->som_dn is %s\n", i, 
                                  state->som_list[i]->som_dn));
        i++;
    }

    ret = ad_gpo_get_som_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

}
static errno_t
ad_gpo_get_som_attrs_step(struct tevent_req *req)
{
    const char *attrs[] = {AD_AT_GPLINK, AD_AT_GPOPTIONS, NULL};
    struct tevent_req *subreq;
    struct ad_gpo_process_som_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_som_state);

    state->som_index++;
    struct gp_som *gp_som = state->som_list[state->som_index];

    /* gp_som is NULL only after all SOMs have been processed */
    if (gp_som == NULL) return EOK;

    char *som_dn = gp_som->som_dn;
    subreq = sdap_get_generic_send(state, state->ev,  state->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   som_dn, LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   state->timeout,
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_get_som_attrs_done, req);
    return EAGAIN;
}

static void
ad_gpo_get_som_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_som_state *state;
    int ret;
    int dp_error;
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    uint8_t *raw_gplink_value;
    uint8_t *raw_gpoptions_value;
    int allow_enforced_only = 0;
    struct gp_som *gp_som;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_som_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);

    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get SOM attributes: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }
    if ((num_results < 1) || (results == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE, ("no attrs found for SOM; try next SOM.\n"));
        ret = ad_gpo_get_som_attrs_step(req);
        goto done;
    } else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("Received multiple replies\n"));
        ret = ERR_INTERNAL;
        goto done;      
    }

    /* Get the gplink value, if available */
    ret = sysdb_attrs_get_el(results[0], AD_AT_GPLINK, &el);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_el() failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE, ("no attrs found for SOM; try next SOM\n"));
        ret = ad_gpo_get_som_attrs_step(req);
        goto done;
    } 

    raw_gplink_value = el[0].values[0].data;

    ret = sysdb_attrs_get_el(results[0], AD_AT_GPOPTIONS, &el);

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }

    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_TRACE_ALL,
              ("gpoptions attr not found or has no value; defaults to 0\n"));
        allow_enforced_only = 0;
    }  else {
        raw_gpoptions_value = el[0].values[0].data;
        allow_enforced_only = atoi((char *)raw_gpoptions_value);
    }

    gp_som = state->som_list[state->som_index];
    ret = ad_gpo_populate_gplink_list(gp_som,
                                      gp_som->som_dn,
                                      (char *)raw_gplink_value,
                                      &gp_som->gplink_list,
                                      state->allow_enforced_only);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("ad_gpo_populate_gplink_list() failed\n"));
        goto done;
    }

    if (allow_enforced_only) {
        state->allow_enforced_only = 1;
    }

    ret = ad_gpo_get_som_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

int
ad_gpo_process_som_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct gp_som ***som_list)
{

    struct ad_gpo_process_som_state *state =
        tevent_req_data(req, struct ad_gpo_process_som_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *som_list = talloc_steal(mem_ctx, state->som_list);
    return EOK;
}

struct ad_gpo_process_gpo_state {
    struct tevent_context *ev;
    struct sdap_id_op *sdap_op; 
    struct sdap_options *opts;
    int timeout;
    struct gp_gpo **gpo_list;
    int gpo_index;
};

static errno_t ad_gpo_get_gpo_attrs_step(struct tevent_req *req);
static void ad_gpo_get_gpo_attrs_done(struct tevent_req *subreq);


struct tevent_req *
ad_gpo_process_gpo_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev, 
                        struct sdap_id_op *sdap_op,
                        struct sdap_options *opts,
                        int timeout,
                        struct gp_som **som_list)
{
    struct tevent_req *req;
    struct ad_gpo_process_gpo_state *state;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_process_gpo_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->sdap_op = sdap_op;
    state->opts = opts;
    state->timeout = timeout;
    state->gpo_index = -1;
    state->gpo_list = NULL;

    ret = ad_gpo_populate_gpo_list(state, som_list, &state->gpo_list);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to retrieve GPO List: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto immediately;
    }

    if (state->gpo_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("no gpos found\n"));
        goto immediately;
    }

    ret = ad_gpo_get_gpo_attrs_step(req);

 immediately:

    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t
ad_gpo_get_gpo_attrs_step(struct tevent_req *req)
{
    const char *attrs[] = {AD_AT_NT_SEC_DESC, AD_AT_CN, AD_AT_DISPLAY_NAME,
                           AD_AT_FILE_SYS_PATH, AD_AT_VERSION_NUMBER,
                           AD_AT_MACHINE_EXT_NAMES, AD_AT_FUNC_VERSION,
                           AD_AT_FLAGS, NULL};
    struct tevent_req *subreq;
    struct ad_gpo_process_gpo_state *state;

    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    state->gpo_index++;
    struct gp_gpo *gp_gpo = state->gpo_list[state->gpo_index];

    /* gp_gpo is NULL only after all GPOs have been processed */
    if (gp_gpo == NULL) return EOK;

    char *gpo_dn = gp_gpo->gpo_dn;

    subreq = sdap_sd_search_send(state, state->ev, 
                                 state->opts, sdap_id_op_handle(state->sdap_op),
                                 gpo_dn, SECINFO_DACL, attrs, state->timeout);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_get_generic_send failed.\n"));
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_get_gpo_attrs_done, req);
    return EAGAIN;
}

static void
ad_gpo_get_gpo_attrs_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_process_gpo_state *state;
    int ret;
    int dp_error;
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    const char *gpo_guid = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_process_gpo_state);

    ret = sdap_sd_search_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);

    if (ret != EOK) {
        ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);
        /* TBD: handle (dp_error == DP_ERR_OFFLINE) case */

        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get GPO attributes: [%d](%s)\n",
               ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    if ((num_results < 1) || (results == NULL)) {
        DEBUG(SSSDBG_OP_FAILURE, ("no attrs found for GPO; try next GPO.\n"));
        ret = ad_gpo_get_gpo_attrs_step(req);
        goto done;
    }
    else if (num_results > 1) {
        DEBUG(SSSDBG_OP_FAILURE, ("Received multiple replies\n"));
        ret = ERR_INTERNAL;
        goto done;      
    }

    struct gp_gpo *gp_gpo = state->gpo_list[state->gpo_index];

    /* retrieve AD_AT_CN */
    ret = sysdb_attrs_get_string(results[0], AD_AT_CN, &gpo_guid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    gp_gpo->gpo_guid = talloc_strdup(gp_gpo, gpo_guid);
    if (gp_gpo->gpo_guid == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_guid: %s\n", gp_gpo->gpo_guid));

    /* retrieve AD_AT_DISPLAY_NAME */
    const char *gpo_display_name = NULL;
    ret = sysdb_attrs_get_string(results[0], AD_AT_DISPLAY_NAME,
                                 &gpo_display_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    gp_gpo->gpo_display_name = talloc_strdup(gp_gpo, gpo_display_name);
    if (gp_gpo->gpo_display_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_display_name: %s\n",
                             gp_gpo->gpo_display_name));

    /* retrieve AD_AT_FILE_SYS_PATH */
    const char *gpo_file_sys_path = NULL;
    ret = sysdb_attrs_get_string(results[0],
                                 AD_AT_FILE_SYS_PATH,
                                 &gpo_file_sys_path);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_string failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    gp_gpo->gpo_file_sys_path = talloc_asprintf(gp_gpo, "%s\\Machine",
                                                gpo_file_sys_path);
    if (gp_gpo->gpo_file_sys_path == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_file_sys_path: %s\n",
                             gp_gpo->gpo_file_sys_path));

    /* retrieve AD_AT_VERSION_NUMBER */
    ret = sysdb_attrs_get_uint32_t(results[0], AD_AT_VERSION_NUMBER,
                                   &gp_gpo->gpo_container_version_number);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_uint32_t failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_container_version_number: %d\n",
                              gp_gpo->gpo_container_version_number));

    /* retrieve AD_AT_MACHINE_EXT_NAMES */
    ret = sysdb_attrs_get_el(results[0], AD_AT_MACHINE_EXT_NAMES, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }
    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("machine_ext_names not found or has no value\n"));
    }

    uint8_t *raw_machine_ext_names = el[0].values[0].data;

    ret = ad_gpo_parse_machine_ext_names(state,
                                         (char *)raw_machine_ext_names,
                                         &gp_gpo->gpo_cse_guids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("ad_gpo_parse_machine_ext_names() failed\n"));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_cse_guid[0]: %s\n",
                             gp_gpo->gpo_cse_guids[0]));

    /* retrieve AD_AT_FUNC_VERSION */
    ret = sysdb_attrs_get_int32_t(results[0], AD_AT_FUNC_VERSION,
                                  &gp_gpo->gpo_func_version);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_int32_t failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_func_version: %d\n",
                             gp_gpo->gpo_func_version));

    /* retrieve AD_AT_FLAGS */
    ret = sysdb_attrs_get_int32_t(results[0], AD_AT_FLAGS,
                                  &gp_gpo->gpo_flags);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("sysdb_attrs_get_int32_t failed: [%d](%s)\n",
               ret, strerror(ret)));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, ("gpo_flags: %d\n", gp_gpo->gpo_flags));

    /* retrieve AD_AT_NT_SEC_DESC */
    ret = sysdb_attrs_get_el(results[0], AD_AT_NT_SEC_DESC, &el);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }
    if ((ret == ENOENT) || (el->num_values == 0)) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("nt_sec_desc attribute not found or has no value\n"));
    }

    ret = ad_gpo_parse_sd(gp_gpo, el[0].values[0].data, el[0].values[0].length,
                          &gp_gpo->gpo_sd);

    ret = ad_gpo_get_gpo_attrs_step(req);

 done:

    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }
}

int
ad_gpo_process_gpo_recv(struct tevent_req *req,
                        TALLOC_CTX *mem_ctx,
                        struct gp_gpo ***gpo_list)
{
    struct ad_gpo_process_gpo_state *state =
        tevent_req_data(req, struct ad_gpo_process_gpo_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *gpo_list = talloc_steal(mem_ctx, state->gpo_list);
    return EOK;
}


