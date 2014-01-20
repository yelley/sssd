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
*/

#include <security/pam_modules.h>
#include "src/util/util.h"
#include "src/providers/data_provider.h"
#include "src/providers/dp_backend.h"
#include "src/providers/ad/ad_access.h"
#include "src/providers/ad/ad_common.h"
#include "src/providers/ldap/sdap_access.h"
#include "src/providers/ldap/sdap_async.h"
#include "src/providers/ldap/sdap.h"

#define AD_AT_GPLINK "gPLink"
#define AD_AT_GPOPTIONS "gpOptions"

struct ad_gpo_access_state {
    struct tevent_context *ev;
    struct ad_access_ctx *ctx;
    struct pam_data *pd;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    struct sdap_id_conn_ctx *conn;
    struct sdap_id_op *sdap_op; 
};

static int ad_gpo_access_step(struct tevent_req *req);
static void ad_gpo_connect_done(struct tevent_req *subreq);
static void ad_gpo_som_done(struct tevent_req *subreq);

struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct be_ctx *be_ctx,
		struct sss_domain_info *domain,
		struct ad_access_ctx *ctx,
		struct pam_data *pd)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    errno_t ret;

    DEBUG(1, ("Entering ad_gpo_access_send.\n"));

    req = tevent_req_create(mem_ctx, &state, struct ad_gpo_access_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ctx = ctx;
    state->pd = pd;
    state->be_ctx = be_ctx;
    state->domain = domain;
    state->conn = ad_get_dom_ldap_conn(ctx->ad_id_ctx, domain);

    DEBUG(1, ("Creating LDAP connection for GPO access checking\n"));

    state->sdap_op = sdap_id_op_create(state, state->conn->conn_cache);

    if (!state->sdap_op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto done;
    }

    ret = ad_gpo_access_step(req);
    if (ret != EOK) {
        goto done;
    }

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;

}

static int ad_gpo_access_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    int ret;

    state = tevent_req_data(req, struct ad_gpo_access_state);

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(2, ("sdap_id_op_connect_send failed: %d (%s)\n", ret, strerror(ret)));
        return ret;
    }

    tevent_req_set_callback(subreq, ad_gpo_connect_done, req);
    return EOK;
}

static void
ad_gpo_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    char *basedn;
    char* filter;
    int dp_error;
    errno_t ret;

    /* const char *attrs[] = {AD_AT_GPLINK, NULL};*/
    const char *attrs[] = {
            "*",
            "altServer",
            SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS,
            "supportedControl",
            "supportedExtension",
            "supportedFeatures",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
            SDAP_ROOTDSE_ATTR_AD_VERSION,
            SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT,
            SDAP_IPA_LAST_USN, SDAP_AD_LAST_USN,
            NULL
    };

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    /*    sdap_options *opts = state->ctx->sdap_access_ctx->id_ctx->opts;*/

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
	  /* ret = ad_gpo_access_decide_offline(req);_
	     if (ret == EOK) {
	       tevent_req_done(req);
	       return;
            }
	  */
        }

	DEBUG(1, ("sdap_id_op_connect_recv failed\n"));
        tevent_req_error(req, ret);
        return;
    }

    /* Convert the domain name into domain DN */
    ret = domain_to_basedn(state, state->domain->name, &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
            ("Cannot convert domain name [%s] to base DN [%d]: %s\n",
            state->domain->name, ret, strerror(ret)));
        goto done;
    }

    DEBUG(1, ("domain_to_basedn yields %s\n", basedn));

    filter = talloc_asprintf(state, "(distinguishedName=%s)", basedn);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    DEBUG(1, ("filter is %s\n", filter));
    DEBUG(1, ("ad_gpo_connect_done about to call sdap_get_generic_send\n"));
    subreq = sdap_get_generic_send(state,
				   state->ev, 
				   state->ctx->sdap_access_ctx->id_ctx->opts,
                                   sdap_id_op_handle(state->sdap_op),
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   dp_opt_get_int(state->ctx->sdap_access_ctx->id_ctx->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
				   false);

    DEBUG(1, ("YKE: completed sdap_get_generic_send\n"));
    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_som_done, req);



 done:
    if (ret == EOK) {
      tevent_req_done(req);
    } else {
      tevent_req_error(req, ret);
    }
    return;

}

static void
ad_gpo_som_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret, dp_error;
    size_t num_results;
    struct sysdb_attrs **results;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

    DEBUG(1, ("ad_gpo_som_done about to call sdap_get_generic_recv\n"));
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);
    if (ret) {
      goto done;
    }

    DEBUG(1, ("num_results=%d\n, num_results"));

    if (num_results == 0){
      DEBUG(1, ("num_result is 0\n"));
      tevent_req_error(req, ENOENT);
      return;
    }

    if (num_results == 1){
      DEBUG(1, ("num_result is 1\n"));
    }

    DEBUG(1, ("YKE: about to call sdap_id_op_done\n"));
    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    return;

}

errno_t ad_gpo_access_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}




