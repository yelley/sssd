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
#include "src/providers/ad/ad_gpo.h"
#include "src/providers/ldap/sdap_access.h"
#include "src/providers/ldap/sdap_async.h"
#include "src/providers/ldap/sdap.h"

struct ad_gpo_access_state {
  struct tevent_context *ev;
  struct ad_access_ctx *ctx;
  struct pam_data *pd;
  struct be_ctx *be_ctx;
  struct sss_domain_info *domain;
  struct sdap_id_conn_ctx *conn;
  struct sdap_id_op *sdap_op; 
  struct sdap_handle *sh;
  struct sdap_options *opts;
  char *basedn;
  char **som_list;
  int som_index;
};


#define AD_AT_DN "distinguishedName"
#define AD_AT_GPLINK "gPLink"
#define AD_AT_GPOPTIONS "gpOptions"

/* maybe ad_gpo_parent_dn should be in util.c?? */
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
 * The ad_gpo_parse_dn function implements the parsing logic specified in 3.2.5.1.3 of [MS-GPOL], which is the section on Domain Scope of Management (SOM) Search.
 * This function essentially repeatedly adds the input DN's parent to the SOM List (if the parent starts with "OU=" or "DC="), until the first "DC=" component is reached.
 * For example:
 *   If the input DN is "CN=MyComputer,OU=Sales,DC=FOO,DC=COM",     then the SOM List consists of two SOM entries:    {[OU=Sales,DC=FOO,DC=COM], [DC=FOO, DC=COM]} 
 *   If the input DN is "CN=MyComputer,CN=Computers,DC=FOO,DC=COM", then the SOM List consists of a single SOM entry: {[DC=FOO, DC=COM]} 
 */
static errno_t ad_gpo_parse_dn(TALLOC_CTX *mem_ctx, char *dn, const char *basedn, char ***_som_list, int *_som_count) {

    TALLOC_CTX *tmp_ctx = NULL;
    int rdn_count = 0;
    int som_count = 0;
    char **som_list;
    char *parent_dn = NULL;
    char *tmp_dn = NULL;

    DEBUG(1, ("YKE\n"));

    tmp_ctx = talloc_new(NULL);
    
    tmp_dn = dn;
    while ((parent_dn = ad_gpo_parent_dn(tmp_dn))){
      rdn_count++;
      tmp_dn = parent_dn;
    }

    /* assume the worst-case, in which every parent is a SOM */
    som_list = talloc_array(tmp_ctx, char *, rdn_count + 1);
    if (!som_list) {
      DEBUG(1, ("returning ENOMEM\n"));
      return ENOMEM;
    }

    tmp_dn = dn;
    while ((parent_dn = ad_gpo_parent_dn(tmp_dn))){

      DEBUG(1, ("parent_dn is %s\n", parent_dn));
      
      if (strncasecmp(parent_dn, "OU=", strlen("OU=")) == 0) {
	som_list[som_count++] = talloc_strdup(som_list, parent_dn);
      } else if (strncasecmp(parent_dn, "DC=", strlen("DC=")) == 0) {
	som_list[som_count++] = talloc_strdup(som_list, parent_dn);
	break;
      }
      
      tmp_dn = parent_dn;
    }
      
    som_list[som_count] = NULL;

    *_som_list = talloc_steal(mem_ctx, som_list);
    *_som_count = som_count;

    talloc_free(tmp_ctx);
    return EOK;
}

/* parse gplink, which is in the following format:
 *  [<GPO DN_1>;<GPLinkOptions_1>][<GPO DN_2>;<GPLinkOptions_2>]...[<GPODN_n>;<GPLinkOptions_n>]
 */

/*
static errno_t parse_gplink(TALLOC_CTX *mem_ctx, char *gplink, struct GP_LINK *gp_link )
{
return 0;

}

*/

static void ad_gpo_connect_done(struct tevent_req *subreq);
static void ad_gpo_dn_retrieval_done(struct tevent_req *subreq);
static errno_t ad_gpo_get_som_attrs_step(struct tevent_req *subreq, char *som_dn);
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
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;
    errno_t ret;

    DEBUG(1, ("YKE\n"));

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
    state->sh = NULL;
    state->opts = state->ctx->sdap_access_ctx->id_ctx->opts;

    state->sdap_op = sdap_id_op_create(state, state->conn->conn_cache);

    if (!state->sdap_op) {
        DEBUG(2, ("sdap_id_op_create failed\n"));
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
    char *ad_hostname;
    char *sam_account_name;
    int dp_error;
    errno_t ret;


    DEBUG(1, ("YKE!!!\n"));

    const char *attrs[] = {AD_AT_DN, NULL};

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);

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

    ad_hostname = dp_opt_get_string(state->ctx->ad_options, AD_HOSTNAME);
    if (!ad_hostname) {
      /* Should be impossible, this is set in ad_get_common_options() */
      DEBUG(1, ("no ad_hostname\n"));
      tevent_req_error(req, EINVAL);
      return;
    }

    sam_account_name = talloc_asprintf(state, "%s$", ad_hostname);
    if (sam_account_name == NULL) {
        DEBUG(1, ("talloc_asprintf() failed\n"));
	tevent_req_error(req, ENOMEM);
	return;
    }
    DEBUG(1, ("sam_account_name is %s\n", sam_account_name));

    /* Convert the domain name into domain DN */
    ret = domain_to_basedn(state, state->domain->name, &state->basedn);
    if (ret != EOK) {
      DEBUG(SSSDBG_OP_FAILURE,
            ("Cannot convert domain name [%s] to base DN [%d]: %s\n",
	     state->domain->name, ret, strerror(ret)));
      tevent_req_error(req, ret);
      return;
    }

    /* "computer" objectclass inherits from "user" objectclass */
    filter = talloc_asprintf(state, "(&(objectclass=user)(sAMAccountName=%s))", sam_account_name);
    if (filter == NULL) {
        ret = ENOMEM;
        tevent_req_error(req, ret);
        return;
    }

    int timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);
    state->sh = sdap_id_op_handle(state->sdap_op);

    DEBUG(1, ("basedn: %s\n", state->basedn));
    DEBUG(1, ("filter: %s\n", filter));

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
				   state->basedn, LDAP_SCOPE_SUBTREE,
				   filter, attrs, NULL, 0,
                                   timeout,
				   false);

    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, ad_gpo_dn_retrieval_done, req);

    return;
}

static void
ad_gpo_dn_retrieval_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret;
    /*int dp_error;*/
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    /*char* filter;*/
    int som_count = 0;

    DEBUG(1, ("YKE!\n"));

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(1, ("Unable to get policy target's DN\n"));
	ret = ENOENT;
	goto done;
    }

    DEBUG(1, ("num_results: %zu\n", num_results));

    if (num_results < 1) {
      DEBUG(1, ("No DN retrieved for policy target.\n"));
      ret = ENOENT;
      goto done;
    } 
    else if (results == NULL) {
      DEBUG(1, ("num_results > 0, but results is NULL\n"));
      ret = ERR_INTERNAL;
      goto done;
    } 
    else if (num_results > 1) {
        DEBUG(1, ("Received multiple replies\n"));
        ret = ERR_INTERNAL;
        goto done;      
    }

    /* if we reach here, we got exactly one result */    

    ret = sysdb_attrs_get_el(results[0], AD_AT_DN, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el() failed\n"));
	goto done;
    }

    if (el->num_values == 0) {
        DEBUG(1, ("DN has no value\n"));
        ret = ENOENT;
	goto done;
    }  else if (el->num_values > 1) {
        DEBUG(1, ("More than one DN value found?\n"));
        ret = EIO;
        goto done;
    }

    /* parse potentially multiple results */
    char *computer_dn = (char *)el[0].values[0].data;
    DEBUG(1, ("computer_dn is %s\n", computer_dn));

    ret = ad_gpo_parse_dn(state, computer_dn, state->basedn, &state->som_list, &som_count);
    if (ret != EOK) {
      DEBUG(1, ("Unable to retrieve SOM List [%d]: %s\n", ret, strerror(ret)));
        ret = ENOENT;
        goto done;
    }

    for (int i = 0; i<som_count; i++){
      DEBUG(1, ("som_list[%d]: %s\n", i, state->som_list[i]));
    }

    ret = ad_gpo_get_som_attrs_step(req, state->som_list[state->som_index]);
    DEBUG(1, ("returned from step, ret is %d\n", ret));
    if (ret == EOK) {
      return;
    }

 done:

    tevent_req_error(req, ret);
    return;
}

static errno_t
ad_gpo_get_som_attrs_step(struct tevent_req *req, char *som_dn)
{

    const char *attrs[] = {AD_AT_GPLINK, NULL};
    struct tevent_req *subreq;
    struct ad_gpo_access_state *state;

    DEBUG(1, ("YKE\n"));

    state = tevent_req_data(req, struct ad_gpo_access_state);

    DEBUG(1, ("som_dn: %s\n", som_dn));

    int timeout = dp_opt_get_int(state->opts->basic, SDAP_SEARCH_TIMEOUT);

    subreq = sdap_get_generic_send(state, state->ev, state->opts, state->sh,
				   som_dn, LDAP_SCOPE_BASE,
				   "(objectclass=*)", attrs, NULL, 0,
                                   timeout,
				   false);

    if (subreq == NULL) {
        DEBUG(1, ("Could not start LDAP communication\n"));
	return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_gpo_som_done, req);
    return EOK;
}

static void
ad_gpo_som_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct ad_gpo_access_state *state;
    int ret, dp_error;
    size_t num_results;
    struct sysdb_attrs **results;
    struct ldb_message_element *el = NULL;
    uint8_t *gplink;
    size_t length;
    /*    struct GP_LINK *gp_link;*/

    DEBUG(1, ("YKE\n"));
    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_gpo_access_state);
    ret = sdap_get_generic_recv(subreq, state,
                                &num_results, &results);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->sdap_op, ret, &dp_error);

    if (ret != EOK) {
        DEBUG(1, ("ret != EOK\n"));
        if (dp_error == DP_ERR_OK) {
	  DEBUG(1, ("dp_error is DP_ERR_OK"));
            /* retry */
        } else if (dp_error == DP_ERR_OFFLINE) {
	  DEBUG(1, ("dp_error is DP_ERR_OFFLINE"));
	  /* ret = ad_gpo_access_decide_offline(req); */
        } else {
            DEBUG(1, ("sdap_get_generic_send() returned error [%d][%s]\n",
                      ret, strerror(ret)));
        }

        goto done;
    }


    /* we could get zero, one, or multiple results */
    if (num_results < 1) {
      DEBUG(1, ("no gplinks found. Denying access.\n"));
      ret = ERR_INTERNAL;
      goto done;
    }
    else if (results == NULL) {
        DEBUG(1, ("num_results > 0, but results is NULL\n"));
        ret = ERR_INTERNAL;
        goto done;
    }


    DEBUG(1, ("gplinks found!\n"));
    DEBUG(1, ("num_results: %zu\n", num_results));

    ret = sysdb_attrs_get_el(results[0], AD_AT_GPLINK, &el);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }

    if (el->num_values == 0) {
        DEBUG(1, ("gplink has no value\n"));
        ret = ENOENT;
        goto done;
    } 

    /* parse potentially multiple results */

    gplink = el[0].values[0].data;
    length = el[0].values[0].length;

    DEBUG(1, ("gplink is %s\n", gplink));
    DEBUG(1, ("length is %zu\n", length));

    if (ret != EOK) {
        DEBUG(1, ("sysdb_attrs_get_el() failed\n"));
        goto done;
    }

    /*    ret = parse_gplink(state, gplink, gp_link );*/

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
    DEBUG(1, ("YKE\n"));
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}




