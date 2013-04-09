/*
    SSSD

    sdap_dyndns.c: LDAP specific dynamic DNS update

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

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

#include "util/util.h"
#include "resolv/async_resolv.h"
#include "providers/dp_backend.h"
#include "providers/dp_dyndns.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/ldap/ldap_common.h"

static struct tevent_req *
sdap_dyndns_get_addrs_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *sdap_ctx,
                           const char *iface);
static errno_t
sdap_dyndns_get_addrs_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct sss_iface_addr **_addresses);

struct sdap_dyndns_update_state {
    struct tevent_context *ev;
    struct be_resolv_ctx *be_res;

    const char *hostname;
    const char *dns_zone;
    const char *realm;
    const char *servername;
    int ttl;

    struct sss_iface_addr *addresses;
    uint8_t remove_af;

    bool check_diff;
    bool use_server_with_nsupdate;
    char *update_msg;
};

static void sdap_dyndns_update_addrs_done(struct tevent_req *subreq);
static void sdap_dyndns_addrs_check_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_update_step(struct tevent_req *req);
static void sdap_dyndns_update_done(struct tevent_req *subreq);

struct tevent_req *
sdap_dyndns_update_send(TALLOC_CTX *mem_ctx,
                        struct tevent_context *ev,
                        struct be_ctx *be_ctx,
                        struct sdap_id_ctx *sdap_ctx,
                        const char *ifname,
                        const char *hostname,
                        const char *dns_zone,
                        const char *realm,
                        const char *servername,
                        const int ttl,
                        bool check_diff)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_create(mem_ctx, &state, struct sdap_dyndns_update_state);
    if (req == NULL) {
        return NULL;
    }
    state->check_diff = check_diff;
    state->hostname = hostname;
    state->dns_zone = dns_zone;
    state->realm = realm;
    state->servername = servername;
    state->use_server_with_nsupdate = false;
    state->ttl = ttl;
    state->be_res = be_ctx->be_res;
    state->ev = ev;

    if (ifname) {
       /* Unless one family is restricted, just replace all
        * address families during the update
        */
        switch (state->be_res->family_order) {
        case IPV4_ONLY:
            state->remove_af |= DYNDNS_REMOVE_A;
            break;
        case IPV6_ONLY:
            state->remove_af |= DYNDNS_REMOVE_AAAA;
            break;
        case IPV4_FIRST:
        case IPV6_FIRST:
            state->remove_af |= (DYNDNS_REMOVE_A |
                                 DYNDNS_REMOVE_AAAA);
            break;
        }
    } else {
        /* If the interface isn't specified, we ONLY want to have the address
         * that's connected to the LDAP server stored, so we need to check
         * (and later remove) both address families.
         */
        state->remove_af = (DYNDNS_REMOVE_A | DYNDNS_REMOVE_AAAA);
    }

    subreq = sdap_dyndns_get_addrs_send(state, state->ev, sdap_ctx, ifname);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret)));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_dyndns_update_addrs_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }
    return req;
}

static void
sdap_dyndns_update_addrs_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = sdap_dyndns_get_addrs_recv(subreq, state, &state->addresses);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Can't get addresses for DNS update\n"));
        tevent_req_error(req, ret);
        return;
    }

    if (state->check_diff) {
        /* Check if we need the update at all */
        subreq = nsupdate_get_addrs_send(state, state->ev,
                                         state->be_res, state->hostname);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Can't initiate address check\n"));
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, sdap_dyndns_addrs_check_done, req);
        return;
    }

    /* Perform update */
    ret = sdap_dyndns_update_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }
    /* Execution will resume in sdap_dyndns_update_done */
}

static void
sdap_dyndns_addrs_check_done(struct tevent_req *subreq)
{
    errno_t ret;
    int i;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;
    char **str_dnslist = NULL, **str_local_list = NULL;
    char **dns_only = NULL, **local_only = NULL;
    bool do_update;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = nsupdate_get_addrs_recv(subreq, state, &str_dnslist);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not receive list of current addresses [%d]: %s\n",
              ret, sss_strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    ret = sss_iface_addr_list_as_str_list(state,
                                          state->addresses, &str_local_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
               ("Converting DNS IP addresses to strings failed: [%d]: %s\n",
               ret, sss_strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    /* Compare the lists */
    ret = diff_string_lists(state, str_dnslist, str_local_list,
                            &dns_only, &local_only, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("diff_string_lists failed: [%d]: %s\n", ret, sss_strerror(ret)));
        tevent_req_error(req, ret);
        return;
    }

    if (dns_only) {
        for (i=0; dns_only[i]; i++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  ("Address in DNS only: %s\n", dns_only[i]));
            do_update = true;
        }
    }

    if (local_only) {
        for (i=0; local_only[i]; i++) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  ("Address on localhost only: %s\n", local_only[i]));
            do_update = true;
        }
    }

    if (do_update) {
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Detected IP addresses change, will perform an update\n"));
        ret = sdap_dyndns_update_step(req);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("Could not start the update [%d]: %s\n",
                  ret, sss_strerror(ret)));
            tevent_req_error(req, ret);
        }
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          ("No DNS update needed, addresses did not change\n"));
    tevent_req_done(req);
    return;
}

static errno_t
sdap_dyndns_update_step(struct tevent_req *req)
{
    errno_t ret;
    struct sdap_dyndns_update_state *state;
    const char *servername;
    struct tevent_req *subreq;

    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    servername = NULL;
    if (state->use_server_with_nsupdate == true &&
        state->servername) {
        servername = state->servername;
    }

    ret = be_nsupdate_create_msg(state, state->realm, state->dns_zone,
                                 servername, state->hostname,
                                 state->ttl, state->remove_af,
                                 state->addresses,
                                 &state->update_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Can't get addresses for DNS update\n"));
        return ret;
    }

    /* Fork a child process to perform the DNS update */
    subreq = be_nsupdate_send(state, state->ev, state->update_msg);
    if (subreq == NULL) {
        return EIO;
    }

    tevent_req_set_callback(subreq, sdap_dyndns_update_done, req);
    return EOK;
}

static void
sdap_dyndns_update_done(struct tevent_req *subreq)
{
    errno_t ret;
    int child_status;
    struct tevent_req *req;
    struct sdap_dyndns_update_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_update_state);

    ret = be_nsupdate_recv(subreq, &child_status);
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* If the update didn't succeed, we can retry using the server name */
        if (state->use_server_with_nsupdate == false && state->servername &&
            WIFEXITED(child_status) && WEXITSTATUS(child_status) != 0) {
            state->use_server_with_nsupdate = true;
            DEBUG(SSSDBG_MINOR_FAILURE,
                   ("nsupdate failed, retrying with server name\n"));
            ret = sdap_dyndns_update_step(req);
            if (ret == EOK) {
                return;
            }
        }

        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
sdap_dyndns_update_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* A request to get addresses to update with */
struct sdap_dyndns_get_addrs_state {
    struct sdap_id_op* sdap_op;
    struct sss_iface_addr *addresses;
};

static void sdap_dyndns_get_addrs_done(struct tevent_req *subreq);
static errno_t sdap_dyndns_add_ldap_conn(struct sdap_dyndns_get_addrs_state *state,
                                         struct sdap_handle *sh);

static struct tevent_req *
sdap_dyndns_get_addrs_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_id_ctx *sdap_ctx,
                           const char *iface)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct sdap_dyndns_get_addrs_state *state;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_dyndns_get_addrs_state);
    if (req == NULL) {
        return NULL;
    }

    if (iface) {
        ret = sss_iface_addr_list_get(state, iface, &state->addresses);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Cannot get list of addresses from interface %s\n", iface));
        }
        /* We're done. Just fake an async request completion */
        goto done;
    }

    /* Detect DYNDNS address from LDAP connection */
    state->sdap_op = sdap_id_op_create(state, sdap_ctx->conn_cache);
    if (!state->sdap_op) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
        goto done;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret)));
        goto done;
    }
    tevent_req_set_callback(subreq, sdap_dyndns_get_addrs_done, req);

    ret = EAGAIN;
done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    /* EAGAIN - resolution in progress */
    return req;
}

static void
sdap_dyndns_get_addrs_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    struct tevent_req *req;
    struct sdap_dyndns_get_addrs_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_dyndns_get_addrs_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("No LDAP server is available, "
                  "dynamic DNS update is skipped in offline mode.\n"));
            ret = ERR_DYNDNS_OFFLINE;
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  ("Failed to connect to LDAP server: [%d](%s)\n",
                  ret, sss_strerror(ret)));
        }
        tevent_req_error(req, ret);
        return;
    }

    ret = sdap_dyndns_add_ldap_conn(state, sdap_id_op_handle(state->sdap_op));
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Can't get addresses from LDAP connection\n"));
        tevent_req_error(req, ret);
        return;
    }

    /* Got the address! Done! */
    tevent_req_done(req);
}

static errno_t
sdap_dyndns_add_ldap_conn(struct sdap_dyndns_get_addrs_state *state,
                          struct sdap_handle *sh)
{
    int ret;
    int fd;
    struct sss_iface_addr *address;
    struct sockaddr_storage ss;
    socklen_t ss_len = sizeof(ss);

    if (sh == NULL) {
        return EINVAL;
    }

    /* Get the file descriptor for the primary LDAP connection */
    ret = get_fd_from_ldap(sh->ldap, &fd);
    if (ret != EOK) {
        return ret;
    }

    errno = 0;
    ret = getsockname(fd, (struct sockaddr *) &ss, &ss_len);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to get socket name\n"));
        return ret;
    }

    switch(ss.ss_family) {
    case AF_INET:
    case AF_INET6:
        address = sss_iface_addr_add(state, &state->addresses, &ss);
        if (address == NULL) {
            return ENOMEM;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Connection to LDAP is neither IPv4 nor IPv6\n"));
        return EIO;
    }

    return EOK;
}

static errno_t
sdap_dyndns_get_addrs_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           struct sss_iface_addr **_addresses)
{
    struct sdap_dyndns_get_addrs_state *state;

    state = tevent_req_data(req, struct sdap_dyndns_get_addrs_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_addresses = talloc_steal(mem_ctx, state->addresses);
    return EOK;
}