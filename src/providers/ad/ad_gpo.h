/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef AD_GPO_H_
#define AD_GPO_H_

struct tevent_req *
ad_gpo_access_send(TALLOC_CTX *mem_ctx,
		   struct tevent_context *ev,
		   struct be_ctx *be_ctx,
		   struct sss_domain_info *domain,
		   struct ad_access_ctx *ctx,
		   struct pam_data *pd);

errno_t ad_gpo_access_recv(struct tevent_req *req);


/* following types are copied from git/samba/libgpo/gpo.h */
enum GPO_LINK_TYPE {
	GP_LINK_UNKOWN	= 0,
	GP_LINK_MACHINE	= 1,
	GP_LINK_SITE	= 2,
	GP_LINK_DOMAIN	= 3,
	GP_LINK_OU	= 4,
	GP_LINK_LOCAL	= 5 /* for convenience */
};

struct GROUP_POLICY_OBJECT {
	uint32_t options;	/* GPFLAGS_* */
	uint32_t version;
	const char *ds_path;
	const char *file_sys_path;
	const char *display_name;
	const char *name;
	const char *link;
	enum GPO_LINK_TYPE link_type;
	const char *user_extensions;
	const char *machine_extensions;
  /*struct security_descriptor *security_descriptor;*/
	struct GROUP_POLICY_OBJECT *next, *prev;
};

struct GP_LINK {
	const char *gp_link;	/* raw link name */
	uint32_t gp_opts;	/* inheritance options GPO_INHERIT */
	uint32_t num_links;	/* number of links */
	char **link_names;	/* array of parsed link names */
	uint32_t *link_opts;	/* array of parsed link opts GPO_LINK_OPT_* */
};

struct GP_EXT {
	const char *gp_extension;	/* raw extension name */
	uint32_t num_exts;
	char **extensions;
	char **extensions_guid;
	char **snapins;
	char **snapins_guid;
	struct GP_EXT *next, *prev;
};

#endif /* AD_GPO_H_ */
