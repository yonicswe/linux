/*
 * Copyright (c) 2016, Mellanox Technologies inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _UVERBS_IOCTL_CMD_
#define _UVERBS_IOCTL_CMD_

#include <rdma/uverbs_ioctl.h>

#define IB_UVERBS_VENDOR_FLAG	0x8000

enum {
	UVERBS_UHW_IN,
	UVERBS_UHW_OUT,
};

int ib_uverbs_std_dist(__u16 *attr_id, void *priv);

/* common validators */

int uverbs_action_std_handle(struct ib_device *ib_dev,
			     struct ib_uverbs_file *ufile,
			     struct uverbs_attr_array *ctx, size_t num,
			     void *_priv);
int uverbs_action_std_ctx_handle(struct ib_device *ib_dev,
				 struct ib_uverbs_file *ufile,
				 struct uverbs_attr_array *ctx, size_t num,
				 void *_priv);

struct uverbs_action_std_handler {
	int (*handler)(struct ib_device *ib_dev, struct ib_ucontext *ucontext,
		       struct uverbs_attr_array *common,
		       struct uverbs_attr_array *vendor,
		       void *priv);
	void *priv;
};

struct uverbs_action_std_ctx_handler {
	int (*handler)(struct ib_device *ib_dev, struct ib_uverbs_file *ufile,
		       struct uverbs_attr_array *common,
		       struct uverbs_attr_array *vendor,
		       void *priv);
	void *priv;
};

void uverbs_free_ah(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_flow(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject);
void uverbs_free_mw(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_qp(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_rwq_ind_tbl(const struct uverbs_type_alloc_action *type_alloc_action,
			     struct ib_uobject *uobject);
void uverbs_free_wq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_srq(const struct uverbs_type_alloc_action *type_alloc_action,
		     struct ib_uobject *uobject);
void uverbs_free_cq(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_mr(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_xrcd(const struct uverbs_type_alloc_action *type_alloc_action,
		      struct ib_uobject *uobject);
void uverbs_free_pd(const struct uverbs_type_alloc_action *type_alloc_action,
		    struct ib_uobject *uobject);
void uverbs_free_event_file(const struct uverbs_type_alloc_action *type_alloc_action,
			    struct ib_uobject *uobject);

enum uverbs_common_types {
	UVERBS_TYPE_DEVICE, /* Don't use IDRs here */
	UVERBS_TYPE_PD,
	UVERBS_TYPE_COMP_CHANNEL,
	UVERBS_TYPE_CQ,
	UVERBS_TYPE_QP,
	UVERBS_TYPE_SRQ,
	UVERBS_TYPE_AH,
	UVERBS_TYPE_MR,
	UVERBS_TYPE_MW,
	UVERBS_TYPE_FLOW,
	UVERBS_TYPE_XRCD,
	UVERBS_TYPE_RWQ_IND_TBL,
	UVERBS_TYPE_WQ,
	UVERBS_TYPE_LAST,
};

enum uverbs_create_cq_cmd_attr {
	CREATE_CQ_HANDLE,
	CREATE_CQ_CQE,
	CREATE_CQ_USER_HANDLE,
	CREATE_CQ_COMP_CHANNEL,
	CREATE_CQ_COMP_VECTOR,
	CREATE_CQ_FLAGS,
	CREATE_CQ_RESP_CQE,
};

enum uverbs_create_comp_channel_cmd_attr {
	CREATE_COMP_CHANNEL_FD,
};

enum uverbs_get_context {
	GET_CONTEXT_RESP,
};

enum uverbs_query_device {
	QUERY_DEVICE_RESP,
	QUERY_DEVICE_ODP,
	QUERY_DEVICE_TIMESTAMP_MASK,
	QUERY_DEVICE_HCA_CORE_CLOCK,
	QUERY_DEVICE_CAP_FLAGS,
};

enum uverbs_alloc_pd {
	ALLOC_PD_HANDLE,
};

enum uverbs_reg_mr {
	REG_MR_HANDLE,
	REG_MR_PD_HANDLE,
	REG_MR_CMD,
	REG_MR_RESP
};

enum uverbs_dereg_mr {
	DEREG_MR_HANDLE,
};

extern const struct uverbs_attr_group_spec uverbs_uhw_compat_spec;
extern const struct uverbs_attr_group_spec uverbs_get_context_spec;
extern const struct uverbs_attr_group_spec uverbs_query_device_spec;
extern const struct uverbs_attr_group_spec uverbs_alloc_pd_spec;
extern const struct uverbs_attr_group_spec uverbs_reg_mr_spec;
extern const struct uverbs_attr_group_spec uverbs_dereg_mr_spec;

int uverbs_get_context(struct ib_device *ib_dev,
		       struct ib_uverbs_file *file,
		       struct uverbs_attr_array *common,
		       struct uverbs_attr_array *vendor,
		       void *priv);

int uverbs_query_device_handler(struct ib_device *ib_dev,
				struct ib_ucontext *ucontext,
				struct uverbs_attr_array *common,
				struct uverbs_attr_array *vendor,
				void *priv);

int uverbs_alloc_pd_handler(struct ib_device *ib_dev,
			    struct ib_ucontext *ucontext,
			    struct uverbs_attr_array *common,
			    struct uverbs_attr_array *vendor,
			    void *priv);

int uverbs_reg_mr_handler(struct ib_device *ib_dev,
			  struct ib_ucontext *ucontext,
			  struct uverbs_attr_array *common,
			  struct uverbs_attr_array *vendor,
			  void *priv);

int uverbs_dereg_mr_handler(struct ib_device *ib_dev,
			    struct ib_ucontext *ucontext,
			    struct uverbs_attr_array *common,
			    struct uverbs_attr_array *vendor,
			    void *priv);

int uverbs_create_comp_channel_handler(struct ib_device *ib_dev,
				       struct ib_ucontext *ucontext,
				       struct uverbs_attr_array *common,
				       struct uverbs_attr_array *vendor,
				       void *priv);

int uverbs_create_cq_handler(struct ib_device *ib_dev,
			     struct ib_ucontext *ucontext,
			     struct uverbs_attr_array *common,
			     struct uverbs_attr_array *vendor,
			     void *priv);

extern const struct uverbs_action uverbs_action_get_context;
extern const struct uverbs_action uverbs_action_create_cq;
extern const struct uverbs_action uverbs_action_create_comp_channel;
extern const struct uverbs_action uverbs_action_query_device;
extern const struct uverbs_action uverbs_action_alloc_pd;
extern const struct uverbs_action uverbs_action_reg_mr;
extern const struct uverbs_action uverbs_action_dereg_mr;

enum uverbs_actions_mr_ops {
	UVERBS_MR_REG,
	UVERBS_MR_DEREG,
};

extern const struct uverbs_type_actions_group uverbs_actions_mr;

enum uverbs_actions_comp_channel_ops {
	UVERBS_COMP_CHANNEL_CREATE,
};

extern const struct uverbs_type_actions_group uverbs_actions_comp_channel;

enum uverbs_actions_cq_ops {
	UVERBS_CQ_CREATE,
};

extern const struct uverbs_type_actions_group uverbs_actions_cq;

enum uverbs_actions_pd_ops {
	UVERBS_PD_ALLOC
};

extern const struct uverbs_type_actions_group uverbs_actions_pd;

enum uverbs_actions_device_ops {
	UVERBS_DEVICE_ALLOC_CONTEXT,
	UVERBS_DEVICE_QUERY,
};

extern const struct uverbs_type_actions_group uverbs_actions_device;

extern const struct uverbs_type uverbs_type_cq;
extern const struct uverbs_type uverbs_type_comp_channel;
extern const struct uverbs_type uverbs_type_mr;
extern const struct uverbs_type uverbs_type_pd;
extern const struct uverbs_type uverbs_type_device;

extern const struct uverbs_types uverbs_common_types;
extern const struct uverbs_types_group uverbs_types_group;
#endif

