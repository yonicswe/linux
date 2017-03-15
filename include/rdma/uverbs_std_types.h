/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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

#ifndef _UVERBS_STD_TYPES__
#define _UVERBS_STD_TYPES__

#include <rdma/uverbs_types.h>
#include <rdma/rdma_user_ioctl_cmd.h>
#define UVERBS_UDATA_DRIVER_DATA_GROUP	1
#define UVERBS_UDATA_DRIVER_DATA_FLAG	BIT(UVERBS_ID_RESERVED_SHIFT)

enum {
	UVERBS_UHW_IN,
	UVERBS_UHW_OUT,
	UVERBS_UHW_NUM
};


extern const struct uverbs_action_group uverbs_actions_mr;
extern const struct uverbs_action_group uverbs_actions_comp_channel;
extern const struct uverbs_action_group uverbs_actions_cq;
extern const struct uverbs_action_group uverbs_actions_qp;
extern const struct uverbs_action_group uverbs_actions_pd;
extern const struct uverbs_action_group uverbs_actions_device;

extern const struct uverbs_type uverbs_type_comp_channel;
extern const struct uverbs_type uverbs_type_cq;
extern const struct uverbs_type uverbs_type_qp;
extern const struct uverbs_type uverbs_type_rwq_ind_table;
extern const struct uverbs_type uverbs_type_wq;
extern const struct uverbs_type uverbs_type_srq;
extern const struct uverbs_type uverbs_type_ah;
extern const struct uverbs_type uverbs_type_flow;
extern const struct uverbs_type uverbs_type_mr;
extern const struct uverbs_type uverbs_type_mw;
extern const struct uverbs_type uverbs_type_pd;
extern const struct uverbs_type uverbs_type_xrcd;
extern const struct uverbs_type uverbs_type_device;
extern const struct uverbs_type_group uverbs_common_types;

static inline struct ib_uobject *__uobj_get(const struct uverbs_obj_type *type,
					    bool write,
					    struct ib_ucontext *ucontext,
					    int id)
{
	return rdma_lookup_get_uobject(type, ucontext, id, write);
}

#define uobj_get_type(_type) uverbs_type_##_type.type_attrs

#define uobj_get_read(_type, _id, _ucontext)				\
	 __uobj_get(_type, false, _ucontext, _id)

#define uobj_get_obj_read(_type, _id, _ucontext)			\
({									\
	struct ib_uobject *uobj =					\
		__uobj_get(uverbs_type_##_type.type_attrs,		\
			   false, _ucontext, _id);			\
									\
	(struct ib_##_type *)(IS_ERR(uobj) ? NULL : uobj->object);	\
})

#define uobj_get_write(_type, _id, _ucontext)				\
	 __uobj_get(_type, true, _ucontext, _id)

static inline void uobj_put_read(struct ib_uobject *uobj)
{
	rdma_lookup_put_uobject(uobj, false);
}

#define uobj_put_obj_read(_obj)					\
	uobj_put_read((_obj)->uobject)

static inline void uobj_put_write(struct ib_uobject *uobj)
{
	rdma_lookup_put_uobject(uobj, true);
}

static inline int __must_check uobj_remove_commit(struct ib_uobject *uobj)
{
	return rdma_remove_commit_uobject(uobj);
}

static inline void uobj_alloc_commit(struct ib_uobject *uobj)
{
	rdma_alloc_commit_uobject(uobj);
}

static inline void uobj_alloc_abort(struct ib_uobject *uobj)
{
	rdma_alloc_abort_uobject(uobj);
}

static inline struct ib_uobject *__uobj_alloc(const struct uverbs_obj_type *type,
					      struct ib_ucontext *ucontext)
{
	return rdma_alloc_begin_uobject(type, ucontext);
}

#define uobj_alloc(_type, ucontext)	\
	__uobj_alloc(_type, ucontext)

#endif

