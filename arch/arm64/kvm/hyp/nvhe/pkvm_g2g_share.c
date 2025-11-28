// SPDX-License-Identifier: GPL-2.0-only

#include <linux/kvm_host.h>
#include <nvhe/pkvm.h>
#include <kvm/arm_hypercalls.h>
#include <nvhe/mem_protect.h>

#include <nvhe/memory.h>
#include <nvhe/hyp_print.h>

extern phys_addr_t g2g_share_base;
extern phys_addr_t g2g_share_size;
extern struct host_mmu host_mmu;

#define PAGE_ALIGNED(addr) IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
#define MAX_GUEST_SHARE_COUNT 256
/*
extern DEFINE_PER_CPU(struct pkvm_hyp_vm *, __current_vm);
#define current_vm (*this_cpu_ptr(&__current_vm))
*/
/* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */


/* pkvm "standard" functions from nvhe/pkvm.c */
unsigned int vm_handle_to_idx(pkvm_handle_t handle);
pkvm_handle_t idx_to_vm_handle(unsigned int idx);
struct pkvm_hyp_vm *get_vm_by_handle(pkvm_handle_t handle);
int pkvm_handle_empty_memcache(struct pkvm_hyp_vcpu *hyp_vcpu,
				      u64 *exit_code);

void guest_lock_component(struct pkvm_hyp_vm *vm);
void guest_unlock_component(struct pkvm_hyp_vm *vm);


enum share_mode {NONE, INITIATOR, COMPLETER};
enum g2g_share_status {EMPTY = 0, INITIATED, COMPLETED, INIT_UNSHARED, COMP_UNSHARED};

struct g2g_share {
	pkvm_handle_t initiator_handle;
	pkvm_handle_t completer_handle;
	unsigned long initiator_ipa;
	unsigned long completer_ipa;
	u32	page_nr;
	enum g2g_share_status status;
};

struct g2g_pool {
	/*The size of the struct g2g_share array depends on how many pages from
	 * the host are reserved for guest to guest sharing. Each page needs one
	 * g2g_share structure.
	 */
	struct g2g_share (*shares)[];
	/* number of pages reserved for sharing */
	u32 nr_pages;
	/* memory allocated for g2g sharing. guests' IPA addresses are s2-mapped
	* here.
	* Please note that the actual number of pages to be shared will be
	* slightly less than the number allocated by the host.
	*/
	void  *shared_mem;
};

static struct g2g_pool g2g_pool;
/*
static void guest_lock_component(struct pkvm_hyp_vm *vm)
{
	hyp_spin_lock(&vm->pgtable_lock);
	current_vm = vm;
}

static void guest_unlock_component(struct pkvm_hyp_vm *vm)
{
	current_vm = NULL;
	hyp_spin_unlock(&vm->pgtable_lock);
}

static void host_lock_component(void)
{
	hyp_spin_lock(&host_mmu.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_mmu.lock);
}
*/
//extern int dbg_ret;

int pkvm_init_g2g_pool(void)
{
	int hdr_pages;
	void *base = hyp_phys_to_virt(g2g_share_base);
	int total_pages = g2g_share_size / PAGE_SIZE;

	if (!PAGE_ALIGNED(g2g_share_base) || !PAGE_ALIGNED(g2g_share_size))
		return -EINVAL;

	hdr_pages = DIV_ROUND_UP(sizeof(struct g2g_share) * total_pages +
				 sizeof(u32), PAGE_SIZE);
	hyp_print("sharepool %d s:%x\n", total_pages, g2g_share_size);

	if (hdr_pages >= total_pages)
		return -EINVAL;

	memset((void *) base, 0, g2g_share_size);
	g2g_pool.shares = (struct g2g_share(*)[]) base;
	g2g_pool.nr_pages = total_pages - hdr_pages;
	g2g_pool.shared_mem = (void *) base + hdr_pages * PAGE_SIZE;

	hyp_print("mem pages %d\n",g2g_pool.nr_pages);
	hyp_print("share: %llx mem %llx\n",g2g_pool.shares, g2g_pool.shared_mem);
	return 0;
}

static phys_addr_t get_share_phys(int id)
{
	return hyp_virt_to_phys(g2g_pool.shared_mem + PAGE_SIZE * id);
}

int get_new_share(void)
{
	int i;
	struct g2g_share *share;

	if (!g2g_pool.shares)
		return -EINVAL;

	for (i = 0; i < g2g_pool.nr_pages; i++) {
		share = &(*g2g_pool.shares)[i];
		if (share->status == EMPTY) {
//			hyp_print("get_new %d\n",i);
			return i;
		}
	}
	return -EINVAL;
}
//int dbg = 0;

enum share_mode get_g2g_mode(struct g2g_share *share,
		    pkvm_handle_t handle, pkvm_handle_t partner, u64 ipa)
{
	if (share->status == EMPTY)
		return NONE;
//	if ((dbg) && (handle == 0x1000) )
//		hyp_print("get_mode status %x:%x ipa %llx, %x\n", handle, partner, ipa, share->status);
	if (share->initiator_handle == handle)
		if ((!ipa) || (share->initiator_ipa == ipa))
			if ((!partner) || (share->completer_handle == partner))
				if (share->status != INIT_UNSHARED) {
					return INITIATOR;
			}
	if (share->completer_handle == handle)
		if ((!ipa) || (share->completer_ipa == ipa))
			if ((!partner) || (share->initiator_handle == partner))
				if (share->status != COMP_UNSHARED)
					return COMPLETER;
	return NONE;
}

pkvm_handle_t find_next_g2g_share(struct pkvm_hyp_vm *hyp_vm, pkvm_handle_t partner)
{
	struct g2g_share *share;
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	int idx;
	int share_id;
	int start;

	if  (partner == 0)
		start = 0;
	else
		start = vm_handle_to_idx(partner) + 1;
	/* search the shared table for existing VMIDs with which we have a share
	 *
	 */
	for (idx = start; idx < KVM_MAX_PVMS; idx++) {
		if (idx_to_vm_handle(idx) == handle)
			continue;
		for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
			share = &(*g2g_pool.shares)[share_id];
			if (get_g2g_mode(share, handle, idx_to_vm_handle(idx), 0) != NONE) {
				//&&
				//((share->status == INITIATED) || (share->status == COMPLETED))) {
				//hyp_print("next %d %x\n",idx,get_g2g_mode(share, handle, idx_to_vm_handle(idx), 0));
				return idx_to_vm_handle(idx);
			}
		}
	}

	return 0;
}

static int do_g2g_map(struct pkvm_hyp_vcpu *vcpu, u64 ipa, phys_addr_t phys)
{
	struct kvm_hyp_memcache *mc = &vcpu->vcpu.arch.stage2_mc;
	struct pkvm_hyp_vm *vm = pkvm_hyp_vcpu_to_hyp_vm(vcpu);
	enum kvm_pgtable_prot prot;
	int ret;
	guest_lock_component(vm);

	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RW, PKVM_PAGE_SHARED_BORROWED);
	ret = kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys, prot, mc, 0);
	if (ret) {
		hyp_print("kvm_pgtable_stage2_map ret %x (%d)\n",ret,ret);
	}
	guest_unlock_component(vm);
	return  ret;
}

bool pkvm_g2g_share(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	struct pkvm_hyp_vm *hyp_vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	struct g2g_share *share;
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	bool share_completed = false;
	int share_id = 0;
	int ret = SMCCC_RET_SUCCESS;
	u64 ipa = smccc_get_arg1(vcpu);
	u32 page_nr = smccc_get_arg2(vcpu) + 1;
	u64 partner = smccc_get_arg3(vcpu);

	hyp_print("guest_share ipa:%llx part: %x handle: %x page:%x\n",
		   ipa,partner,handle, page_nr);
	if (handle == partner) {
		hyp_print("cannot be shared by itself\n");
		ret = EINVAL;
		goto err;

	}
	if (!g2g_pool.shares)
		if (pkvm_init_g2g_pool()) {
			ret = -EINVAL;
			goto err;
		}

	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		 if (get_g2g_mode(share, handle, 0, ipa) != NONE) {
			hyp_print("duplicate share\n");
			ret = -EEXIST;
			goto err;
		 }
	}

	/* look for an existing share request for this guest */
	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		if (share->page_nr == page_nr) {
			switch (get_g2g_mode(share, handle, partner, 0)) {
			case INITIATOR:
				hyp_print("pkvm_g2g_share INITIATOR:state %x\n",share->status);
				if ((share->status == INITIATED) ||
				    (share->status == COMPLETED) ||
				    (share->status == COMP_UNSHARED)) {
					hyp_print("duplicate share\n");
					ret = -EEXIST;
					goto err;
				}
				break;

			case COMPLETER:
				hyp_print("pkvm_g2g_share COMPLETE:state %x\n",share->status);
				if (share->status != INITIATED) {
					hyp_print("duplicate share\n");
					ret = -EEXIST;
					goto err;
				}
				ret = do_g2g_map(hyp_vcpu, ipa, get_share_phys(share_id));
				if (!ret) {
					share->completer_ipa = ipa;
					share->status = COMPLETED;
					share_completed = true;
				}
				/* share complete */
				goto out;
				break;
			case NONE:
				continue;
			}
		}
	}

	/* No share request for this quest found, create it */
	share_id = get_new_share();
	if (share_id < 0) {
		hyp_print("get_new_share() failed\n");
		ret = -ENOMEM;
		goto err;
	}

	ret = do_g2g_map(hyp_vcpu, ipa, get_share_phys(share_id));
	if (!ret) {
		share = &(*g2g_pool.shares)[share_id];
		share->completer_handle = partner;
		share->page_nr = page_nr;
		share->initiator_handle = handle;
		share->initiator_ipa = ipa;
		share->status = INITIATED;
	}

out:
	if (ret == -ENOMEM) {
		/* do_g2g_map() tried to allocate memory for new page table
		 * without success.
		 */
		hyp_print("ENOMEM: handle_empty_memcache\n");
		if (!pkvm_handle_empty_memcache(hyp_vcpu, exit_code)) {
			/* handle memcache request on the host */
			return false;
		}
		hyp_print("pkvm_handle_empty_memcache() failed\n");
		ret = -EINVAL;
	}
err:
	smccc_set_retval(vcpu, ret, share_completed, 0, 0);

	return true;

}

bool pkvm_g2g_share_query(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{
	struct pkvm_hyp_vm *hyp_vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	pkvm_handle_t partner = smccc_get_arg1(vcpu);
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	struct g2g_share *share;
	int share_id = 0;
	enum share_mode mode;
	u32 free = 0;
	u32 waiting = 0;
	u32 completed = 0;
	u32 incoming_req = 0;
	u32 unsharing = 0;
	u64 stat1;
	u64 stat2;
	u64 stat3;
	int ret;

	hyp_print("pkvm_guest_to_guest_query h:%x p:%x\n",handle, partner);
	if (!g2g_pool.shares)
		if (pkvm_init_g2g_pool()) {
			ret = -EINVAL;
			goto err;
		}

	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		//hyp_print("share %p\n",share);
		if (share->status == EMPTY)
			free++;
		mode = get_g2g_mode(share, handle, partner, 0);
	//	if (share_id < 8)
	//		hyp_print("pkvm_guest status %d %x %x\n",share_id, share->status,mode);
		if (mode == NONE)
			continue;
	//	hyp_print("pkvm_guest2 status %d %x %x\n",share_id, share->status,mode);
		switch (share->status) {
		case COMPLETED:
			completed++;
			break;
		case INITIATED:
	//		hyp_print("initiated %x\n",mode);
			if (mode == INITIATOR)
				waiting++;
			if (mode == COMPLETER)
				incoming_req++;
			break;
		case INIT_UNSHARED:
			hyp_print("INIT_UNSHARED %x \n",mode);

			if (mode == COMPLETER)
				unsharing++;
			break;
		case COMP_UNSHARED:
			hyp_print("COMP_UNSHARED %x \n",mode);
			if (mode == INITIATOR)
				unsharing++;
			break;
		default:
		}
	}
	hyp_print("Free %d\n", free);
err:
	partner = find_next_g2g_share(hyp_vm, partner);
	stat1 = (u64) incoming_req << 32 | (waiting & 0xffffffffUL);
	stat2 = (u64) completed << 32 | (unsharing & 0xffffffffUL);
	stat3 = (u64) (partner & 0xffffUL) << 48  |
		      (handle & 0xffffUL) << 32 |
		      (free & ((1UL << 32) - 1));
	smccc_set_retval(vcpu, ret, stat1, stat2, stat3);

	return true;
}


int do_pkvm_g2g_unmap(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;

	hyp_print("do_pkvm_g2g_unshare\n");
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_unmap(&vm->pgt, ipa, 4096);
	guest_unlock_component(vm);

	return ret;
}

static int __pkvm_g2g_unshare(struct pkvm_hyp_vm *hyp_vm, pkvm_handle_t handle,
			      pkvm_handle_t partner, u64 ipa, u32 *unmapped)
{
	struct g2g_share *share;
	u64 unmap_ipa = 0;
	int share_id;
	u64 phys;
	int ret = 0;

	hyp_print("pkvm_g2g_unshare i:%x c: %x ipa: %llx\n", handle, partner, ipa);
	if (!g2g_pool.shares) {
		/* Nothing to unshare */
		ret = -EINVAL;
		goto err;
	}

	if (unmapped)
		*unmapped = 0;

	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		switch (get_g2g_mode(share, handle, 0, ipa)) {
		case INITIATOR:
			hyp_print("unshare: found initiator %x %x\n",share->completer_handle, share->status);
			unmap_ipa = share->initiator_ipa;
			share->initiator_ipa = 0;
			if ((share->status == INITIATED) ||
			    (share->status == COMP_UNSHARED))
				share->status = EMPTY;
			else
				share->status = INIT_UNSHARED;
			break;

		case COMPLETER:
			hyp_print("unshare: found completer %x %x\n",share->initiator_handle, share->status);
			unmap_ipa = share->completer_ipa;
			share->completer_ipa = 0;
			if (share->status == INIT_UNSHARED)
				share->status = EMPTY;
			else
				share->status = COMP_UNSHARED;
			break;
		case NONE:
			continue;
		}
		if (unmap_ipa) {
			if (share->status == EMPTY) {
				/* both guests have unmapped this */
				phys = get_share_phys(share_id);
				memset(hyp_phys_to_virt(phys), 0, PAGE_SIZE);
			}
			hyp_print("unmap ipa %lx %x\n", unmap_ipa, handle);
			ret = do_pkvm_g2g_unmap(hyp_vm, unmap_ipa);
			/* What we can do if unmap fails */
			if (unmapped)
				(*unmapped)++;
			if (ipa) {
				/* if an IPA address is given, only that address
				 * will be unmapped, otherwise all addresses
				 * shared by the guest will be unmapped
				 */
				break;
			}

			unmap_ipa = 0;
		}
	}
err:
	return ret;
}

bool pkvm_g2g_unshare(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{

	struct pkvm_hyp_vm *hyp_vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	u64 ipa = smccc_get_arg1(vcpu);
	pkvm_handle_t partner = smccc_get_arg2(vcpu);
	u32 unmapped = 0;
	int ret;


	ret = __pkvm_g2g_unshare(hyp_vm, handle, partner, ipa, &unmapped);

	smccc_set_retval(vcpu, ret, unmapped, 0, 0);
	hyp_print("unmapped %d\n",unmapped);
	return true;
}

void pkvm_g2g_share_teardown(pkvm_handle_t handle)
{
	struct pkvm_hyp_vm *hyp_vm = get_vm_by_handle(handle);

	__pkvm_g2g_unshare(hyp_vm, handle, 0, 0, 0);
}
