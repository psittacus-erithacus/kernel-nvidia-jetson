#include <linux/kvm_host.h>
#include <nvhe/pkvm.h>
#include <kvm/arm_hypercalls.h>
#include <nvhe/mem_protect.h>

#include <nvhe/memory.h>
#include <nvhe/hyp_print.h>

extern phys_addr_t g2g_share_base;
extern phys_addr_t g2g_share_size;
extern struct host_mmu host_mmu;
extern DEFINE_PER_CPU(struct pkvm_hyp_vm *, __current_vm);

#define MAX_GUEST_SHARE_COUNT 256
#define current_vm (*this_cpu_ptr(&__current_vm))

unsigned int vm_handle_to_idx(pkvm_handle_t handle);
pkvm_handle_t idx_to_vm_handle(unsigned int idx);
struct pkvm_hyp_vm *get_vm_by_handle(pkvm_handle_t handle);


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
	struct g2g_share (*shares)[];
	u32 nr_pages;
	void  *shared_mem;
};

static struct g2g_pool g2g_pool;

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

/* shares table
 * header:
 * g2g_pool.shares[0] -> struct g2g_share[0]
 * g2g_pool.shares[1] -> struct g2g_share[1]
 * ...
 * g2g_pool.shares[n] -> struct g2g_share[n]
 *
 * 4k-aligmented
 * physical shared pages:
 *  g2g_pool.shared_mem points the first address of it
 * n * 4k pages
 */
int pkvm_init_g2g_pool(void)
{
	int hdr_pages;

	hyp_print("pkvm_init_g2g_pool2\n");
	void *p = hyp_phys_to_virt(g2g_share_base);
	int total_pages = g2g_share_size / 4096;

	hdr_pages = DIV_ROUND_UP(sizeof(struct g2g_share) * total_pages +
				 sizeof(u32), PAGE_SIZE);
	hyp_print("sharepool %d\n", total_pages);

	if (hdr_pages >= total_pages)
		return -EINVAL;

	memset((void *) p, 0, g2g_share_size);
	g2g_pool.shares = (struct g2g_share(*)[]) p;
	g2g_pool.nr_pages = total_pages - hdr_pages;
	g2g_pool.shared_mem = (void *) p + hdr_pages * PAGE_SIZE;

	hyp_print("mem pages %d\n",g2g_pool.nr_pages);
	hyp_print("share: %llx mem %llx\n",g2g_pool.shares, g2g_pool.shared_mem);
	return 0;
}

static phys_addr_t get_share_phys(int id) {
	return hyp_virt_to_phys(g2g_pool.shared_mem + PAGE_SIZE * id);
}

int get_new_share(void)
{
	int i;
	struct g2g_share *share;

	if (!g2g_pool.shares)
		pkvm_init_g2g_pool();
	for (i = 0; i < g2g_pool.nr_pages; i++) {
		share = &(*g2g_pool.shares)[i];
		if (share->status == EMPTY) {
			hyp_print("get_new %d\n",i);
			return i;
		}
	}
	return -1;
}

enum share_mode get_g2g_mode(struct g2g_share *share,
		    pkvm_handle_t handle, pkvm_handle_t partner, u64 ipa)
{
	if (share->status == EMPTY)
		return NONE;

	if (share->initiator_handle == handle)
		if ((!ipa) || (share->initiator_ipa == ipa))
			if ((!partner) || (share->completer_handle == partner)) {
				return INITIATOR;
			}
	if (share->completer_handle == handle)
		if ((!ipa) || (share->completer_ipa == ipa))
			if ((!partner) || (share->initiator_handle == partner))
				return COMPLETER;
	return NONE;
}

pkvm_handle_t find_next_g2g_share(struct pkvm_hyp_vm *hyp_vm, pkvm_handle_t partner)
{
	struct g2g_share *share;// = g2g_shares;
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	int idx;
	int share_id ;
	int start;

	if  (partner == 0)
		start = 0;
	else
		start = vm_handle_to_idx(partner) + 1;

	for (idx = start; idx < KVM_MAX_PVMS; idx++) {
		if (idx_to_vm_handle(idx) == handle)
			continue;
		for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
			share = &(*g2g_pool.shares)[share_id];
			if ((get_g2g_mode(share, handle, idx_to_vm_handle(idx), 0) != NONE) &&
			    (share->page_nr == 1)) {
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
	kvm_pte_t ptep;
	enum kvm_pgtable_prot prot;
	u32 level;

	hyp_print("do_share ipa:%llx -> phys. %llx\n",ipa,  phys);
	if (kvm_pgtable_get_leaf(&vm->pgt, ipa, &ptep, &level)) {
		hyp_print("ERR: cannot read mapping status\n");
		return -EINVAL;
	}

	hyp_print("pte1 %llx lev: %d\n",ptep, level);
	if (ptep) {
		hyp_print("the page has already been mapped\n");
		//return -EINVAL;
	}

	prot = pkvm_mkstate(KVM_PGTABLE_PROT_RW, PKVM_PAGE_SHARED_BORROWED);
	return kvm_pgtable_stage2_map(&vm->pgt, ipa, PAGE_SIZE, phys, prot, mc, 0);
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
	u32 page_nr = smccc_get_arg2(vcpu);
	u64 partner = smccc_get_arg3(vcpu);

	hyp_print("guest_share  ipa:%llx part: %x handle: %x page:%x /n",
		   ipa,partner,handle, page_nr);
	if (handle == partner) {
		hyp_print("cannot be shared by itself\n");
		ret = EINVAL;
		goto out;

	}

	/* look for an existing sharing request for this guest */
	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];

		if (get_g2g_mode(share, handle, partner, 0) == NONE)
			continue;
		if ((share->status == INITIATED) && share->page_nr == page_nr) {
			hyp_print("complete share %d phys:%llx\n",share_id, get_share_phys(share_id));
			if (!do_g2g_map(hyp_vcpu, ipa, get_share_phys(share_id))) {
				share->completer_ipa = ipa;
				share->status = COMPLETED;
				share_completed = true;
				hyp_print("pkvm_g2g_share_complete OK\n");
			} else {
				ret = EINVAL;
			}
			goto out;
		}
	}

	share_id = get_new_share();
	if (share_id < 0) {
		ret = -EINVAL;
		goto out;
	}

	hyp_print("initiate share %d phys:%llx\n",share_id, get_share_phys(share_id));
	if (!do_g2g_map(hyp_vcpu, ipa, get_share_phys(share_id))) {
		share = &(*g2g_pool.shares)[share_id];
		share->completer_handle = partner;
		share->page_nr = page_nr;
		share->initiator_handle = handle;
		share->initiator_ipa = ipa;
		share->status = INITIATED;

	} else
		ret = EINVAL;

out:
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
	u32 waiting = 0;
	u32 completed = 0;
	u32 incoming_req = 0;
	u32 unsharing = 0;
	u64 stat1;
	u64 stat2;

	hyp_print("pkvm_guest_to_guest_query h:%x p:%x\n",handle, partner);
	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		mode = get_g2g_mode(share, handle, partner, 0);
		if (mode == NONE)
			continue;
		switch (share->status) {
		case COMPLETED:
			completed++;
			break;
		case INITIATED:
			if (mode == INITIATOR)
				waiting++;
			if (mode == COMPLETER)
				incoming_req++;
			break;
		case INIT_UNSHARED:
			if (mode == COMPLETER)
				unsharing++;
			break;
		case COMP_UNSHARED:
			if (mode == INITIATOR)
				unsharing++;
			break;
		default:
		}
	}

	stat1 = (u64) incoming_req << 32 | waiting;
	stat2 = (u64) completed << 32 | unsharing;

	partner = find_next_g2g_share(hyp_vm, partner);
	smccc_set_retval(vcpu, SMCCC_RET_SUCCESS, stat1, stat2, partner);

	return true;
}


int do_pkvm_g2g_unmap(struct pkvm_hyp_vm *vm, u64 ipa)
{
	int ret;

	hyp_print("do_pkvm_g2g_unshare\n");
	host_lock_component();
	guest_lock_component(vm);
	ret = kvm_pgtable_stage2_unmap(&vm->pgt, ipa, 4096);

	guest_unlock_component(vm);
	host_unlock_component();

	return ret;
}

static int __pkvm_g2g_unshare(struct pkvm_hyp_vm *hyp_vm, pkvm_handle_t handle, pkvm_handle_t partner, u64 ipa)
{
	struct g2g_share *share;
	u64 unmap_ipa = 0;
	int share_id;
	u64 phys;
	int ret = 0;

	hyp_print("pkvm_g2g_unshare i:%x c: %x ipa: %llx\n", handle, partner, ipa);
	for (share_id = 0; share_id < g2g_pool.nr_pages; share_id++) {
		share = &(*g2g_pool.shares)[share_id];
		switch (get_g2g_mode(share, handle, 0, ipa)) {
		case INITIATOR:
			//share->initiator_handle = 0;
			hyp_print("unshare: found initiator\n");
			unmap_ipa = share->initiator_ipa;
			share->initiator_ipa = 0;
			if ((share->status == INITIATED) ||
			    (share->status == COMP_UNSHARED))
				share->status = EMPTY;
			else
				share->status = INIT_UNSHARED;
			break;

		case COMPLETER:
			//share->completer_handle = 0;
			hyp_print("unshare: found completer\n");
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
			unmap_ipa = 0;
			if (share->status == EMPTY) {
				phys = get_share_phys(share_id);
				memset(hyp_phys_to_virt(phys), 0, PAGE_SIZE);
			}
			hyp_print("unmap ipa %lx %x\n", unmap_ipa, handle);
			ret = do_pkvm_g2g_unmap(hyp_vm, unmap_ipa);
			 /* if an IPA address is given, only that address will
			  * be unmapped, otherwise all addresses shared by the
			  * guest will be unmapped
			  */
			if (ipa) {
				hyp_print("stop unmap\n");
				break;
			}
		}
	}
	return ret;
}

bool pkvm_g2g_unshare(struct pkvm_hyp_vcpu *hyp_vcpu, u64 *exit_code)
{

	struct pkvm_hyp_vm *hyp_vm = pkvm_hyp_vcpu_to_hyp_vm(hyp_vcpu);
	struct kvm_vcpu *vcpu = &hyp_vcpu->vcpu;
	pkvm_handle_t handle = hyp_vm->kvm.arch.pkvm.handle;
	u64 ipa = smccc_get_arg1(vcpu);
	pkvm_handle_t partner = smccc_get_arg2(vcpu);
	int ret;

	ret = __pkvm_g2g_unshare(hyp_vm, handle, partner, ipa);

	smccc_set_retval(vcpu,ret, 0, 0, 0);

	return true;

}

void pkvm_g2g_share_teardown(pkvm_handle_t handle)
{
	struct pkvm_hyp_vm *hyp_vm = get_vm_by_handle(handle);
	__pkvm_g2g_unshare(hyp_vm, handle, 0, 0);
}
