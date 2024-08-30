#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

#define MAX_LENGTH 2097152

void FLUSH()
{
    asm volatile(
        "mov %%cr3, %%rax;"
        "mov %%rax, %%cr3;"
        :
        :
        : "%rax");
}

u64 *get_user_pte_entry(struct exec_context *ctx, u64 addr, int dump)
{
    u64 *vaddr_base = (u64 *)osmap(ctx->pgd);
    u64 *entry;
    u32 phy_addr;

    entry = vaddr_base + (addr >> 39);
    phy_addr = (*entry >> 12);
    vaddr_base = (u64 *)osmap(phy_addr);
    if ((*entry & 0x1) == 0)
        return NULL;

    entry = vaddr_base + (addr >> 30);
    phy_addr = (*entry >> 12);
    vaddr_base = (u64 *)osmap(phy_addr);
    if ((*entry & 0x1) == 0)
        return NULL;

    entry = vaddr_base + (addr >> 21);
    phy_addr = (*entry >> 12);
    vaddr_base = (u64 *)osmap(phy_addr);
    if ((*entry & 0x1) == 0)
        return NULL;

    entry = vaddr_base + (addr >> 12);
    if ((*entry & 0x1) == 0)
        return NULL;

    return entry;
}

int pfn_modifier(long address)
{

    struct exec_context *ctx = get_current_ctx();
    long pfn = ctx->pgd;

    int offset;
    long *base_ptr;

    for (int i = 0; i < 4; i++)
    {
        base_ptr = osmap(pfn);
        offset = (address >> (39 - 9 * i)) % 512;
        pfn = base_ptr[offset] >> 12;
    }
    if (base_ptr[offset] % 2 == 1)
    {
        if (get_pfn_refcount(pfn) != 1)
        {
            put_pfn(pfn);
            base_ptr[offset] = 0;
        }
        else
        {
            put_pfn(pfn);
            os_pfn_free(USER_REG, pfn);
            base_ptr[offset] = 0;
        }
    }
    asm volatile("invlpg (%0)" ::"r"(address) : "memory");
    return 0;
}

struct vm_area *init_vma(long start, long end, int prot)
{
    struct vm_area *new_vma = os_alloc(sizeof(struct vm_area));
    new_vma->vm_start = start;
    new_vma->vm_end = end;
    new_vma->access_flags = prot;
    stats->num_vm_area += 1;
    return new_vma;
}

u32 map_to_physical_page(struct exec_context *current, u64 address, u32 access_flags)
{
    u64 *pgd_base = (u64 *)osmap(current->pgd);
    u64 offset_into_pgd = (address >> 39);
    u64 *offset_loc_in_pgd = pgd_base + offset_into_pgd;

    if ((*offset_loc_in_pgd & 0x1) == 0)
    {
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        *offset_loc_in_pgd = 0x0;
        *offset_loc_in_pgd = (pfn << 12) | 0x19;
    }

    u64 *pud_base = (u64 *)osmap(*offset_loc_in_pgd >> 12);
    u64 offset_into_pud = (address >> 30);
    u64 *offset_loc_in_pud = pud_base + offset_into_pud;

    if ((*offset_loc_in_pud & 0x1) == 0)
    {
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        *offset_loc_in_pud = 0x0;
        *offset_loc_in_pud = (pfn << 12) | 0x19;
    }

    u64 *pmd_base = (u64 *)osmap(*offset_loc_in_pud >> 12);
    u64 offset_into_pmd = (address >> 21);
    u64 *offset_loc_in_pmd = pmd_base + offset_into_pmd;

    if ((*offset_loc_in_pmd & 0x1) == 0)
    {
        u64 pfn = os_pfn_alloc(OS_PT_REG);
        *offset_loc_in_pmd = 0x0;
        *offset_loc_in_pmd = (pfn << 12) | 0x19;
    }

    u64 *pte_base = (u64 *)osmap(*offset_loc_in_pmd >> 12);
    u64 offset_into_pte = (address >> 12);
    u64 *offset_loc_in_pte = pte_base + offset_into_pte;

    if (*offset_loc_in_pte & 0x1)
    {
        return 0;
    }
    else
    {
        u64 new_page = os_pfn_alloc(USER_REG);
        *offset_loc_in_pte = 0x0;

        if (access_flags == PROT_READ)
        {
            *offset_loc_in_pte = (new_page << 12) | 0x11;
        }
        else
        {
            *offset_loc_in_pte = (new_page << 12) | 0x19;
        }

        return 0;
    }
}

int modify_prot(long address, int prot)
{
    struct exec_context *ctx = get_current_ctx();
    long pfn = ctx->pgd;
    long *base_ptr;
    int offset;
    for (int i = 0; i < 4; i++)
    {
        base_ptr = osmap(pfn);
        offset = (address >> (39 - 9 * i)) % 512;
        pfn = base_ptr[offset] >> 12;
    }

    if (!base_ptr[offset] % 2)
    {
        return 0;
    }

    if (get_pfn_refcount(pfn) != 1)
    {
        if (prot == PROT_READ)
        {
            base_ptr[offset] = base_ptr[offset] & (-9);
        }
    }
    else
    {
        if ((prot & PROT_WRITE) == PROT_WRITE)
        {
            base_ptr[offset] = base_ptr[offset] | 8;
        }
        else
        {
            base_ptr[offset] = base_ptr[offset] & (-9);
        }
    }

    asm volatile("invlpg (%0)" ::"r"(address) : "memory");
    return 0;
}

int duplicate_memory(long begin, long end, long pgd_old, long pgd_new)
{

    begin = begin - begin % 4096;

    long pfn1, pfn2;
    long *rt_old, *rt_new;

    long *rt_ptr_old = osmap(pgd_old);
    long *rt_ptr_new = osmap(pgd_new);

    for (long addr = begin; addr < end; addr += 4096)
    {

        rt_old = rt_ptr_old;
        rt_new = rt_ptr_new;
        int offset;

        for (int i = 1; i <= 4; i++)
        {
            offset = (addr >> (48 - 9 * i)) % 512;

            if (rt_old[offset] % 2 == 0)
            {
                rt_new[offset] = 0;
                break;
            }
            else if (i <= 3)
            {
                if (rt_new[offset] % 2 == 0)
                {

                    long temp = os_pfn_alloc(OS_PT_REG);

                    if (temp == 0)
                    {
                        return -1;
                    }

                    rt_new[offset] = (temp << 12) + (rt_old[offset] % 4096);
                }
                rt_old = osmap(rt_old[offset] >> 12);
                rt_new = osmap(rt_new[offset] >> 12);
            }
            else
            {
                rt_old[offset] = rt_old[offset] & (-9);
                rt_new[offset] = rt_old[offset];
                get_pfn(rt_old[offset] >> 12);
                asm volatile("invlpg (%0)" ::"r"(addr) : "memory");
            }
        }
    }
    return 0;
}

/**
 * mprotect System call Implementation.
 */
long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    if (current == NULL || length > MAX_LENGTH || addr >= MMAP_AREA_END || addr < MMAP_AREA_START || prot <= 0 || prot >= 4)
    {
        return -EINVAL;
    }

    if (length < 0)
    {
        return -EINVAL;
    }

    if (length == 0)
    {
        return 0;
    }

    if (length % 4096 != 0)
    {
        length = length - length % 4096 + 4096;
    }

    if (current->vm_area == NULL)
    {
        current->vm_area = init_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr->vm_start < addr + length && curr != NULL)
    {
        long start, end;

        if (curr->access_flags == prot || curr->vm_end <= addr)
        {
            prev = curr;
            curr = curr->vm_next;
            continue;
        }
        else
        {
            if (addr + length >= curr->vm_end)
            {
                end = curr->vm_end;
                struct vm_area *next = curr->vm_next;
                if (addr > curr->vm_start)
                {
                    start = addr;
                    if (next != NULL && next->vm_start == curr->vm_end && next->access_flags == prot)
                    {
                        next->vm_start = addr;
                        curr->vm_end = addr;
                    }
                    else
                    {
                        struct vm_area *new_vma = init_vma(addr, curr->vm_end, prot);
                        curr->vm_end = addr;
                        new_vma->vm_next = curr->vm_next;
                        curr->vm_next = new_vma;
                    }
                }
                else
                {
                    start = curr->vm_start;
                    if (prev->access_flags == prot && prev != current->vm_area && prev->vm_end == curr->vm_start)
                    {
                        if (next != NULL && next->vm_start == curr->vm_end && next->access_flags == prot)
                        {
                            prev->vm_end = next->vm_end;
                            prev->vm_next = next->vm_next;

                            os_free(curr, sizeof(struct vm_area));
                            os_free(next, sizeof(struct vm_area));

                            stats->num_vm_area -= 2;
                            curr = prev;
                        }
                        else
                        {
                            prev->vm_end = curr->vm_end;
                            prev->vm_next = next;

                            os_free(curr, sizeof(struct vm_area));
                            stats->num_vm_area--;
                            curr = prev;
                        }
                    }
                    else
                    {
                        if (next->access_flags == prot && next != NULL && next->vm_start == curr->vm_end)
                        {
                            curr->vm_end = next->vm_end;
                            curr->vm_next = next->vm_next;
                            curr->access_flags = prot;
                            os_free(next, sizeof(struct vm_area));
                            stats->num_vm_area--;
                        }
                        else
                        {
                            curr->access_flags = prot;
                        }
                    }
                }
                for (long ptr = start; ptr < end; ptr += 4096)
                {
                    modify_prot(ptr, prot);
                }
            }
            else
            {
                end = addr + length;
                if (curr->vm_start < addr)
                {
                    start = addr;

                    struct vm_area *new_vma1 = init_vma(curr->vm_start, addr, curr->access_flags);
                    struct vm_area *new_vma2 = init_vma(addr, addr + length, prot);

                    curr->vm_start = addr + length;
                    prev->vm_next = new_vma1;
                    new_vma1->vm_next = new_vma2;
                    new_vma2->vm_next = curr;
                }
                else
                {
                    start = curr->vm_start;
                    if (prev->vm_end == curr->vm_start && prev->access_flags == prot && prev != current->vm_area)
                    {
                        prev->vm_end = addr + length;
                        curr->vm_start = addr + length;
                    }
                    else
                    {
                        struct vm_area *new_vma = init_vma(curr->vm_start, addr + length, prot);
                        curr->vm_start = addr + length;
                        new_vma->vm_next = curr;
                        prev->vm_next = new_vma;
                    }
                }

                for (long ptr = start; ptr < end; ptr += 4096)
                {
                    modify_prot(ptr, prot);
                }
                break;
            }
        }
        prev = curr;
        curr = curr->vm_next;
    }
    return 0;
}

/**
 * mmap system call implementation.
 */
long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if ((flags != 1 && flags != 0) || current == NULL || length > MAX_LENGTH || prot <= 0 || prot >= 4)
    {
        return -EINVAL;
    }

    if (length < 0)
    {
        return -EINVAL;
    }

    if (length == 0)
    {
        return 0;
    }
    if (length % 4096 != 0)
    {
        length = length - length % 4096 + 4096;
    }

    if (current->vm_area == NULL)
    {

        current->vm_area = init_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }

    if ((addr == NULL || addr < MMAP_AREA_START || addr >= MMAP_AREA_END) && flags == MAP_FIXED)
    {
        return -EINVAL;
    }

    if (addr < MMAP_AREA_END && addr != NULL && addr >= MMAP_AREA_START + 4096)
    {

        struct vm_area *prev = current->vm_area;
        struct vm_area *curr = prev->vm_next;

        while (prev->vm_end <= addr && curr != NULL)
        {
            if (addr + length <= curr->vm_start)
            {
                if (prev->access_flags == prot && addr == prev->vm_end)
                {
                    if (!(addr + length == curr->vm_start && curr->access_flags == prot))
                    {
                        prev->vm_end += length;
                    }
                    else
                    {
                        prev->vm_end = curr->vm_end;
                        prev->vm_next = curr->vm_next;

                        os_free(curr, sizeof(struct vm_area));
                        stats->num_vm_area--;
                    }
                }

                else
                {
                    if (!(prot == curr->access_flags && addr + length == curr->vm_start))
                    {
                        struct vm_area *new_vma = init_vma(addr, addr + length, prot);
                        prev->vm_next = new_vma;
                        new_vma->vm_next = curr;
                    }
                    else
                    {
                        curr->vm_start -= length;
                    }
                }
                return addr;
            }
            else if (addr <= curr->vm_start)
            {
                if (flags == MAP_FIXED)
                {
                    return -1;
                }
                else
                {
                    break;
                }
            }
            else
            {
                prev = curr;
                curr = curr->vm_next;
            }
        }
        if (curr == NULL)
        {
            if (prev->access_flags == prot && addr == prev->vm_end)
            {
                prev->vm_end += length;
                return addr;
            }
            else if (flags == MAP_FIXED)
            {
                return -EINVAL;
            }
            else if (addr > prev->vm_end)
            {
                struct vm_area *new_vma = init_vma(addr, addr + length, prot);
                prev->vm_next = new_vma;
                new_vma->vm_next = NULL;
                return addr;
            }
        }
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr != NULL)
    {
        if (curr->vm_start - prev->vm_end >= length)
        {
            long returnvalue = prev->vm_end;
            if (prev->access_flags != prot)
            {
                if (prev->vm_end + length == curr->vm_start && prot == curr->access_flags)
                {
                    curr->vm_start -= length;
                }
                else
                {
                    struct vm_area *new_vma = init_vma(prev->vm_end, prev->vm_end + length, prot);
                    prev->vm_next = new_vma;
                    new_vma->vm_next = curr;
                }
            }
            else
            {
                if (!(prev->vm_end + length == curr->vm_start && prot == curr->access_flags))
                {
                    prev->vm_end += length;
                }
                else
                {
                    prev->vm_end = curr->vm_end;
                    prev->vm_next = curr->vm_next;
                    os_free(curr, sizeof(struct vm_area));
                    stats->num_vm_area--;
                }
            }
            return returnvalue;
        }
        else
        {
            prev = curr;
            curr = curr->vm_next;
        }
    }
    if (curr == NULL)
    {
        long returnvalue = prev->vm_end;
        if (prev->access_flags != prot)
        {
            struct vm_area *new_vma = init_vma(prev->vm_end, prev->vm_end + length, prot);
            prev->vm_next = new_vma;
            new_vma->vm_next = NULL;
        }
        else
        {
            prev->vm_end += length;
        }
        return returnvalue;
    }
    return -EINVAL;
}

/**
 * munmap system call implemenations
 */

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{
    if (length > MAX_LENGTH || current == NULL || addr < MMAP_AREA_START || addr >= MMAP_AREA_END)
    {
        return -EINVAL;
    }
    if (length < 0)
    {
        return -EINVAL;
    }
    if (length == 0)
    {
        return 0;
    }
    if (length % 4096 != 0)
    {
        length = length - length % 4096 + 4096;
    }

    if (current->vm_area == NULL)
    {
        current->vm_area = init_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }

    struct vm_area *prev = current->vm_area;
    struct vm_area *curr = prev->vm_next;

    while (curr != NULL && curr->vm_start < addr + length)
    {
        if (curr->vm_end > addr)
        {
            long start, end;
            if (addr + length < curr->vm_end)
            {
                end = addr + length;
                if (curr->vm_start < addr)
                {
                    start = addr;
                    struct vm_area *new_vma = init_vma(curr->vm_start, addr, curr->access_flags);
                    prev->vm_next = new_vma;
                    new_vma->vm_next = curr;
                    curr->vm_start = addr + length;
                }
                else
                {
                    start = curr->vm_start;
                    curr->vm_start = addr + length;
                }
            }
            else
            {
                end = curr->vm_end;
                if (addr <= curr->vm_start)
                {
                    start = curr->vm_start;
                    prev->vm_next = curr->vm_next;
                    os_free(curr, sizeof(struct vm_area));
                    stats->num_vm_area--;
                    curr = prev;
                }
                else
                {
                    start = addr;
                    curr->vm_end = addr;
                }
            }

            for (long ptr = start; ptr < end; ptr += 4096)
            {
                pfn_modifier(ptr);
            }
        }
        prev = curr;
        curr = curr->vm_next;
    }

    return 0;
}

/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    if (addr < MMAP_AREA_START || current == NULL || addr >= MMAP_AREA_END)
    {
        return -EINVAL;
    }

    if (error_code != 6 && error_code != 7 && error_code != 4)
    {
        return -1;
    }

    if (current->vm_area == NULL)
    {
        current->vm_area = init_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        current->vm_area->vm_next = NULL;
        stats->num_vm_area = 1;
    }

    struct vm_area *curr = current->vm_area->vm_next;

    for (; curr != NULL; curr = curr->vm_next)
    {

        if (curr->vm_start <= addr && addr < curr->vm_end)
        {
            if (error_code == 7)
            {
                if ((curr->access_flags & PROT_WRITE) == PROT_WRITE)
                {

                    handle_cow_fault(current, addr, curr->access_flags);
                    return 1;
                }
                else
                {
                    return -1;
                }
            }

            else
            {
                if (curr->access_flags == PROT_READ && error_code == 6)
                {
                    return -1;
                }
                long *rt_ptr = osmap(current->pgd);
                for (int i = 1; i <= 3; i++)
                {
                    int offset = (addr >> (48 - 9 * i)) % 512;
                    if (!rt_ptr[offset] % 2)
                    {
                        long pfn = os_pfn_alloc(OS_PT_REG);
                        if (pfn == 0)
                        {
                            return -1;
                        }
                        rt_ptr[offset] = (pfn << 12) + (1 << 4) + (1 << 3) + 1;
                    }
                    rt_ptr = osmap(rt_ptr[offset] >> 12);
                }
                int offset = (addr >> 12) % 512;
                if (!rt_ptr[offset] % 2)
                {
                    int check = 0;
                    if ((curr->access_flags & PROT_WRITE) == PROT_WRITE)
                        check = 1;
                    long pfn = os_pfn_alloc(USER_REG);
                    if (pfn == 0)
                        return -1;
                    rt_ptr[offset] = (pfn << 12) + (1 << 4) + (check << 3) + 1;
                }
                return 1;
            }
            break;
        }
    }
    return -1;
}

/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the
 * end of this function (e.g., setup_child_context etc.)
 */

int copy_exec_state(struct exec_context *new_ctx, struct exec_context *ctx)
{
    int returnvalue;

    new_ctx->ppid = ctx->pid;

    new_ctx->type = ctx->type;

    new_ctx->used_mem = ctx->used_mem;

    new_ctx->state = ctx->state;

    new_ctx->regs = ctx->regs;

    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;

    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;

    new_ctx->alarm_config_time = ctx->alarm_config_time;

    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;

    new_ctx->ctx_threads = ctx->ctx_threads;

    for (int i = 0; i < MAX_MM_SEGS; i++)
    {
        new_ctx->mms[i] = ctx->mms[i];
    }

    if (ctx->vm_area == NULL)
    {
        new_ctx->vm_area = NULL;
    }
    else
    {
        struct vm_area *temp1, *new_vma, *temp2 = ctx->vm_area->vm_next;
        new_ctx->vm_area = init_vma(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        temp1 = new_ctx->vm_area;
        while (temp2 != NULL)
        {
            new_vma = init_vma(temp2->vm_start, temp2->vm_end, temp2->access_flags);
            temp1->vm_next = new_vma;
            temp1 = new_vma;
            temp2 = temp2->vm_next;
        }
        temp1->vm_next = NULL;
    }
    for (int i = 0; i < MAX_OPEN_FILES; i++)
    {
        new_ctx->files[i] = ctx->files[i];
    }
    for (int i = 0; i < CNAME_MAX; i++)
    {
        new_ctx->name[i] = ctx->name[i];
    }
    for (int i = 0; i < MAX_SIGNALS; i++)
    {
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG);

    if (new_ctx->pgd == 0)
    {
        return -1;
    }

    for (int i = 0; i <= 2; i++)
    {
        returnvalue = duplicate_memory(ctx->mms[i].start, ctx->mms[i].next_free, ctx->pgd, new_ctx->pgd);
        if (returnvalue == -1)
        {
            return -1;
        }
    }
    returnvalue = duplicate_memory(ctx->mms[3].start, ctx->mms[3].end, ctx->pgd, new_ctx->pgd);
    if (returnvalue == -1)
    {
        return -1;
    }

    if (ctx->vm_area != NULL)
    {
        for (struct vm_area *ptr = ctx->vm_area->vm_next; ptr != NULL; ptr = ptr->vm_next)
        {
            returnvalue = duplicate_memory(ptr->vm_start, ptr->vm_end, ctx->pgd, new_ctx->pgd);

            if (returnvalue == -1)
            {
                return -1;
            }
        }
    }
}

long do_cfork()
{
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
    /* Do not modify above lines
     *
     * */
    //--------------------- Your code [start]---------------//

    pid = new_ctx->pid;

    if (copy_exec_state(new_ctx, ctx) == -1)
        return -1;

    //--------------------- Your code [end] ----------------//

    /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}

/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data)
 * it is called when there is a CoW violation in these areas.
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    long *pfn_temp;
    long temp = current->pgd;
    int phy_addr;
    for (int j = 1; j <= 4; j++)
    {
        pfn_temp = osmap(temp);
        phy_addr = (vaddr >> (48 - 9 * j)) % 512;
        temp = pfn_temp[phy_addr] >> 12;
    }

    int count = get_pfn_refcount(temp);

    if (count <= 1)
    {
        pfn_temp[phy_addr] = pfn_temp[phy_addr] | 8;
    }
    else
    {
        long temp1 = os_pfn_alloc(USER_REG);
        if (temp1 == 0)
            return -1;
        pfn_temp[phy_addr] = (temp1 << 12) + (pfn_temp[phy_addr] % 4096);
        pfn_temp[phy_addr] = pfn_temp[phy_addr] | 8;
        put_pfn(temp);

        long *temp2 = osmap(temp);
        long *temp3 = osmap(temp1);
        for (int i = 0; i < 512; i++)
        {
            temp3[i] = temp2[i];
        }
    }

    asm volatile("invlpg (%0)" ::"r"(vaddr) : "memory");
    return 1;
}