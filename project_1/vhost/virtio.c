/* virtio.c: STUDENT IMPLEMENTATION FILE for Project 1 (Part III).
 *
 * In Part II you invented a device protocol (MMIO registers). Here you implement
 * the one the whole world actually uses: a virtio split virtqueue, driven by a
 * REAL QEMU virtual machine, whose stock virtio_console driver talks to your
 * code with no guest-side changes at all.
 *
 * The provided backend (backend.c) speaks the vhost-user protocol to QEMU, maps
 * the guest's memory, sets up the rings, and calls you every time the guest
 * kicks the queue. Everything below the seam is yours: TWO functions.
 *
 * WHAT IS PROVIDED: virtq.h (the ring structures, the memory map, the log sink),
 * backend.c (all vhost-user plumbing), run-qemu.sh (boots the VM).
 *
 * ============================================================================
 * TASK (a): virtq_gpa_to_hva(), the hypervisor's address translation.
 * ============================================================================
 * You wrote this once already: vmm_gpa_to_host() in Part I. This is the same
 * contract against a real hypervisor's memory map, except now there can be
 * SEVERAL regions with GAPS between them (see `struct virtq_mem` in virtq.h).
 *
 * Return a host pointer for [gpa, gpa+len), or NULL unless the range lies
 * ENTIRELY inside ONE region. The guest picks these numbers, so reject:
 *   - a range that runs off the end of its region (no straddling two regions),
 *   - an address in a gap between regions, or outside all of them,
 *   - a gpa + len that overflows.
 * Get this wrong and the guest can make your hypervisor read (or crash on)
 * memory that is not its own.
 *
 * ============================================================================
 * TASK (b): vlog_virtq_handle(), the virtqueue.
 * ============================================================================
 * For every chain the guest has made available:
 *
 *   1. Read the head index from the AVAIL ring:
 *          head = vq->avail->ring[vq->last_avail % vq->num]
 *      (First read vq->avail->idx to see how many are ready, and virtq_rmb()
 *      before you trust the ring contents.)
 *   2. Walk the DESCRIPTOR CHAIN from `head`. For each descriptor:
 *        - VRING_DESC_F_WRITE set  -> it is space for the DEVICE to write into.
 *          This queue is guest->host, so it carries no data: skip it.
 *        - VRING_DESC_F_INDIRECT set -> it is not data either! `d->addr` points
 *          at a TABLE of further descriptors in guest memory (`d->len` bytes of
 *          them, so d->len / sizeof(struct vring_desc) entries), which form
 *          their own chain starting at index 0. Translate the table and walk it.
 *          (Indirect tables do not nest.)
 *        - otherwise it is data: translate d->addr with
 *              virtq_gpa_to_hva(mem, d->addr, d->len)
 *          (CHECK FOR NULL) and append its bytes to the record.
 *        - follow d->next while VRING_DESC_F_NEXT is set.
 *      Concatenate the chain's bytes into one record, capped at VIRTQ_MAX_RECORD
 *      (never overflow your buffer).
 *   3. Emit it:  vlog_sink_emit(sink, bytes, len);
 *   4. COMPLETE the chain on the USED ring:
 *          vq->used->ring[vq->used->idx % vq->num] = { .id = head, .len = 0 };
 *          virtq_wmb();
 *          vq->used->idx++;
 *      (This is the virtio equivalent of the Part II STATUS/SEQ readback: it is
 *      how the driver learns its buffer is free again. Get it wrong and the
 *      guest hangs after a few writes.)
 *   5. Advance vq->last_avail and count the chain.
 *
 * Return the number of chains you completed; the backend raises the guest's
 * interrupt when that is > 0.
 *
 * SAFETY: the rings live in memory the GUEST owns and can change at any time. A
 * descriptor index, a chain, or a length can be nonsense. Bounds-check every
 * index against the table size, check every translation, and never loop forever
 * on a cyclic chain. A hypervisor must not be crashable by its guest.
 *
 * See SPEC.md Part III. Develop against `cd tests && ./run_virtq_tests.sh`, then
 * watch it drive a real VM with `cd vhost && ./run-qemu.sh`.
 */
#include "virtq.h"

#include <string.h>
#include <stdbool.h>

/* ---- (a) guest-physical -> host-virtual -------------------------------- */

void *virtq_gpa_to_hva(const struct virtq_mem *mem, uint64_t gpa, uint64_t len)
{
    if (mem == NULL || len == 0)
        return NULL;

    if (gpa > UINT64_MAX - len)
        return NULL;

    size_t num_regions = mem->nregions;
    
    for (size_t i = 0; i < num_regions; ++i) {

        const struct virtq_mem_region *r = &mem->regions[i];

        if (r->gpa > UINT64_MAX - r->size)
            continue;

        uint64_t curr_gpa = r->gpa;
        uint64_t end_gpa = curr_gpa + r->size;

        if (gpa >= curr_gpa && gpa + len <= end_gpa) {
            return mem->regions[i].hva + (gpa - curr_gpa);  
        }

    }

    /* TODO(student): find the region that fully contains [gpa, gpa+len) and
     * return the host pointer for it; otherwise return NULL. See the notes
     * above, and remember what vmm_gpa_to_host() had to guard against. */
    return NULL;
}

/* ---- (b) the virtqueue ------------------------------------------------- */
static void append_descriptor(const struct virtq_mem *mem, const struct vring_desc *d, char rec[VIRTQ_MAX_RECORD], uint32_t *rec_len)
{
    if (d->len == 0)
        return;

    const void *src = virtq_gpa_to_hva(mem, d->addr, d->len);
    if (src == NULL)
        return;

    uint32_t remaining = VIRTQ_MAX_RECORD - *rec_len;
    uint32_t amount = d->len;

    if (amount > remaining)
        amount = remaining;

    if (amount > 0) {
        memcpy(rec + *rec_len, src, amount);
        *rec_len += amount;
    }
}

static void process_table(const struct vring_desc *table,
                          uint32_t count,
                          uint16_t head,
                          bool allow_indirect,
                          const struct virtq_mem *mem,
                          char rec[VIRTQ_MAX_RECORD],
                          uint32_t *rec_len)
{
    uint32_t index = head;
    uint32_t hops = 0;

    while (index < count && hops < count) {
        struct vring_desc d = table[index];
        hops++;

        if (d.flags & VRING_DESC_F_WRITE) {
            // skip
        } else if (d.flags & VRING_DESC_F_INDIRECT) {
            // Indirect descriptors are permitted only in the main table.
            // An indirect table cannot contain another indirect table.
            if (!allow_indirect)
                break;

            if (d.len >= sizeof(struct vring_desc) &&
                d.len % sizeof(struct vring_desc) == 0) {
                struct vring_desc *indirect =
                    virtq_gpa_to_hva(mem, d.addr, d.len);

                if (indirect != NULL) {
                    uint32_t indirect_count =
                        d.len / (uint32_t)sizeof(struct vring_desc);

                    process_table(indirect, indirect_count, 0, false, mem, rec, rec_len);
                }
            }
        } else {
            append_descriptor(mem, &d, rec, rec_len);
        }

        if (!(d.flags & VRING_DESC_F_NEXT))
            break;

        if ((uint32_t)d.next >= count)
            break;

        index = d.next;
    }
}


int vlog_virtq_handle(struct virtq *vq, const struct virtq_mem *mem,
                      struct vlog_sink *sink)
{

    if (vq == NULL || mem == NULL || sink == NULL || vq->desc == NULL ||
        vq->avail == NULL || vq->used == NULL || vq->num == 0) {
        return 0;
    }

    int completed = 0;
    uint16_t available = vq->avail->idx;
    virtq_rmb();

    while (vq->last_avail != available) {
        char record[VIRTQ_MAX_RECORD];

        uint32_t record_len = 0;
        uint16_t avail_slot = vq->last_avail % vq->num;

        uint16_t head = vq->avail->ring[avail_slot];

        if (head < vq->num) {
            process_table(vq->desc, vq->num, head, true, mem, record, &record_len);
        }

        vlog_sink_emit(sink, record, record_len);

        uint16_t used_slot = vq->used->idx % vq->num;

        vq->used->ring[used_slot].id = head;
        vq->used->ring[used_slot].len = 0;

        virtq_wmb();

        vq->used->idx++;
        vq->last_avail++;
        completed++;
    }

    return completed;
}
