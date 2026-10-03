/*
 * sieveplate — seL4 (Microkit) reference cell PD.
 *
 * The minimal honest artifact: a real seL4 protection domain, built by
 * CI with the Microkit SDK, booted under QEMU, printing a banner that
 * the boot smoke test greps for. The next port step replaces this body
 * with the vat event loop over endpoint capabilities (see README.md).
 */
#include <microkit.h>

#define BANNER "sieveplate-seL4-cell boot OK\n"

void
init(void)
{
    microkit_dbg_puts(BANNER);
}

void
notified(microkit_channel ch)
{
    (void)ch;
}
