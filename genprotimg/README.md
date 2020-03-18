# genprotimg

`genprotimg` takes a kernel, key files, optionally an initrd image,
optionally a file containing the kernel command line parameters, and
generates a single, bootable image file. The generated image file
consists of a concatenation of a plain text boot loader, the encrypted
components for kernel, initrd, kernel command line, and the
integrity-protected PV header, containing the metadata necessary for
running the guest in protected mode. See [Memory Layout](#memory-layout)
for details about the internal structure of the created image.

It is possible to use the generated image as a kernel for zipl or for
a direct kernel boot using QEMU.

## Getting started

If all dependencies are met a simple `make` call in the source tree
should be enough for building `genprotimg`.

## Details

The main idea of `genprotimg` is:

1. read in all keys, IVs, and other information needed for the
   encryption of the components and the generation of the PV header
2. add stub stage3a (so we can calculate the memory addresses)
3. add components: prepare the components (alignment and encryption)
   and add them to the memory layout
4. build and add stage3b: generate the stage3b and add it to the memory layout
5. generate the PV header: generate the hashes (pld, ald, and tld) of
   the components and create the PV header and IPIB
6. parameterize the stub stage3a: uses the IPIB and PV header
7. write the final image to the specified output path

### Boot Loader

The boot loader consists of two parts:

1. stage3a boot loader (cleartext), this loader is responsible for the
   transition into the protected mode by doing diag308 subcode 8 and
   10 calls.
2. stage3b boot loader (encrypted), this loader is very similar to the
   normal zipl stage3 boot loader. It will be loaded by the Ultravisor
   after the successful transition into protected mode. Like the zipl
   stage3 boot loader it moves the kernel and patches in the values
   for initrd and parmline.

The loaders have the following constraints:

1. It must be possible to place stage3a and stage3b at a location
   greater than 0x10000 because the zipl stage3 loader zeroes out
   everything at addresses lower than 0x10000 of the image.
2. As the stage3 loader of zipl assumes that the passed kernel image
   looks like a normal kernel image, the zipl stage3 loader modifies the
   content at the memory area 0x10400 - 0x10800, therefore we leave this
   area unused in our stage3a loader.
3. The default entry address used by the zipl stage3 loader is 0x10000
   so we add a simple branch to 0x11000 at 0x10000 so the zipl stage3
   loader can modify the area 0x10400 - 0x10800 without affecting the
   stage3a loader.

#### Detail about stage3b

The stage3b.bin is linked at address 0x9000, therefore it will not
work at another address. The relocation support for the stage3b
loader, so that it can be placed at addresses != 0x9000, is added in
the loader with the name stage3b_reloc.bin. By default, if we're
talking about stage3b we refer to stage3b_reloc.bin.

### Memory Layout

The memory layout of the bootable file looks like:

| Start                  | End        | Use                                                                   |
|------------------------|------------|-----------------------------------------------------------------------|
| 0                      | 0x7        | Short PSW, starting instruction at 0x11000                            |
| 0x10000                | 0x10012    | Branch to 0x11000                                                     |
| 0x10013                | 0x10fff    | Left intentionally unused                                             |
| 0x11000                | 0x12fff    | Stage3a                                                               |
| 0x13000                | 0x13fff    | IPIB used as argument for the diag308 call                            |
| 0x14000                | 0x1[45]fff | UV header used for the diag308 call (size can be either 1 or 2 pages) |
| NEXT_PAGE_ALIGNED_ADDR |            | Encrypted kernel                                                      |
| NEXT_PAGE_ALIGNED_ADDR |            | Encrypted kernel parameters                                           |
| NEXT_PAGE_ALIGNED_ADDR |            | Encrypted initrd                                                      |
| NEXT_PAGE_ALIGNED_ADDR |            | Encrypted stage3b_reloc                                               |
