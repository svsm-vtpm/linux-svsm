# Linux SVSM (Secure VM Service Module)

## Table of contents

1. [What is this magic?](#introduction)
2. [Preparing the host](#host)
3. [Installation](#install)
4. [Running Linux SVSM](#run)
5. [Contribution](#contribute)
6. [Authors and License](#authors)

## What is this magic? <a name="introduction"></a>

Linux SVSM (Secure VM Service Module) implements a guest communication
interface so that VM guests can offload sensitive operations (for example,
updating access permissions on protected pages) onto a privileged\* guest
acting as service module. Linux SVSM relies on AMD's Secure Nested Paging
(SNP) and prior Secure Encrypted Virtualization technologies (See
[SEV documentation](https://developer.amd.com/sev/)).

The idea is that Linux SVSM will not only offload security operations,
but will also be able to provide other services such as live VM migration;
the privilege separation model of SVSM permits the existence of a virtual
Trusted Platform Module (virtual TPM).

\* AMD SNP introduces the Virtual Machine Privilege Level (VMPLs) for
enhanced security control. VMPL0 is the highest level of privilege.
Linux SVSM runs at VMPL 0, as opposed to other guests running under
VMPL >=1. Certain operations become architecturally impossible to guests
running at lower privilege levels (e.g. use of the PVALIDATE instruction
and certain forms of RMPADJUST).

Generate and read source code documentation with:

```
# make doc
```

which will also install necessary prerequisites.

This Linux SVSM also implements a virtual Trusted Platform Module (vTPM).
Further information can be found in the [README-vtpm.md](README-vtpm.md) file.

## Preparing the host <a name="host"></a>

Linux SVSM assumes a host with support for AMD's SEV-SNP, as well as
compatible guest, Qemu and OVMF BIOS. We provide bash scripts to automate
the installation process of these prerequisites. The remainder of these
instructions were tested on Ubuntu 22.04 server, installed with kernel
5.15.0-46-generic.

Start by verifying that the following BIOS settings are enabled. The
settings may vary depending on the vendor BIOS. The menu options below are
from AMD's BIOS.

```
  CBS -> CPU Common ->
                SEV-ES ASID space Limit Control -> Manual
                SEV-ES ASID space limit -> 100
                SNP Memory Coverage -> Enabled
                SMEE -> Enabled
      -> NBIO common ->
                SEV-SNP -> Enabled
```

We now need to build the host and guest kernels, Qemu and OVMF BIOS used for
launching the SEV-SNP guest.

```
$ cd scripts/
$ ./build.sh --package
```

If the VTPM flag is disabled, the guest kernel and QEMU built can be used to
test a svsm.bin that does not support vTPM. For example:

```
$ VTPM=0 ./build.sh --package
```

If build fails, read subsection [Build troubleshooting](#trouble-build). On
successful build, the binaries will be available in `snp-release-<DATE>`.

Now we need to install the Linux kernel on the host machine:

```
$ cd snp-release-<date>
$ sudo ./install.sh
```

Reboot the machine and choose SNP Host kernel from the grub menu. You can
check you have a kernel with the proper SNP support with:

```
$ sudo dmesg | grep SEV
[    7.393321] SEV-SNP: RMP table physical address 0x0000000088a00000 - 0x00000000a8ffffff
[   18.958687] ccp 0000:22:00.1: SEV firmware update successful
[   21.081484] ccp 0000:22:00.1: SEV-SNP API:1.51 build:3
[   21.286378] SEV supported: 255 ASIDs
[   21.290367] SEV-ES and SEV-SNP supported: 254 ASIDs
```

### Build troubleshooting <a name="trouble-build"></a>

The most likely source of build errors is missing a tool. Try installing
the following:

```
$ sudo apt install make ninja-build libglib2.0-dev libpixman-1-dev python3
$ sudo apt install nasm iasl flex bison libelf-dev libssl-dev
```

If your error is during OVMF's compilation, you can try getting a verbose
form of the error, running manually with -v. In our case:

```
$ cd ovmf
$ source edksetup.sh
$ nice build -v -q --cmd-len=64436 -DDEBUG_ON_SERIAL_PORT -n 32 -t GCC5 -a X64 -p OvmfPkg/OvmfPkgX64.dsc
```

If your error involves still not finding Python, you can try the following
command (but be aware this may affect other components of your system that
use Python):

```
$ sudo cp /bin/python3 /bin/python
```

## Installation <a name="install"></a>

Linux SVSM requires the Rust nightly tool-chain, as well as components that
can be downloaded from rustup. The process can be automated with:

```
# make prereq
```

You can select default installation for rustup. After that, make sure rust-lld
can be found in your PATH. You can edit your ~/.bashrc with:

```
export PATH="/(YOUR PATH)/rustlib/x86_64-unknown-linux-gnu/bin/:$PATH"
```

The vTPM code has additional dependencies in the form of submodules. Before building,
make sure you update the submodules:

```
# git submodule init
# git submodule update --recursive
```

To build:

```
# make
```

To build with serial output progress information, for debugging:

```
# make FEATURES=verbose
```

You should NEVER have to specify the cargo target, as we have
.cargo/config.toml. The Makefile includes a basic clean target. To
force prerequisites re-installation on the next execution of make do:

```
# make superclean
```

## Running Linux SVSM <a name="run"></a>

The building process will generate svsm.bin that can be passed to Qemu (svsm
parameter). Inside directory scripts/ we provide launch-qemu.sh to ease the
execution of the Qemu virtual machine. First, we need an empty virtual disk
image and distribution (in our example, Ubuntu):

```
# qemu-img create -f qcow2 guest.qcow2 30G
# wget <link-to-iso> ubuntu.iso
```

Once we have an image prepared, we can boot with the command below. In the
Grub option of installation, you can edit the linux kernel command adding
'console=tty0 console=ttyS0,115200n8' and then Ctr+X.

```
# ./launch-qemu.sh -hda guest.qcow2 -cdrom ubuntu.iso
```

after that, we can simply boot and install the kernel \*.debs/\*.rpms from
within the guest VM.

```
[host@snp-host ~]#  ./launch-qemu.sh -hda guest.qcow2
[guest@snp-guest ~]# scp host@ip:/<dir>/scripts/linux/<version>*guest*.deb .
[guest@snp-guest ~]# chmod +x *.deb && dpkg -i *.deb
[guest@snp-guest ~]# reboot
```

Finally, we will have to execute the script again, this time providing the
SVSM binary. Once the SVSM guest is up, you can check it is running on
VMPL1 (lower privilege level) with:

```
[host@snp-host ~]#  ./launch-qemu.sh -hda guest.qcow2 -sev-snp -svsm svsm.bin -svsmcrb -ssh-forward
[guest@snp-guest ~]# dmesg | grep VMPL
[    1.264552] SEV: SNP running at VMPL1.
```

The -ssh-forward allow you to ssh to the guest from the host. For example, the
default port is 5555:
```
$ ssh -p 5555 <user>@localhost
```
Once the SVSM guest is up, you can also check it has a tpm device with
an EK pub (ALG_SHA256); your EK pub will likely be different though
since the SVSM generates a new one on every guest boot:

```
[guest@snp-vtpm-guest:~]$ sudo apt install tpm2-tools
[guest@snp-vtpm-guest:~]$ sudo tpm2_getcap handles-persistent
- 0x81010001
[guest@snp-vtpm-guest:~]$ sudo tpm2_readpublic -c 0x81010001 -o ek_pub_rsa -f pem
name: 000bdf34d36f79a14d1a3ef79fb266e20575ace4b44dcc73042020086d8963f973f3
qualified name: 000b3a5f427dfa526dab73754790f88487769a626472394c9e3c422ca1efa38bf63e
name-alg:
  value: sha256
  raw: 0xb
attributes:
  value: fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|restricted|decrypt
  raw: 0x300b2
type:
  value: rsa
  raw: 0x1
exponent: 65537
bits: 2048
scheme:
  value: null
  raw: 0x10
scheme-halg:
  value: (null)
  raw: 0x0
sym-alg:
  value: aes
  raw: 0x6
sym-mode:
  value: cfb
  raw: 0x43
sym-keybits: 128
rsa: e731aa6151be2c57b2313da03e7ffcb723c83ac689d273edd47acca079d45bc221c9b9a3a3313d96f65ea47d1f344a5897d4227fe89ac46820a69a4db0ad4b756d11481aad20b9b9a7aad75e5b3ec3d56632786e3cdab563fa2a245cb143eb46a3dc018518c397b93f27c047df6c188d4ccb2512e16951d121834539ffc9968e8d2eef54e1e436ce4a06b3aaf3670d1eac318d4b72722a4719d3ab241a8d4829f83feb19961aa892f5ac0c46101c6848348ae577db48e53fb4df3132a7e1c5a19fd8119b3c39baa1d93af69e9c9a0146e7275eb8f230328817c759f5ab8b7a0e1d6430048b0c34e7aef62d7f42f34b41780bc094660af97a6578fc0a5453970d
authorization policy: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
[guest@snp-vtpm-guest:~]$ sudo cat ek_pub_rsa
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5zGqYVG+LFeyMT2gPn/8
tyPIOsaJ0nPt1HrMoHnUW8IhybmjozE9lvZepH0fNEpYl9Qif+iaxGggpppNsK1L
dW0RSBqtILm5p6rXXls+w9VmMnhuPNq1Y/oqJFyxQ+tGo9wBhRjDl7k/J8BH32wY
jUzLJRLhaVHRIYNFOf/Jlo6NLu9U4eQ2zkoGs6rzZw0erDGNS3JyKkcZ06skGo1I
Kfg/6xmWGqiS9awMRhAcaEg0iuV320jlP7TfMTKn4cWhn9gRmzw5uqHZOvaenJoB
RucnXrjyMDKIF8dZ9auLeg4dZDAEiww05672LX9C80tBeAvAlGYK+XplePwKVFOX
DQIDAQAB
-----END PUBLIC KEY-----
[guest@snp-vtpm-guest:~$]
```

By default, SVSM lives at 512 GB (SVSM\_GPA), and has 256 MB of memory
(SVSM\_MEM). This can be changed at compilation. For example:

```
# make SVSM_GPA=0x90000000 SVSM_MEM=0x20000000
```

## Contribution <a name="contribute"></a>

Please read CONTRIBUTING.md for instructions on contribution and style.

## Authors and License <a name="authors"></a>

The main authors and maintainers of this software are:

- [Thomas Lendacky](https://github.com/tlendacky)
- [Carlos Bilbao](https://github.com/Zildj1an)

They will act as reviewers for future contributions.

Linux SVSM is distributed under the MIT license. For more information, read
file LICENSE.
