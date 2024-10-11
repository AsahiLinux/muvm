# muvm - run programs from your system in a microVM

`muvm` allows you to run arbitrary programs from your system in a microVM. It's comprised of three small programs:

- `muvm`: links against [libkrun](https://github.com/containers/libkrun) to create the microVM.

- `muvm-guest`: acts as an entrypoint inside the microVM to set up the environment for running your program.

- `muvm-server`: a server listening for requests to run additional programs. This allows you to run multiple graphical applications inside the same microVM.

## Using

``` sh
Usage: muvm [-c=CPU_LIST]... [-e=ENV]... [--mem=MEM] [--vram=VRAM] [--passt-socket=PATH] [-p=
SERVER_PORT] [-f=FEX_IMAGE]... COMMAND [COMMAND_ARGS]...

Available positional items:
    COMMAND                  the command you want to execute in the vm
    COMMAND_ARGS             arguments of COMMAND

Available options:
    -c, --cpu-list=CPU_LIST  The numerical list of processors that this microVM will be bound to.
                                     Numbers are separated by commas and may include ranges. For
                                     example: 0,5,8-11.
                             [default: all logical CPUs on the host, limited to performance cores
                                 (if applicable)]
    -e, --env=ENV            Set environment variable to be passed to the microVM
                                     ENV should be in KEY=VALUE format, or KEY on its own to inherit
                                     the current value from the local environment
        --mem=MEM            The amount of RAM, in MiB, that will be available to this microVM.
                                     The memory configured for the microVM will not be reserved
                                     immediately. Instead, it will be provided as the guest demands
                                     it, and both the guest and libkrun (acting as the Virtual
                                     Machine Monitor) will attempt to return as many pages as
                                     possible to the host.
                             [default: 80% of total RAM]
        --vram=VRAM          The amount of Video RAM, in MiB, that will be available to this
                             microVM.
                                     The memory configured for the microVM will not be reserved
                                     immediately. Instead, it will be provided as the guest demands
                                     it, and will be returned to the host once the guest releases
                                     the underlying resources.
                             [default: same as the total amount of RAM in the system]
        --passt-socket=PATH  Instead of starting passt, connect to passt socket at PATH
    -p, --server-port=SERVER_PORT  Set the port to be used in server mode
                             [default: 3334]
    -f, --fex-image=FEX_IMAGE  Adds an erofs file to be mounted as a FEX rootfs.
                                     May be specified multiple times.
                                     First the base image, then overlays in order.
    -h, --help               Prints help information
```

## Running graphical applications

If [sommelier](https://chromium.googlesource.com/chromiumos/platform2/+/main/vm_tools/sommelier) is installed in your system, `muvm` will use it to connect to the Wayland session on the hosts, allowing you to run graphical applications in the microVM.

GPU acceleration is also enabled on systems supporting [DRM native context](https://indico.freedesktop.org/event/2/contributions/53/attachments/76/121/XDC2022_%20virtgpu%20drm%20native%20context.pdf) (freedreno, amdgpu, asahi).

## Running x86/x86_64 on aarch64

If [FEX-Emu](https://fex-emu.com/) is installed in your system, `muvm` will configure `binfmt_misc` inside the microVM so x86/x86_64 programs can be run transparently on it.

## Motivation

This tool is mainly intended to enable users to easily run programs designed for 4K-page systems on systems with a different page size, with [Asahi Linux](https://asahilinux.org/) being the prime example of this use case.

Other potential use cases could be software isolation, accessing privileged kernel features (provided by the guest) or local testing.
