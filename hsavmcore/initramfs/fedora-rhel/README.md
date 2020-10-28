
# Setup

## Configure crashkernel

```shell
sudo grubby --args "crashkernel=512M" --update-kernel=ALL
sudo reboot
```

## Production kernel's root file system

- kdump mounts the production kernel's root file system under **/sysroot**.

## Dependencies

```shell
sudo dnf install -y fuse fuse-devel systemd-devel
```

## Build hsavmcore

```shell
make -C s390-tools/hsavmcore
```

## Install hsavmcore

```shell
sudo cp s390-tools/hsavmcore/hsavmcore /usr/sbin/
```

## Create swap file

```shell
sudo dd if=/dev/zero of=/var/crash/swap.img bs=1M count=1024
sudo mkswap /var/crash/swap.img
```

## Install hsavmcore.conf

### Test configuration

- Doesn't require HSA support

#### HSA cache in file

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /sysroot/var/crash
use_hsa_mem = 0
mount_debugfs = 1
hsa_size = 0x1ffff000
release_hsa = 0
bind_mount_vmcore = 1
EOF
```

#### HSA cache in memory

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /sysroot/var/crash
use_hsa_mem = 1
mount_debugfs = 1
hsa_size = 0x1ffff000
release_hsa = 0
bind_mount_vmcore = 1
swap = /sysroot/var/crash/swap.img
EOF
```

### Production configuration

- Works only on s390x

#### HSA cache in file

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /sysroot/var/crash
use_hsa_mem = 0
mount_debugfs = 1
hsa_size = -1
release_hsa = 1
bind_mount_vmcore = 1
EOF
```

#### HSA cache in memory

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /sysroot/var/crash
use_hsa_mem = 1
mount_debugfs = 1
hsa_size = -1
release_hsa = 1
bind_mount_vmcore = 1
swap = /sysroot/var/crash/swap.img
EOF
```

## Install new dracut module

```shell
sudo cp -r s390-tools/hsavmcore/initramfs/fedora-rhel/dracut/modules.d/99hsavmcore /lib/dracut/modules.d/
```

## Add the new dracut module as a dependency to the dracut module *kdumpbase*

```shell
sudo sed -e 's#local _dep="base shutdown"#local _dep="base shutdown hsavmcore"#' \
         -i /lib/dracut/modules.d/99kdumpbase/module-setup.sh
```

## Rebuild kdump initramfs

```shell
sudo kdumpctl rebuild
```

## Enable swap LVM in kdump

- Required if you want to use a swap device in kdump

```shell
sudo sed -e 's#^KDUMP_COMMANDLINE_APPEND="\(.*\)"$#KDUMP_COMMANDLINE_APPEND="\1 rd.lvm.lv=rhel/swap"#' \
         -i /etc/sysconfig/kdump
```

## Reload kdump

```shell
sudo kdumpctl reload
```

# Test

```shell
echo N | sudo tee /sys/module/kernel/parameters/crash_kexec_post_notifiers
echo c | sudo tee /proc/sysrq-trigger
```
