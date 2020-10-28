
# Setup

## Configure crashkernel

```shell
sudo vim /etc/default/grub
sudo sed -e 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 crashkernel=512M"/' \
         -i /etc/default/grub
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
sudo reboot
```

## Production kernel's root file system

- kdump mounts the production kernel's root file system under **/kdump/mnt1**.

## Dependencies

```shell
sudo zypper install -y fuse fuse-devel systemd-devel
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
workdir = /kdump/mnt1/var/crash
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
workdir = /kdump/mnt1/var/crash
use_hsa_mem = 1
mount_debugfs = 1
hsa_size = 0x1ffff000
release_hsa = 0
bind_mount_vmcore = 1
swap = /kdump/mnt1/var/crash/swap.img
EOF
```

### Production configuration

- Works only on s390x

#### HSA cache in file

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /kdump/mnt1/var/crash
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
workdir = /kdump/mnt1/var/crash
use_hsa_mem = 1
mount_debugfs = 1
hsa_size = -1
release_hsa = 1
bind_mount_vmcore = 1
swap = /kdump/mnt1/var/crash/swap.img
EOF
```

## Install new dracut module

```shell
sudo cp -r s390-tools/hsavmcore/initramfs/sles/dracut/modules.d/99hsavmcore /usr/lib/dracut/modules.d/
```

## Add the new dracut module as a dependency to the dracut module *kdump*

```shell
sudo sed -e 's/_modules\[drm\]=/_modules[drm]=\n    _modules[hsavmcore]=/' \
         -i /usr/lib/dracut/modules.d/99kdump/module-setup.sh
```

## Rebuild kdump initramfs

```shell
sudo mkdumprd -f
```

## Reload kdump

```shell
systemctl enable kdump
systemctl restart kdump
```

# Test

```shell
echo c | sudo tee /proc/sysrq-trigger
```
