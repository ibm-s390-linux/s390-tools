# Setup

## Production kernel's root file system

- kdump mounts the production kernel's root file system under **/**.

## debugfs

- kdump mounts debugfs automatically.

## Dependencies

```shell
sudo apt-get install -y make gcc kdump-tools fuse libfuse-dev libsystemd-dev
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
mount_debugfs = 0
hsa_size = 0x1ffff000
release_hsa = 0
bind_mount_vmcore = 1
EOF
```

#### HSA cache in memory

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /var/crash
use_hsa_mem = 1
mount_debugfs = 0
hsa_size = 0x1ffff000
release_hsa = 0
bind_mount_vmcore = 1
swap = /var/crash/swap.img
EOF
```

### Production configuration

- Works only on s390x

#### HSA cache in file

```shell
cat <<EOF | sudo tee /etc/hsavmcore.conf
verbose = 2
workdir = /var/crash
use_hsa_mem = 0
mount_debugfs = 0
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
mount_debugfs = 0
hsa_size = -1
release_hsa = 1
bind_mount_vmcore = 1
swap = /var/crash/swap.img
EOF
```

## Install new dracut module

```shell
sudo cp s390-tools/hsavmcore/initramfs/ubuntu/hsavmcore.service /usr/lib/systemd/system/
```

## Add the new systemd service as a dependency to the service *kdump-tools-dump*

```shell
Wants=network-online.target dbus.socket systemd-resolved.service hsavmcore.service
After=network-online.target dbus.socket systemd-resolved.service hsavmcore.service

sudo sed -e 's/Wants=\(.*\)$/Wants=\1 hsavmcore.service/' \
         -e 's/After=\(.*\)$/After=\1 hsavmcore.service/' \
         -i /usr/lib/systemd/system/kdump-tools-dump.service
```

## Rebuild kdump initramfs

```shell
sudo rm -rf /var/lib/kdump/initrd*
sudo kdump-config unload
sudo kdump-config load
sudo systemctl restart kdump-tools
```

## Reload kdump

```shell
sudo kdump-config unload
sudo kdump-config load
```

# Test

```shell
echo N | sudo tee /sys/module/kernel/parameters/crash_kexec_post_notifiers
echo c | sudo tee /proc/sysrq-trigger
```
