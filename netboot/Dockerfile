#
# Sample Dockerfile to build PXE-style boot image for KVM on s390
#

FROM s390x/ubuntu:16.04

RUN apt-get update && apt-get install -y \
	linux-image-4.4.0-78-generic \
	make \
	wget \
	bzip2 \
	linux-headers-4.4.0-78-generic \
	gcc \
	kexec-tools \
	file

RUN mkdir /netboot

COPY . /netboot

RUN cd /netboot && make -f Makefile.pxelinux.0 KERNEL_VERSION=4.4.0-78-generic
