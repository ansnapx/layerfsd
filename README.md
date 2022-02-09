# Overview

LFS is layered file system driver for Windows. LFS stays above any existing
file systems (NTFS, ExFat, Ext2Fsd etc) and can intercept and interpret all
i/o requests.

LFS is a complete Windows installable file system driver implementation. It
can hide all underlying file systems and then form a new namespace, providing
more powerful naming and data manipulation than Windows filter driver or mini-
filter driver solutions. All underlying file systems can be treated as object-
based units of LFS. When a user i/o request arrives at LFS, LFS knows how to
interpret and which underlying file system driver to talk to and where to lead
the data streams.

## Architecture

![image](https://user-images.githubusercontent.com/79788735/153116178-c1a1ec3a-b8a6-48b4-81b0-3bea31363165.png)

