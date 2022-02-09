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

Typical working modes of LFS:

*)  Passthru
    LFS just intercepts and monitors all i/o requests (irp), but doesn't re-
    interprect or modify any one

*)  Proxy
    LFS does re-interpretion for pattern-based requests. A pattern could be a
    match of specified files or directories, content keywords or signatures,
    pre-defined set of processes etc

*） Object Storage
    Underlying file systems and volumes are treated as object-based storages,
    and LFS *DOES* take over whole namespace management and data manipulation,
    then to implement file-level RAID, replication, COW or snapshots.
    
