asymmetricfs Program Options
==============================

Memory Locking Options
----------------------

`--memory-lock` controls the memory locking strategy used for allocations.
There are 3 options:

* `all`:  `mlockall` is specified early during startup.  Any errors returned
  lead to program termination.
* `buffers`: Internal file buffers are locked, but temporary buffers obtained
  from FUSE may not be.  Failures to acquire locked memory may lead to write
  errors during filesystem usage.
* `none`: No memory locking is done.  This is the *least secure option*, as
  file contents may be inadvertently paged to disk *unencrypted*.
