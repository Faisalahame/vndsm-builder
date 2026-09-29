# vndsm-builder

Builds a 32-bit-binder-ABI `vndservicemanager` (static ARM32) for the Galaxy A2 Core
(a2corelte) H-VENDOR package. Stock vendor binary uses the 64-bit binder ABI and cannot
talk to the kernel's 32-bit binder, so /dev/vndbinder never gets a context manager.

## Use
1. Create a GitHub repo, upload `vndsm.c`, `README.md` and `.github/workflows/build.yml`
   (keep the folder path exactly).
2. Actions tab -> "build-vndservicemanager" -> Run workflow.
3. When it is green, open the run -> Artifacts -> download `vndservicemanager`.
   The run only goes green if the ARM binary passes its own self-test under qemu.
4. Send the downloaded zip (or the extracted `vndservicemanager` file) back for the v1.7 package.
