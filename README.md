# bn-kallsyms ![Python Lint](https://github.com/zznop/bn-kallsyms/workflows/pylint/badge.svg)

## Description:

Binary Ninja plugin for importing symbols to a kernel binary from /proc/kallsyms

**Before loading kernel symbols:**

![Before kallsyms import](screens/before.png "Before:")

**After loading kernel symbols:**

![After kallsyms import](screens/after.png "After:")

## License

This plugin is released under a [MIT](LICENSE) license.

## Generating a kernel symbols file

To generate a kernel symbols file run the following command:
```
sudo sh -c "echo 0  > /proc/sys/kernel/kptr_restrict" && sudo cat /proc/kallsyms > kallsyms.txt
```

## Importing the kernel symbols

To use this plugin, ensure the kernel binary is decompressed. If it is a bzImage kernel, use binwalk:

```
$ binwalk -e vmlinuz-4.13.0-43-generic
...
$ file ~/_vmlinuz-4.13.0-43-generic.extracted/47B4
/home/joe/_vmlinuz-4.13.0-43-generic.extracted/47B4: elf 64-bit lsb executable, x86-64, version 1 (sysv), statically linked, buildid[sha1]=3e0dc1c8b93e2f3f522a596cfc4b482065469041, stripped
```

Load the kernel binary into Binary Ninja. Then, click `tools->"kallsyms: apply kernel symbols"`. You will be
prompted to select the kernel symbols file. Select it, and click "open". the plugin will proceed to parse
the kernel symbol file, create functions, and import symbols into the database.
