# Vulkan

Vulkan dumps the main PE image of a process from memory to your disk. It targets processes protected by dynamic code encryption, implemented by the [hyperion](https://roblox.fandom.com/wiki/Hyperion) and [theia](https://reversingthread.info/index.php/2024/01/10/the-finals-defeating-theia-packer/) anti-tamper solutions. Once launched, Vulkan will monitor all pages of code and cache them as they are decrypted by the anti-tamper. After a desired amount of the application has been decrypted (read more [here](#decryption)), the restored PE image is saved to the disk and ready for analysis.

Vulkan has been tested on [Roblox](https://roblox.com) and [The Finals](https://www.reachthefinals.com/).

## How to use

After downloading the latest version from the [releases](https://github.com/atrexus/vulkan/releases) tab, you can run it from the command line like so:

```
vulkan.exe -p <TARGET_PROCESS> -o <OUTPUT_DIRECTORY>
```

If no output directory is specified, the file will be saved to the current working directory (`.`). 

An optional `-D` parameter can also be specified if you want to run Vulkan in debug mode. This will prevent any regular user-mode application from querying information about Vulkan.

Another optional parameter `-t` can be used to add a timestamp to the output file. For example, if your output file is named `program.exe`, and you run Vulkan with the `-t` option, the file will be saved as `program_2024-09-08.exe`

### Decryption

By default, the decryption factor is set to `1.0`, meaning the dumping process will only conclude once all the application's code has been decrypted. This can take an incredibly long time, so if at any moment you want to terminate the current decryption task, use `Ctrl+C` in the terminal, and the dump will be saved as is.

If you want to set the target decryption factor manually, you can do it from the command line like so:

```
vulkan.exe -p <TARGET_PROCESS> -o <OUTPUT_DIRECTORY> --decrypt <TARGET_FACTOR>
```

> **Note**: Increasing the decryption factor will significantly increase the time it takes to produce the dump. It is recommended that the factor be between `0.6` and `0.7`.

## Contributing

If you have anything to contribute to this project, please send a pull request, and I will review it. If you want to contribute but are unsure what to do, check out the [issues](https://github.com/atrexus/vulkan/issues) tab for the latest stuff I need help with.

## Changes made after fork
- Moved code to c++
- Dynamically patch int3 and other instructions which break analysis on Binary Ninja, as it is my main disassembler
- Dump all modules in the target process and dump them as if they were encrypted.
- Sections are copied from the remote process parallely

## Todo
- When dumping all modules, validate that the BaseAddress is the same as in the current; if so do not dump, as then there would be no changes done to the DLL (Most likely)
- Port to ImGui

These changes were somewhat lazily done, which makes it have some bugs, however as Atrexus (The original author of Vulkan) has rewritten his project on C++, this project proves to no longer be of use.

Because of it this project is no longer maintained, and I will make a new fork with the changes Atrexus has put forth, however with an ImGui as a front end and perhaps some other feature i may think of later.