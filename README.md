

# McSema [![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)
<p align="center">
     <img src="docs/images/mcsema_logo.png" />
</p>

McSema is an executable lifter. It translates ("lifts") executable binaries from native machine code to LLVM bitcode. LLVM bitcode is an [intermediate representation](https://en.wikipedia.org/wiki/Intermediate_representation) form of a program that was originally created for the [retargetable LLVM compiler](https://llvm.org), but which is also very useful for performing program analysis methods that would not be possible to perform on an executable binary directly.

McSema enables analysts to find and retroactively harden binary programs against security bugs, independently validate vendor source code, and generate application tests with high code coverage. McSema isn’t just for static analysis. The lifted LLVM bitcode can also be [fuzzed with libFuzzer](https://github.com/trailofbits/mcsema/blob/master/docs/UsingLibFuzzer.md), an LLVM-based instrumented fuzzer that would otherwise require the target source code. The lifted bitcode can even be [compiled](https://github.com/trailofbits/mcsema/blob/master/docs/UsingLibFuzzer.md) back into a [runnable program](https://github.com/trailofbits/mcsema/blob/master/docs/McSemaWalkthrough.md)! This is a procedure known as static binary rewriting, binary translation, or binary recompilation.

McSema supports lifting both Linux (ELF) and Windows (PE) executables, and understands most x86 and amd64 instructions, including integer, X87, MMX, SSE and AVX operations. AARCH64 (ARMv8) instruction support is in active development.

Using McSema is a two-step process: control flow recovery, and instruction translation. Control flow recovery is performed using the `mcsema-disass` tool, which relies on IDA Pro, Binary Ninja, or DynInst to disassemble a binary file and produce a control flow graph. Instruction translation is then performed using the `mcsema-lift` tool, which converts the control flow graph into LLVM bitcode. Under the hood, the instruction translation capability of `mcsema-lift` is implemented in the [`remill` library](https://github.com/trailofbits/remill). The development of `remill` was a result of refactoring and improvements to McSema, and was first introduced with McSema version 2.0.0. Read more about `remill` [here](https://github.com/trailofbits/remill).

McSema and `remill` were developed and are maintained by Trail of Bits, funded by and used in research for DARPA and the US Department of Defense.

## Build status

|       | master                                   |
| ----- | ---------------------------------------- |
| Linux | [![Build Status](https://travis-ci.org/trailofbits/mcsema.svg?branch=master)](https://travis-ci.org/trailofbits/mcsema) |

## Features

* Lifts 32- and 64-bit Linux ELF and Windows PE binaries to bitcode, including executables and shared libraries for each platform.
* Supports a large subset of x86 and x86-64 instructions, including most integer, X87, MMX, SSE, and AVX operations.
* McSema runs on Windows and Linux and has been tested on Windows 7, 10, Ubuntu (14.04, 16.04), and openSUSE.
* McSema can cross-lift: it can translate Linux binaries on Windows, or Windows binaries on Linux.
* Output bitcode is compatible with the LLVM toolchain (versions 3.5 and up).
* Translated bitcode can be analyzed or [recompiled as a new, working executable](docs/McSemaWalkthrough.md) with functionality identical to the original.

## Use-cases

Why would anyone translate binaries *back* to bitcode?

* **Binary Patching And Modification**. Lifting to LLVM IR lets you cleanly modify the target program. You can run obfuscation or hardening passes, add features, remove features, rewrite features, or even fix that pesky typo, grammatical error, or insane logic. When done, your new creation can be recompiled to a new binary sporting all those changes. In the [Cyber Grand Challenge](https://blog.trailofbits.com/2015/07/15/how-we-fared-in-the-cyber-grand-challenge/), we were able to use McSema to translate challenge binaries to bitcode, insert memory safety checks, and then re-emit working binaries.

* **Symbolic Execution with KLEE**. [KLEE](https://klee.github.io/) operates on LLVM bitcode, usually generated by providing source to the LLVM toolchain. McSema can lift a binary to LLVM bitcode, [permitting KLEE to operate on previously unavailable targets](https://blog.trailofbits.com/2014/12/04/close-encounters-with-symbolic-execution-part-2/). See our [walkthrough](examples/Maze/README.md) showing how to run KLEE on a symbolic maze.

* **Re-use existing LLVM-based tools**. KLEE is not the only tool that becomes available for use on bitcode. It is possible to run LLVM optimization passes and other LLVM-based tools like [libFuzzer](http://llvm.org/docs/LibFuzzer.html) on [lifted bitcode](docs/UsingLibFuzzer.md).

* **Analyze the binary rather than the source**. Source level analysis is great but not always possible (e.g. you don't have the source) and, even when it is available, it lacks compiler transformations, re-ordering, and optimizations. Analyzing the actual binary guarantees that you're analyzing the true executed behavior.

* **Write one set of analysis tools**. Lifting to LLVM IR means that one set of analysis tools can work on both the source and the binary. Maintaining a single set of tools saves development time and effort, and allows for a single set of better tools.

## Comparison with other machine code to LLVM bitcode lifters
|   | McSema | [dagger](https://github.com/repzret/dagger) | [llvm-mctoll](https://github.com/Microsoft/llvm-mctoll) | [retdec](https://github.com/avast-tl/retdec) | [reopt](https://github.com/GaloisInc/reopt) | [rev.ng](https://github.com/revng/revamb) | [bin2llvm](https://github.com/cojocar/bin2llvm) | [fcd](https://github.com/zneak/fcd) | [RevGen](https://github.com/S2E/tools/tree/master/tools) | [Fracture](https://github.com/draperlaboratory/fracture) | [libbeauty](https://github.com/jcdutton/libbeauty) |
|  ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ | ------ |
|  Actively maintained? | Yes | No | Yes | Yes | Yes | No | Maybe | Maybe | Maybe | No | Yes |
|  Commercial support available? | Yes | No | No | No | Maybe | No | No | No | No | Maybe | No |
|  LLVM versions | 3.5 - current | 5 | current | 3.9.1 | 3.8 | 3.8 | 3.2 | 4 | 3.9 | 3.4 | 6 |
|  Builds with CI? | Yes | No | No | Yes | No | No | Yes | Maybe | Maybe | No | No |
|  32-bit architectures | x86 | x86 | ARM | x86, ARM, MIPS, PIC32, PowerPC |  | ARM, MIPS | S2E | S2E | S2E | ARM, x86 |  |
|  64-bit architectures | x86-64, AArch64 | x86-64 | x86-64 |  | x86-64 | x86-64 |  | S2E | S2E | PowerPC | x86-64 |
|  Control-flow recovery | IDA Pro, Binary Ninja, DynInst | Ad-hoc | Ad-hoc | Ad-hoc | Ad-hoc | Ad-hoc | Ad-hoc | Ad-hoc | McSema | Ad-hoc | Ad-hoc |
|  File formats | ELF, PE | ELF, Mach-O |  | ELF, PE, Mach-O, COFF, AR, Intel HEX, Raw | ELF | ELF | ELF |  | ELF, PE | ELF, Mach-O (maybe) | ELF |
|  Bitcode is executable? | Yes | Yes | Yes | Yes | Yes | Yes | No | No | CGC | No | No |
|  C++ exceptions suport? | Yes | No | No | No | No | Indirectly | No | No | No | No | Maybe |
|  Lifts stack variables? | Yes | No | Maybe | Yes | No | No | No | Yes | No | No | Maybe |
|  Lifts global variables? | Yes | Maybe | Yes | Yes | No | Maybe | No | No | No | Yes | Maybe |
|  Has a test suite? | Yes | No | Yes | Yes | Yes | Yes | Yes | Yes | No | Yes | No |
|  Usabele for grammar recovery? | Yes | Trouble with recompiling | No makefiles after cmake | No X86_64 | Requires GHC and no longer builds | ? | No | No | No | No | No |

**Note:** We label some architectures as "S2E" to mean any architecture supported by the S2E system. A system using "McSema" for control-flow recovery (e.g. RevGen) uses McSema's CFG.proto format for recovering control-flow. In the case of RevGen, only bitcode produced from DARPA Cyber Grand Challenge (CGC) binaries is executable.

## Dependencies

| Name | Version | 
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.2+ |
| [Google Protobuf](https://github.com/google/protobuf) | 2.6.1 |
| [Google Flags](https://github.com/google/glog) | Latest |
| [Google Log](https://github.com/google/glog) | Latest |
| [Google Test](https://github.com/google/googletest) | Latest |
| [Intel XED](https://github.com/intelxed/xed) | Latest |
| [LLVM](http://llvm.org/) | 3.5+ |
| [Clang](http://clang.llvm.org/) | 3.5+ |
| [Python](https://www.python.org/) | 2.7 | 
| [Python Package Index](https://pypi.python.org/pypi) | Latest |
| [python-protobuf](https://pypi.python.org/pypi/protobuf) | 3.2.0 |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 6.7+ |

## Getting and building the code

### Docker

#### Step 1: Download Dockerfile

`wget https://raw.githubusercontent.com/trailofbits/mcsema/master/tools/Dockerfile`

#### Step 2: Add your disassembler

Currently IDA and BinaryNinja are supported for control-flow recovery, it's left as an exercise to the reader to install your disassembler of choice, but an example of installing BinaryNinja is provided (remember for Docker that paths need to be relative to where you built from):
```
ADD local-relative/path/to/binaryninja/ /root/binaryninja/
ADD local-relative/path/to/.binaryninja/ /root/.binaryninja/ # <- Make sure there's no `lastrun` file
RUN /root/binaryninja/scripts/linux-setup.sh
```

#### Step 3: Build & Run Dockerfile

This will build the container for you and run it with your local directory mounted into the container (at /home/user/local) such that your work in the container is saved locally: 
`docker build -t=mcsema . && docker run --rm -it --ipc=host -v "${PWD}":/home/user/local mcsema`

### On Linux

#### Step 1: Install dependencies

```shell
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     curl \
     cmake \
     python2.7 python-pip python-virtualenv \
     wget \
     build-essential \
     gcc-multilib g++-multilib \
     libtinfo-dev \
     lsb-release \
     realpath \
     zlib1g-dev
```

If you are going to be using IDA Pro for CFG recovery also do the following:

```shell
sudo dpkg --add-architecture i386
sudo apt-get install zip zlib1g-dev:i386
```

#### Step 1.5 (Optional): Create a virtualenv for your mcsema installation

Using a [virtualenv](https://virtualenv.pypa.io/en/stable/) ensures that your mcsema installation does not interfere with other software packages. This setup is especially helpful if you are hacking on mcsema and want to avoid clobbering a global, working version with development code.

```shell
mkdir mcsema-ve
virtualenv mcsema-ve
cd mcsema-ve
source bin/activate
``` 
##### Fixing IDA Pro's Python installation (Ubuntu 14.04)

Note: If you are using IDA on 64 bit Ubuntu and your IDA install does not use the system Python, you can add the `protobuf` library manually to IDA's zip of modules.

```shell
# Python module dir is generally in /usr/lib or /usr/local/lib
IDAPYTHON=/home/$USER/ida-6.9/python/lib/python27.zip
GOOGLEMODULE=$(python -c "import os; import sys; import google; sys.stdout.write(os.path.dirname(google.__file__))")
pushd ${GOOGLEMODULE}/..
chmod +w ${IDAPYTHON}
zip -rv ${IDAPYTHON} google/
chmod -w ${IDAPYTHON}
popd
```

#### Step 2: Clone the repository

The next step is to clone the [Remill](https://github.com/trailofbits/remill) repository. We then clone the McSema repository into the `tools` subdirectory of Remill. This is kind of like how Clang and LLVM are distributed separately, and the Clang source code needs to be put into LLVM's tools directory.

**Notice that when building McSema, you should always use a specific Remill commit hash (the one we test). This hash can be found in the .remill_commit_id file**.

```shell
git clone --depth 1 https://github.com/trailofbits/mcsema.git
export REMILL_VERSION=`cat ./mcsema/.remill_commit_id`

git clone https://github.com/trailofbits/remill.git
cd remill
git checkout -b temp ${REMILL_VERSION}

mv ../mcsema tools
```

#### Step 3: Build McSema

McSema is a kind of sub-project of Remill, similar to how Clang is a sub-project of LLVM. To that end, we invoke Remill's build script to build both Remill and McSema. It will also download all remaining dependencies needed by Remill.

The following script will build Remill and McSema into the `remill-build` directory, which will be placed in the current working directory.

```shell
if [ -z "${VIRTUAL_ENV}" ]
then
  # no virtualenv; global install for all users
  ./scripts/build.sh
else
  # found a virtualenv; local install
  ./scripts/build.sh --prefix $(realpath ../)
fi
```

This script accepts several command line options:

* `--prefix PATH`: Install files to `PATH`. By default, `PATH` is `/usr/local`.
* `--llvm-version MAJOR.MINOR`: Download pre-built dependencies for LLVM version MAJOR.MINOR. The default is to use LLVM 4.0.
* `--build-dir PATH`: Produce all intermediate build files in `PATH`. By default, `PATH` is `$CWD/remill-build`.
* `--use-system-compiler`: Compile Remill+McSema using the system compiler toolchain (typically the GCC).

#### Step 4: Install McSema

The next step is to build the code.

```shell
cd remill-build
if [ -z "${VIRTUAL_ENV}" ]
then
  # no virtualenv; global install for all users requires sudo
  sudo make install
else
  # found a virtualenv; local install does not need root
  make install
fi
```

Once installed, you may use `mcsema-disass` for disassembling binaries, and `mcsema-lift-4.0` for lifting the disassembled binaries. If you specified `--llvm-version 3.6` to the `build.sh` script, then you would use `mcsema-lift-3.6`.

#### Step 5: Verifying Your McSema Installation

In order to verify that McSema works correctly as built, head on over to [the documentation on integration tests](tests/MakingTests.md). Check that you can run the tests and that they pass.

### On Windows
#### Step 1: Installing the toolchain
**Visual Studio**
1. Download the "Build Tools for Visual Studio 2017" installer from the following page: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2017
2. Run the setup and select "Visual C++ build tools"

**LLVM**
1. Get the LLVM 7.0.1 (x64) installer from the LLVM download page: http://releases.llvm.org
2. Do **NOT** enable "Add to PATH"
3. Download the LLVM integration addon from the VS marketplace: https://marketplace.visualstudio.com/items?itemName=LLVMExtensions.llvm-toolchain
4. Extract the '.vsix' archive as a ZIP archive, and copy the files within the `$VCTargets` folder to `C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\Common7\IDE\VC\VCTargets`

**Python**
1. Get the latest Python 2.7 (X64) installer from the official download page: https://www.python.org/downloads/windows/
2. Enable "Add to PATH" when possible

**CMake**
1. Download the CMake (x64) installer from https://cmake.org/download
2. Enable "Add to PATH" when possible

#### Step 2: Obtaining the source code
```
git clone https://github.com/trailofbits/remill.git --depth=1
git clone https://github.com/trailofbits/mcsema.git --depth=1 remill/tools/mcsema
```

Note that for production usage you should always use a specific remill commit (`remill/tools/mcsema/.remill_commit_id`) when building mcsema. At the time of writing, it is however best to use HEAD (or at least make sure that commit `e7795be` is present in the remill branch).

```
cd remill
git fetch --unshallow
git checkout -b production `cat tools/mcsema/.remill_commit_id`
```

#### Step 3: Dependencies
You can either build them yourself using our [cxx-common](https://github.com/trailofbits/cxx-common) dependency manager or download a pre-built package.
Only the LLVM 5.0.1 package is supported right now, and you should build it using the Visual Studio 2017 Win64 generator with the LLVM 5.0.1 toolchain. The cxx-common script will automatically take care of this requirement.

Binaries (extract to C:\Projects\tob_libraries)
* [LLVM 5](https://s3.amazonaws.com/cxx-common/libraries-llvm50-windows10-amd64.7z)

#### Step 4: Building
Make sure to always execute the `vcvars64.bat` script from the "x64 Native Tools Command Prompt": `C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvars64.bat`.

```
mkdir remill_build
cd remill_build

cmake -G "Visual Studio 15 2017" -T llvm -A x64 -DCMAKE_BUILD_TYPE=Release -DLIBRARY_REPOSITORY_ROOT=C:\Projects\tob_libraries -DCMAKE_INSTALL_PREFIX=C:\ ..\remill
cmake --build . --config Release -- /maxcpucount:4
```

If you are using a recent CMake version (> 3.13) you can also use the newly introduced cross-platform `-j` parameter:

```
cmake --build . --config Release -j 4
```

#### Step 5: Installing
```
cmake --build . --config Release --target install
```

You should now have the following directories: C:\mcsema, C:\remill.

Add the following folders to your PATH environment variable:
* C:\remill\bin
* C:\mcsema\Scripts
* C:\mcsema\bin

Also update your PYTHONPATH: C:\mcsema\Lib\site-packages

## Additional Documentation

* [McSema command line reference](docs/CommandLineReference.md)
* [Common Errors](docs/CommonErrors.md) and [Debugging Tips](docs/DebuggingTips.md)
* [How to add support for a new instruction](https://github.com/trailofbits/remill/blob/master/docs/ADD_AN_INSTRUCTION.md)
* [How to use McSema: A walkthrough](docs/McSemaWalkthrough.md)
* [Life of an instruction](docs/LifeOfAnInstruction.md)
* [Limitations](docs/Limitations.md)
* [Navigating the source code](docs/NavigatingTheCode.md)
* [Using McSema with libFuzzer](docs/UsingLibFuzzer.md)

## Getting help

If you are experiencing problems with McSema or just want to learn more and contribute, join the `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/). Alternatively, you can join our mailing list at [mcsema-dev@googlegroups.com](https://groups.google.com/forum/?hl=en#!forum/mcsema-dev) or email us privately at mcsema@trailofbits.com.

## FAQ

### How do you pronounce McSema and where did the name come from

This is a hotly contested issue. We must explore the etymology of the name to find an answer. The "Mc" in McSema was originally a contraction of the words "Machine Code," and the "sema" is short for "semantics." At that time, McSema used LLVM's instruction decoder to take machine code bytes, and turn them into `llvm::MCInst` data structures. It is possible that "MC" in that case is pronounced em-see. Alas, even those who understand the origin of the name pronounce it as if it were related to America's favorite fast food joint.

### Why do I need IDA Pro to use McSema

McSema's goal is binary to bitcode translation. Accurate disassembly and control flow recovery is a separate and difficult problem. IDA has already invested countless hours of engineering into getting disassembly right, and it only makes sense that we re-use existing work. We understand that not everyone can afford an IDA license. With the original release of McSema, we shipped our own recursive-descent disassembler. It was never as good as IDA, and it never would be. Maintaining the broken tool took away valuable development time from more important McSema work. We hope to eventually transition to more accessible control flow recovery front-ends, such as Binary Ninja (we have a branch with [experimental Binary Ninja support](https://github.com/trailofbits/mcsema/tree/binja_cfg_updates/tools/mcsema_disass/binja)). We very warmly welcome pull requests that implement support for new control flow recovery front-ends.

### What is Remill, and why does McSema need it

[Remill](https://github.com/trailofbits/remill) is a library that McSema uses to lift individual machine code instructions to LLVM IR. You can think of McSema being to Remill as Clang is to LLVM. Remill's scope is small: it focuses on instruction semantics only, and it provides semantics for x86, x86-64, and AArch64 instruction semantics. McSema's scope is much bigger: it focuses on lifting entire programs. To do so, McSema must lift the individual instructions, but there's a lot more to lifting programs than just the instructions; there are code and data cross-references, segments, etc.

### I'm a student and I'd like to contribute to McSema: how can I help

We would love to take you on as an intern to help improve McSema. We have several project ideas labelled [`intern project`](https://github.com/trailofbits/mcsema/labels/intern%20project), as well as having smaller scale to-dos labelled under [`good first issue`](https://github.com/trailofbits/mcsema/labels/good%20first%20issue) and [`help wanted`](https://github.com/trailofbits/mcsema/labels/help%20wanted) on our issue tracker. You are not limited to those items: if you think of a great feature you want in McSema, let us know and we will sponsor it. Simply contact us on our [Slack channel](https://empireslacking.herokuapp.com/) or via mcsema@trailofbits.com and let us know what you'd want to work on and why.
