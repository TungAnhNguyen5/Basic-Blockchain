# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/Basic-Blockchain

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/Basic-Blockchain/build

# Include any dependencies generated for this target.
include CMakeFiles/blockchain.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/blockchain.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/blockchain.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/blockchain.dir/flags.make

CMakeFiles/blockchain.dir/src/blockchain.c.o: CMakeFiles/blockchain.dir/flags.make
CMakeFiles/blockchain.dir/src/blockchain.c.o: ../src/blockchain.c
CMakeFiles/blockchain.dir/src/blockchain.c.o: CMakeFiles/blockchain.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/Basic-Blockchain/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/blockchain.dir/src/blockchain.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/blockchain.dir/src/blockchain.c.o -MF CMakeFiles/blockchain.dir/src/blockchain.c.o.d -o CMakeFiles/blockchain.dir/src/blockchain.c.o -c /home/Basic-Blockchain/src/blockchain.c

CMakeFiles/blockchain.dir/src/blockchain.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/blockchain.dir/src/blockchain.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/Basic-Blockchain/src/blockchain.c > CMakeFiles/blockchain.dir/src/blockchain.c.i

CMakeFiles/blockchain.dir/src/blockchain.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/blockchain.dir/src/blockchain.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/Basic-Blockchain/src/blockchain.c -o CMakeFiles/blockchain.dir/src/blockchain.c.s

CMakeFiles/blockchain.dir/src/main.c.o: CMakeFiles/blockchain.dir/flags.make
CMakeFiles/blockchain.dir/src/main.c.o: ../src/main.c
CMakeFiles/blockchain.dir/src/main.c.o: CMakeFiles/blockchain.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/Basic-Blockchain/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/blockchain.dir/src/main.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/blockchain.dir/src/main.c.o -MF CMakeFiles/blockchain.dir/src/main.c.o.d -o CMakeFiles/blockchain.dir/src/main.c.o -c /home/Basic-Blockchain/src/main.c

CMakeFiles/blockchain.dir/src/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/blockchain.dir/src/main.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/Basic-Blockchain/src/main.c > CMakeFiles/blockchain.dir/src/main.c.i

CMakeFiles/blockchain.dir/src/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/blockchain.dir/src/main.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/Basic-Blockchain/src/main.c -o CMakeFiles/blockchain.dir/src/main.c.s

# Object files for target blockchain
blockchain_OBJECTS = \
"CMakeFiles/blockchain.dir/src/blockchain.c.o" \
"CMakeFiles/blockchain.dir/src/main.c.o"

# External object files for target blockchain
blockchain_EXTERNAL_OBJECTS =

blockchain: CMakeFiles/blockchain.dir/src/blockchain.c.o
blockchain: CMakeFiles/blockchain.dir/src/main.c.o
blockchain: CMakeFiles/blockchain.dir/build.make
blockchain: /usr/lib/x86_64-linux-gnu/libcrypto.so
blockchain: ../lib/libcheck-x86_64.so
blockchain: CMakeFiles/blockchain.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/Basic-Blockchain/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable blockchain"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/blockchain.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/blockchain.dir/build: blockchain
.PHONY : CMakeFiles/blockchain.dir/build

CMakeFiles/blockchain.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/blockchain.dir/cmake_clean.cmake
.PHONY : CMakeFiles/blockchain.dir/clean

CMakeFiles/blockchain.dir/depend:
	cd /home/Basic-Blockchain/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/Basic-Blockchain /home/Basic-Blockchain /home/Basic-Blockchain/build /home/Basic-Blockchain/build /home/Basic-Blockchain/build/CMakeFiles/blockchain.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/blockchain.dir/depend

