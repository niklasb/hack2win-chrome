#pragma once

// add a function call to `stub` at function entry
void patch_entry(void* location, size_t prefix_len, void* stub);
void patch_replace(void* location, void* stub);
void insert_jmp(char* location, void* target, bool call);