//
// Description: This file contains the declarations of the functions that are used to manipulate the sections of the
// dumped image.
//

#pragma once

#include "dumper.hpp"

//
// Resolves the sections of the specified module. The original image contains the raw data of the module.
//
bool ResolveSections(_In_ PDUMPER pDumper, const MODULEINFO &moduleinfo, _In_ PBYTE *OriginalImage);
