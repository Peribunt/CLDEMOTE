#ifndef __CLDEMOTE_H__
#define __CLDEMOTE_H__

#include <Windows.h>
#include <intrin.h>

//
// Amount of times to measure the cldemote instruction from which to obtain the lowest measurement
//
#define CLDEMOTE_MEASUREMENT_SAMPLE_COUNT 10

/**
 * @brief Check whether or a physical page belonging to the specified virtual address is in RAM
 * 
 * @param [in] VirtualAddress: The virtual address to check
 * 
 * @return TRUE  if the specified virtual address is mapped to a physical page
 * @return FALSE if the specified virtual address is either invalid or not mapped to a physical page
*/
BOOLEAN
IsMappedToPhysicalPage( 
	_In_ LPVOID VirtualAddress 
	);
#endif
