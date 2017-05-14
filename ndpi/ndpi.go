package ndpi

// XXX we should use something like
// pkg-config --libs libndpi

// #cgo pkg-config: libndpi
/*
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
//#include <libndpi-1.8.0/libndpi/ndpi_api.h>
#include <libndpi-1.8.0/libndpi/ndpi_main.h>

extern void *mallocWrapper(unsigned long size);
extern void freeWrapper(void *freeable);



 static struct ndpi_detection_module_struct* ndpi_init() {

	set_ndpi_malloc(mallocWrapper), set_ndpi_free(freeWrapper);
	//set_ndpi_flow_malloc(NULL), set_ndpi_flow_free(NULL);

	struct ndpi_detection_module_struct* my_ndpi_struct = ndpi_init_detection_module();

	if (my_ndpi_struct == NULL) {
		return NULL;
	}

	//    my_ndpi_struct->http_dont_dissect_response=1;

	NDPI_PROTOCOL_BITMASK all;

	NDPI_BITMASK_ADD(all,NDPI_PROTOCOL_HTTP);
	NDPI_BITMASK_ADD(all,NDPI_PROTOCOL_SSL);

	// enable all protocols
	//    NDPI_BITMASK_SET_ALL(all);
        ndpi_set_protocol_detection_bitmask2(my_ndpi_struct, &all);

	return my_ndpi_struct;
}

*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/dustin/go-humanize"
)

type wrapper struct {
	cM (*C.struct_ndpi_detection_module_struct)
	cS C.size_t
}

//export mallocWrapper
func mallocWrapper(size C.size_t) unsafe.Pointer {

	NDPIFilter.cS = NDPIFilter.cS + size
	return unsafe.Pointer(C.malloc(size))
}

//export freeWrapper
func freeWrapper(freeable unsafe.Pointer) {

	C.free(freeable)

}

//NDPIFilter n
var NDPIFilter wrapper

//ErrInitFailed ...
var ErrInitFailed = errors.New("nDPI: init failed")

//Init initialize DPI
func Init() error {

	fmt.Println("Init nDPI")
	NDPIFilter.cM = C.ndpi_init()
	if NDPIFilter.cM == nil {
		fmt.Println("NDPI Error")
		return ErrInitFailed
	}
	fmt.Printf("NFQFilter mem size is %s", humanize.Bytes((uint64(NDPIFilter.cS))))

	return nil

}
