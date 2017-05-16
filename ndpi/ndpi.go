package ndpi

// XXX we should use something like
// pkg-config --libs libndpi

// #cgo pkg-config: libndpi
/*
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <libndpi-1.8.0/libndpi/ndpi_api.h>


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


 static int parse_packet(struct ndpi_detection_module_struct* my_ndpi_struct, void* buffer, int ipsize) {


		struct ndpi_id_struct *src = NULL;
    struct ndpi_id_struct *dst = NULL;
    struct ndpi_flow_struct *flow = NULL;
		u_int32_t ndpi_size_flow_struct = 0;
		u_int32_t ndpi_size_id_struct = 0;

		printf("Enter to parse_packet\n");
		ndpi_size_id_struct   = ndpi_detection_get_sizeof_ndpi_id_struct();
		ndpi_size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

    src = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(src, 0, ndpi_size_id_struct);

    dst = (struct ndpi_id_struct*)malloc(ndpi_size_id_struct);
    memset(dst, 0, ndpi_size_id_struct);

    flow = (struct ndpi_flow_struct *)malloc(ndpi_size_flow_struct);
    memset(flow, 0, ndpi_size_flow_struct);

    uint32_t current_tickt = 0;

    ndpi_protocol detected_protocol = ndpi_detection_process_packet(my_ndpi_struct, flow, buffer, ipsize, current_tickt, src, dst);

    char* protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol);
    char* master_protocol_name = ndpi_get_proto_name(my_ndpi_struct, detected_protocol.master_protocol);

    printf("Protocol: %s master protocol: %s\n", protocol_name, master_protocol_name);


    ndpi_free_flow(flow);
    free(dst);
    free(src);
		return detected_protocol.master_protocol;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"log"
	"unsafe"

	"github.com/dustin/go-humanize"
)

type wrapper struct {
	cM   (*C.struct_ndpi_detection_module_struct)
	cS   C.size_t
	src  (*C.struct_ndpi_id_struct)
	dst  (*C.struct_ndpi_id_struct)
	flow (*C.struct_ndpi_flow_struct)
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
	fmt.Printf("NFQFilter mem size is %s \n", humanize.Bytes((uint64(NDPIFilter.cS))))

	ndpiSizeIDStruct := C.size_t(C.ndpi_detection_get_sizeof_ndpi_id_struct())
	ndpiSizeFlowStruct := C.size_t(C.ndpi_detection_get_sizeof_ndpi_flow_struct())

	NDPIFilter.src = (*C.struct_ndpi_id_struct)(C.calloc(1, ndpiSizeIDStruct))
	NDPIFilter.dst = (*C.struct_ndpi_id_struct)(C.calloc(1, ndpiSizeIDStruct))
	NDPIFilter.flow = (*C.struct_ndpi_flow_struct)(C.calloc(1, ndpiSizeFlowStruct))

	return nil

}

//DetectionProcessPacket ...
func DetectionProcessPacket(packet []byte, size int) {
	packetData := packet
	//packetDataP := unsafe.Pointer(&packetData)

	log.Printf("[DEBUG] protocol is: %d len is: %d packet is: %s", C.parse_packet(NDPIFilter.cM, C.CBytes(packetData), C.int(size)), size, packet)
	//log.Printf("[DEBUG] HTTP is: %s", C.NDPI_PROTOCOL_HTTP)
}
