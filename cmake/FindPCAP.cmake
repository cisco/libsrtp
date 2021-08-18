find_path(PCAP_INCLUDE_DIR_TEMP pcap.h)
find_library(PCAP_LIBRARY_TEMP pcap)

if (PCAP_INCLUDE_DIR_TEMP AND PCAP_LIBRARY_TEMP)
  set(PCAP_LIBRARY pcap)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP DEFAULT_MSG
    PCAP_LIBRARY)

mark_as_advanced(PCAP_LIBRARY)
