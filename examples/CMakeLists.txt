# $Id$
set(EXAMPLES-SOURCES
        mifare-classic-format-pcsc
        mifare-classic-read-ndef-pcsc
        mifare-classic-write-ndef-pcsc
        mifare-desfire-access-pcsc
        mifare-desfire-create-ndef-pcsc
        mifare-desfire-format-pcsc
        mifare-desfire-info-pcsc
        mifare-desfire-read-ndef-pcsc
        mifare-desfire-write-ndef-pcsc
        mifare-desfire-ev1-configure-ats-pcsc
        mifare-desfire-ev1-configure-default-key-pcsc
        mifare-desfire-ev1-configure-random-uid-pcsc
        mifare-ultralight-info-pcsc
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../libfreefare)

# Examples
foreach(source ${EXAMPLES-SOURCES})
  add_executable(${source} ${source}.c)
  target_link_libraries(${source} freefare)
  install(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT examples)
endforeach(source)
