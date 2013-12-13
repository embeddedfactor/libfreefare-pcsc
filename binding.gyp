{
  "variables": {
    "freefare_url": "https://github.com/hackerhelmut/libfreefare-pcsc.git",
    "freefare_src": "libfreefare",
  },
  "targets": [
    {
      "target_name": "freefare_pcsc",
      "product_prefix": "lib",
      "type": "static_library",
      "conditions": [
        ["OS=='linux'", {
          "variables": {
            "freefare_contrib": "contrib/linux",
            "openssl_inc": "/usr/include"
          }
        }],
        ["OS=='mac'", {
          "include_dirs": [
            "contrib/macos",
            "/System/Library/Frameworks/PCSC.framework/Headers"
          ],
          "libraries": ["-framework", "PCSC"]
        }],
        ["OS=='win'", {
          "include_dirs": [
            "contrib/win32",
            "C:\OpenSSL-Win32/include"
          ],
        }]
      ],
        "sources": [
          "<(freefare_src)/freefare.c",
          "<(freefare_src)/freefare.h",
          "<(freefare_src)/freefare_pcsc.h",
          "<(freefare_src)/freefare_nfc.h",
          "<(freefare_src)/freefare_internal.h",
          "<(freefare_src)/mad.c",
          "<(freefare_src)/mifare_application.c",
          "<(freefare_src)/mifare_classic.c",
          "<(freefare_src)/mifare_desfire.c",
          "<(freefare_src)/mifare_desfire_aid.c",
          "<(freefare_src)/mifare_desfire_crypto.c",
          "<(freefare_src)/mifare_desfire_error.c",
          "<(freefare_src)/mifare_desfire_key.c",
          "<(freefare_src)/mifare_ultralight.c",
          "<(freefare_src)/tlv.c"
        ],
        "cflags": [
          "-Wall",
          "-Wextra",
          "-Wno-unused-parameter",
          "-fPIC",
          "-fno-strict-aliasing",
          "-fno-exceptions",
          "-pedantic",
          "-UHAVE_LIBNFC"
        ],
        'msvs_settings': {
          'VCCLCompilerTool': {
            'AdditionalOptions': [
              '/TP',
            ],
          },
        },
        "include_dirs": [
            "<(freefare_src)", 
        ],
        "libraries": [
        ]
    }
  ]
}
