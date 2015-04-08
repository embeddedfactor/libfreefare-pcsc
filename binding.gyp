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
          "include_dirs": [
            "contrib/linux",
            "<(freefare_src)",
            "/usr/include/PCSC/",
            "/usr/local/include/PCSC/"
          ],
          "libraries": ["-lpcsclite"],
          "cflags": ["-std=c99"],
          "direct_dependent_settings": {
            "include_dirs": [
              "contrib/linux",
              "<(freefare_src)",
              "/usr/include/PCSC",
              "/usr/local/include/PCSC"
            ],
            "libraries": ["-lpcsclite"]
          }
        }],
        ["OS=='mac'", {
          "include_dirs": [
            "contrib/macos",
            "<(freefare_src)",
            "/System/Library/Frameworks/PCSC.framework/Headers"
          ],
          "libraries": ["$(SDKROOT)/System/Library/Frameworks/PCSC.framework"],
          "direct_dependent_settings": {
            "include_dirs": [
              "contrib/macos",
              "<(freefare_src)",
              "/System/Library/Frameworks/PCSC.framework/Headers"
            ],
            "libraries": ["$(SDKROOT)/System/Library/Frameworks/PCSC.framework"]
          }
        }],
        ["OS=='win'", {
          'conditions': [
            # "openssl_root" is the directory on Windows of the OpenSSL files.
            # Check the "target_arch" variable to set good default values for
            # both 64-bit and 32-bit builds of the module.
            ['target_arch=="x64"', {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win64'
              },
            }, {
              'variables': {
                'openssl_root%': 'C:/OpenSSL-Win32'
              },
            }],
          ],
          "include_dirs": [
            "contrib/win32",
            "<(freefare_src)",
            "<(openssl_root)/include"
          ],
          "direct_dependent_settings": {
            "include_dirs": [
              "contrib/win32",
              "<(freefare_src)",
              "<(openssl_root)\include"
            ],
            "libraries": [
              "-lWinSCard",
              "-l<(openssl_root)\lib\libeay32.lib"
            ]
          }
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
        #"-pedantic",
      ],
      'msvs_settings': {
        'VCCLCompilerTool': {
          'AdditionalOptions': [
            '/TP',
          ]
        }
      }
    }
  ]
}
