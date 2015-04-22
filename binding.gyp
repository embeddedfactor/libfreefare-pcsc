{
  "variables": {
    "freefare_url": "https://github.com/embeddedfactor/libfreefare-pcsc.git",
    "freefare_src": "libfreefare",
    "ARCH%": '',
  },
  "targets": [
    {
      "target_name": "freefare_pcsc",
      "product_prefix": "lib",
      "type": "static_library",
      "include_dirs": [
        "<(freefare_src)",
        "contrib/<(OS)/<(ARCH)",
      ],
      "defines": ["USE_PCSC"],
      "direct_dependent_settings": {
        "include_dirs": [
          "<(freefare_src)",
          "contrib/<(OS)/<(ARCH)",
        ],
      },
      "conditions": [
        ["OS=='linux'", {
          "variables": {
            "ARCH%": '<!(uname -m | grep -q ^arm && echo arm || /bin/true)',
          },
          "conditions": [
            ['ARCH=="arm"', {
              "include_dirs!": [ '/usr/include/PCSC', '/usr/local/include/PCSC'],
              "libraries!": ['-lpcsclite'],
              "libraries": ['-lnfc'],
              "defines!": ["USE_PCSC"],
              "defines": ["USE_LIBNFC"],
              "direct_dependent_settings": {
                "include_dirs!": [ '/usr/include/PCSC', '/usr/local/include/PCSC'],
                "libraries!": ['-lpcsclite'],
                "libraries": ["-lnfc"],
              },
            }],
          ],
          "include_dirs": [
            "/usr/include/PCSC/",
            "/usr/local/include/PCSC/"
          ],
          "libraries": ["-lpcsclite"],
          "cflags": ["-std=c99"],
          "direct_dependent_settings": {
            "include_dirs": [
              "/usr/include/PCSC",
              "/usr/local/include/PCSC"
            ],
            "libraries": ["-lpcsclite",]
          }
        }],
        ["OS=='mac'", {
          "include_dirs": [
            "/System/Library/Frameworks/PCSC.framework/Headers"
          ],
          "libraries": ["$(SDKROOT)/System/Library/Frameworks/PCSC.framework"],
          "direct_dependent_settings": {
            "include_dirs": [
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
            "<(openssl_root)/include"
          ],
          "direct_dependent_settings": {
            "include_dirs": [
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
