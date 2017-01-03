stage("Build") {
  //parallel linux: {
    node('ArchLinux') {
      echo 'Cleanup Workspace'
      deleteDir()
      echo 'Checkout SCM'
      checkout scm
      sh '''#!/bin/bash
        export OLDPATH="$PATH"
        for node in /opt/nodejs/x64/* ; do
          export PATH="${node}/bin:${OLDPATH}"
          export VER=$(basename ${node})
          for type in "Debug" "Release" ; do
            npm install --${type,,}
            mkdir -p dist/linux/x64/${VER}/${type,,} || true
          done
          cp -r build/${type}/libfreefare_pcsc.a dist/linux/x64/${VER}/${type,,}/
        done
      '''
      archiveArtifacts artifacts: 'dist/**', fingerprint: true
    }
  /*}, windows: {
    node('Windows-7-Dev') {
      echo 'Cleanup Workspace'
      deleteDir()
      echo 'Checkout SCM'
      checkout scm
      echo 'Build Debug via NPM'
      sh 'npm install --debug'
      echo 'Build Release via NPM'
      sh 'npm install'
      archiveArtifacts artifacts: 'build/**/libfreefare_pcsc.a', fingerprint: true
    }
  }, macos: {
    node('Yosemite-Dev') {
      echo 'Cleanup Workspace'
      deleteDir()
      echo 'Checkout SCM'
      checkout scm
      echo 'Build Debug via NPM'
      sh 'npm install --debug'
      echo 'Build Release via NPM'
      sh 'npm install'
      archiveArtifacts artifacts: 'build/**/libfreefare_pcsc.a', fingerprint: true
    }
  }*/
}
