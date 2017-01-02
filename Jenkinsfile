stage("Build") {
  parallel linux: {
    node('ArchLinux') {
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
  }, windows: {
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
  }
}
