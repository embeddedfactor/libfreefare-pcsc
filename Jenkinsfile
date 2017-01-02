stage("Build") {
  parallel linux: {
    echo 'Cleanup Workspace'
    deleteDir()
    echo 'Checkout SCM'
    checkout scm
    echo 'Build Debug via NPM'
    npm install --debug
    echo 'Build Release via NPM'
    npm install
  }, windows: {
    echo 'Cleanup Workspace'
    deleteDir()
    echo 'Checkout SCM'
    checkout scm
    echo 'Build Debug via NPM'
    npm install --debug
    echo 'Build Release via NPM'
    npm install
  }, macos: {
    echo 'Cleanup Workspace'
    deleteDir()
    echo 'Checkout SCM'
    checkout scm
    echo 'Build Debug via NPM'
    npm install --debug
    echo 'Build Release via NPM'
    npm install
  }
}
