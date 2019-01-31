#!/usr/bin/env groovy

@Library('sec_ci_libs@v2-latest') _

def master_branches = ["master", "dcos/1.8", "dcos/1.9", "dcos/1.10", "dcos/1.11", "dcos/1.12", "dcos/1.13"] as String[]

if (master_branches.contains(env.BRANCH_NAME)) {
    // Rebuild main branch once a day
    properties([
        pipelineTriggers([cron('H H * * *')])
    ])
}

task_wrapper('mesos-sec', master_branches, '8b793652-f26a-422f-a9ba-0d1e47eb9d89', '#dcos-security-ci') {
    def nameByBranch = ""
    def nameByCommit = ""

    stage("Verify author") {
        user_is_authorized(master_branches, '8b793652-f26a-422f-a9ba-0d1e47eb9d89', '#dcos-security-ci')
    }

    stage('debug docker version') {
        sh 'docker version'
    }

    stage('Cleanup workspace') {
        deleteDir()
    }

    stage('Checkout') {
        checkout scm

        // http://stackoverflow.com/questions/35554983/git-variables-in-jenkins-workflow-plugin
        // https://issues.jenkins-ci.org/browse/JENKINS-35230
        def gitCommit = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()

        nameByBranch = "mesosphereci/bouncer:" + "${env.BRANCH_NAME}".replaceAll('/','-')
        nameByCommit = "mesosphereci/bouncer:${gitCommit}"
    }

    stage('make rebuild-container-images`') {
        sh 'make rebuild-container-images'
    }

    try {

        stage('make test') {
            sh 'make test'
        }

    } finally {

        stage('archive artifacts') {
            archiveArtifacts allowEmptyArchive: true, artifacts: 'gunicorn_*.outerr', fingerprint: true
        }

        stage('make clean'){
            sh 'make clean'
        }
    }
}
