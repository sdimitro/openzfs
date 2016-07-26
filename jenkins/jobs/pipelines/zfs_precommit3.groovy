/**
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

import com.google.common.base.Charsets
import com.google.common.hash.Hashing

def RELEASE = 'master'
def ARCHIVE_HOST = 'westy'

/*
 * This function was copied from the "jobs/lib/common.groovy" file.
 * @param url Url of Jenkins instance where job is running.
 * @return Filesystem safe hash of url.
 */
def static String jenkinsTag(String url) {
    return Hashing.murmur3_32().newHasher()
            .putString(url, Charsets.UTF_8).hash().toString()
}

/**
 * Define a single string parameter for job.
 * @param name Name of parameter.
 * @param value Value of parameter.
 * @return Dictionary initialized with a string parameter suitable for passing to 'build'.
 */
def static string_param(name, value) {
    return [$class: 'StringParameterValue', name: name, value: value]
}

/**
 * Define a single node parameter for job.
 * @param name Name of parameter.
 * @param value Label of node to run on.
 * @return Dictionary initialized with a node parameter suitable for passing to 'build'.
 */
def static node_param(name, label) {
    return [$class: 'NodeParameterValue', name: name, labels: [label], nodeEligibility: [$class: 'AllNodeEligibility']]
}

node {
    stage('Build OS')

    def jenkins_url  = env.JENKINS_URL
    def build_number = env.BUILD_NUMBER
    def build_name   = BUILD_DISPLAY_NAME
    def job_name     = env.JOB_NAME

    /*
     * The build_name variable is generated via the BUILD_DISPLAY_NAME
     * parameter. If this is empty, we use a default value using the
     * ASSIGN_ON_FAILURE and OS_BRANCH parameters to give the build a
     * recognizable label when it is displayed in the GUI.
     */
    if (!build_name) {
        build_name = ASSIGN_ON_FAILURE + ' ' + OS_BRANCH
    }

    def display_name = '#' + build_number + ' ' + build_name
    currentBuild.setDisplayName(display_name)

    /*
     * The build name is used to populate the BUILD_TAG used by the
     * downstream Jenkins jobs. Setting this to a recognizable value is
     * useful because the BUILD_TAG is used when displaying the job in the
     * GUI; and this make navigation of the many jobs that may be present
     * much easier. Additionally, this allows one to map a downstream job
     * back up to the original job that triggered it more easily (this is
     * because we embed the zfs precommit job number in the BUILD_TAG that
     * is assigned to the downstream jobs).
     */
    def downstream_build_tag = build_name + ' zpc-' + build_number

    /*
     * The build will occur in the workspace of the Jenkins job, but in
     * order to preserve the build products and make them available to
     * be used in the 'oi-onu' and 'dx-osu' jobs, we archive the build
     * products to a directory on the static buildserver.
     *
     * Note, since we're archiving/copying the build products to a
     * directory external to the Jenkins job's workspace, we're
     * relying on another process to clean up these directories;
     * otherwise they'll keep accumulating to the point of running the
     * static buildserver out of disk space.
     */
    def archive_dir = (
            '/data/jenkins/' + job_name + '/build-' + build_number + '-' + jenkinsTag(jenkins_url))

    def default_build_parameters = [
        string_param('ASSIGN_ON_FAILURE', ASSIGN_ON_FAILURE),
        string_param('ARCHIVE_DIR', archive_dir),
        string_param('ARCHIVE_HOST', ARCHIVE_HOST),
        string_param('BUILD_ON_DCENTER', BUILD_ON_DCENTER),
        string_param('BUILD_SCRIPT_REPO', BUILD_SCRIPT_REPO),
        string_param('BUILD_SCRIPT_BRANCH', BUILD_SCRIPT_BRANCH),
        string_param('BUILD_TAG', downstream_build_tag),
        string_param('DCENTER_HOST', DCENTER_HOST),
        string_param('DEVOPS_REPO', DEVOPS_REPO),
        string_param('DEVOPS_BRANCH', DEVOPS_BRANCH),
        string_param('EXPIRATION_ON_FAILURE', EXPIRATION_ON_FAILURE),
        string_param('EXPIRATION_ON_SUCCESS', EXPIRATION_ON_SUCCESS),
        string_param('OS_BRANCH', OS_BRANCH),
        string_param('OS_REPO', OS_REPO),
        string_param('RELEASE', RELEASE),
    ]

    parallel(
            debug: {
                build job: 'build-os-usher',
                      parameters: default_build_parameters + [
                          string_param('BUILD_DEBUG', 'yes'),
                          string_param('BUILD_NONDEBUG', 'no'),
                          string_param('RUN_LINT', 'no'),
                      ]
            },
            non_debug: {
                build job: 'build-os-usher',
                      parameters: default_build_parameters + [
                          string_param('BUILD_DEBUG', 'no'),
                          string_param('BUILD_NONDEBUG', 'yes'),
                          string_param('RUN_LINT', 'no'),
                      ]
            },
    )

    stage('Installation')

    /*
     * The "oi-onu" and "dx-osu" jobs will create a new DCenter VM that
     * is used to install the build products into, but those jobs
     * require the name of the VM to be passed in; thus we generate the
     * name for this VM here.
     *
     * If we had already created a DCenter VM to perform the build, then
     * it's unnecessary to create another VM to install the build
     * products into, since we could just re-use the VM that was used
     * for the build. We don't do that simply because it'd require more
     * work to refactor "dx-osu" to accept a pre-allocated VM, and the
     * job is already written to create a new one.
     *
     * Additionally, creating a new VM to install the build products
     * into allows for different DCenter images to be used for
     * performing the build vs. running the tests. For example, we use a
     * build server image when building the OS, but use a delphix trunk
     * image when running the tests. This flexibility is crucial since
     * we don't actually want to run the tests on build server VM.
     *
     * Also note, while the "oi-osu" and "dx-osu" jobs will create a new
     * DCenter VM, they do not handle the destruction of this VM; thus
     * it's up to us to ensure this VM is properly destroyed when we're
     * done with it (even on failure).
     *
     * Finally, if we're installing illumos (not DxOS) then we need to
     * perform different logic during the upgrade step, since DxOS and
     * illumos do not handle upgrades the same way.
     */
    def default_create_parameters = [
        string_param('BUILD_SCRIPT_BRANCH', BUILD_SCRIPT_BRANCH),
        string_param('BUILD_SCRIPT_REPO', BUILD_SCRIPT_REPO),
        string_param('BUILD_TAG', downstream_build_tag),
        string_param('DCENTER_HOST', DCENTER_HOST),
        string_param('DCENTER_IMAGE', DCENTER_IMAGE),
        string_param('DEVOPS_BRANCH', DEVOPS_BRANCH),
        string_param('DEVOPS_REPO', DEVOPS_REPO),
        string_param('JENKINS_MASTER', jenkins_url),
    ]

    def default_install_parameters = [
        string_param('BUILD_SCRIPT_BRANCH', BUILD_SCRIPT_BRANCH),
        string_param('BUILD_SCRIPT_REPO', BUILD_SCRIPT_REPO),
        string_param('BUILD_TAG', downstream_build_tag),
        string_param('INSTALL_DEBUG', 'yes'),
        string_param('OS_DIR', '/net/' + ARCHIVE_HOST + archive_dir),
    ]

    def dcenter_roles = 'dlpx.dxos-credentials'
    def slave_roles = 'dlpx.initialize-dxos'
    def install_job = 'dx-osu2'

    def create = build job: 'create-dc-slave',
                       parameters: default_create_parameters + [
                           string_param('DCENTER_ROLES', dcenter_roles),
                           string_param('SLAVE_ROLES', slave_roles),
                       ]

    def install_dc_guest = create.rawBuild.environment.get('GUEST_NAME')
    def install = null

    catchError {
        echo('Installing on guest: ' + install_dc_guest)
        install = build job: install_job,
                        parameters: default_install_parameters + [
                            node_param('JOB_SLAVE', install_dc_guest),
                        ]
    }

    /*
     * This will shutdown and unregister the VM with the new build
     * products installed prior to that system being cloned for the
     * "ztest" and "zfs-test" jobs below.
     */
    build job: 'destroy-dc-guest',
          parameters: [
              string_param('ASSIGN_TO_USER', ASSIGN_ON_SUCCESS),
              string_param('BUILD_SCRIPT_BRANCH', BUILD_SCRIPT_BRANCH),
              string_param('BUILD_SCRIPT_REPO', BUILD_SCRIPT_REPO),
              string_param('BUILD_TAG', downstream_build_tag),
              string_param('DCENTER_HOST', DCENTER_HOST),
              string_param('DEVOPS_BRANCH', DEVOPS_BRANCH),
              string_param('DEVOPS_REPO', DEVOPS_REPO),
              string_param('EXPIRATION', EXPIRATION_ON_SUCCESS),
              string_param('GUEST_NAME', install_dc_guest),
              string_param('UNREGISTER_ONLY', 'yes'),
          ]

    if (!install) {
        return
    }

    stage('Run tests')

    /*
     * Finally, now that we have built the OS and have a DCenter VM with
     * the build products installed on it, we pass the name of this VM
     * down to the jobs that will run the ZFS tests. Both of these jobs
     * will create a clone of the VM passed in to run the tests, and
     * will destroy the clone they create after the tests are finished.
     * Thus, we do not have to worry about destroying the VMs created
     * for testing (like we do for the VM used for installing).
     */

    def default_test_parameters = [
        string_param('ASSIGN_ON_FAILURE', ASSIGN_ON_FAILURE),
        string_param('ASSIGN_ON_SUCCESS', ASSIGN_ON_SUCCESS),
        string_param('BUILD_TAG', downstream_build_tag),
        string_param('BUILD_SCRIPT_REPO', BUILD_SCRIPT_REPO),
        string_param('BUILD_SCRIPT_BRANCH', BUILD_SCRIPT_BRANCH),
        string_param('DEVOPS_REPO', DEVOPS_REPO),
        string_param('DEVOPS_BRANCH', DEVOPS_BRANCH),
        string_param('DCENTER_HOST', DCENTER_HOST),
        string_param('DCENTER_ROLES', dcenter_roles),
        string_param('DCENTER_GUEST', install_dc_guest),
        string_param('EXPIRATION_ON_FAILURE', EXPIRATION_ON_FAILURE),
        string_param('EXPIRATION_ON_SUCESS', EXPIRATION_ON_SUCCESS),
    ]

    parallel(
            zfs_test: {
                build parameters: default_test_parameters, job: 'zfs-test-usher'
            },
            zloop: {
                build parameters: default_test_parameters, job: 'zloop-usher'
            },
            lint: {
                build job: 'build-os-usher',
                      parameters: default_build_parameters + [
                          string_param('BUILD_DEBUG', 'yes'),
                          string_param('BUILD_NONDEBUG', 'no'),
                          string_param('RUN_LINT', 'yes'),
                      ]
            }
    )
}
