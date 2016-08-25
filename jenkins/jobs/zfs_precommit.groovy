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

workflowJob('zfs-precommit') {
    label 'blackbox-slave'

    quietPeriod 0
    concurrentBuild true

    description('''
        This job is intended to be used to checkout a given os-gate (or
        illumos-gate) revision/branch, perform a full "nightly" build,
        install the generated build products using "dx-osu" (or "onu"),
        and will run the ZFS regression test suite against the build
        products generated from the specified os-gate revision.

        This job doesn't actually perform any of the compilation,
        installation, or testing itself. Instead, this job is merely a
        thin orchestration layer on top of the various sub-jobs, and is
        used to ensure the intended revision/branch is properly
        compiled, installed, and tested. A failure in any of these
        sub-jobs will result in this overarching job reporting failure.
    ''')

    wrappers {
        colorizeOutput()
        timestamps()
    }

    parameters {
        stringParam('ASSIGN_ON_FAILURE', 'blackbox',
                    'On failure, any outstanding DCenter VMs will be assigned to ' +
                    'the user specified here. E.g. if the zfs-test suite fails, ' +
                    'the DCenter VM used to run that test will be assigned to ' +
                    'this user; this must be a valid LDAP username.')
        stringParam('ASSIGN_ON_SUCCESS', 'blackbox',
                    'On success, any outstanding DCenter VMs will be assigned to ' +
                    'the user specified here. E.g. if the zfs-test suite fails, ' +
                    'the DCenter VM used to run that test will be assigned to ' +
                    'this user; this must be a valid LDAP username.')
        choiceParam('BUILD_ON_DCENTER', ['yes', 'no'],
                    'Create and use a DCenter VM to perform the build.')
        stringParam('BUILD_SCRIPT_REPO', 'ssh://git@git/var/dlpx-build-gate',
                    'The build-gate repository to use, containing the Ansible files.')
        stringParam('BUILD_SCRIPT_BRANCH', 'master',
                    'The build-gate repository branch that will be used.')
        stringParam('BUILD_DISPLAY_NAME', '',
                    'Used to set the name of the build which is displayed in the GUI.')
        stringParam('DCENTER_HOST', 'dcenter.delphix.com',
                    'Use the specified DCenter host when creating new VMs.')
        stringParam('DEVOPS_REPO', 'ssh://git@git/var/devops-gate',
                    'The devops-gate repository to use, containing the Ansible files.')
        stringParam('DEVOPS_BRANCH', 'master',
                    'The devops-gate repository branch that will be used.')
        stringParam('DCENTER_IMAGE', 'dlpx-trunk',
                    'This specifies the DCenter gold image to clone a guest from that ' +
                    'will be used for installation and testing of the os-gate. ' +
                    'After the code is built, the build products will be installed ' +
                    'on a guest that was cloned from this DCenter image, and then ' +
                    'this guest (that was just upgraded) will be cloned for testing.')
        stringParam('EMAIL', '',
                    'After the build completes, the results will be sent to the ' +
                    'comma seperated list of email addresses specified here.')
        stringParam('EXPIRATION_ON_FAILURE', '7',
                    'Any DCenter guests that are used by this job will be ' +
                    'unregistered and configured with a expiration after the ' +
                    'job is finished using the gueste. This parameter specifies ' +
                    'the expiration that is give to the DCenter guest on failure.')
        stringParam('EXPIRATION_ON_SUCCESS', '2',
                    'Any DCenter guests that are used by this job will be ' +
                    'unregistered and configured with a expiration after the ' +
                    'job is finished using the gueste. This parameter specifies ' +
                    'the expiration that is give to the DCenter guest on success.')
        stringParam('OS_REPO', 'ssh://git@git/var/dlpx-os-gate',
                    'The os-gate or illumos repository to clone for testing.')
        stringParam('OS_BRANCH', 'master',
                    'The os-gate or illumos repository branch to checkout for testing.')
    }

    publishers {
        extendedEmail {
            recipientList('${EMAIL}')
            replyToList('no-reply@delphix.com')

            /*
             * Instead of using the default email body which basically
             * only contains the build result (success, failure, etc)
             * and a link to view the build in the Jenkins UI, we use
             * the following snippet to provide the job's full console
             * output in the body of the email.
             *
             * Since the Jenkins console page is displayed in a
             * mono-spaced font, there's often formatting that is lost
             * when the same contents are viewed when not using a
             * mono-spaced font.
             *
             * To try and preserve this formatting requirement, we
             * specify HTML as the content type for the email, but use
             * the "pre" tags to try and coerse the user's email viewing
             * application to use an appropriate font. Obviously this
             * isn't fool proof, as the email application still may not
             * use a mono-spaced font, but it tends to mostly work for
             * our needs (e.g. GMail in a web browser or mobile app).
             */
            contentType('text/html')
            defaultContent('''
                <p>See full results at: ${BUILD_URL}</p>
                <p>See full pipeline steps at: ${BUILD_URL}/flowGraphTable/</p>
                <p>See below for the build log:</p>
                '''.stripIndent())

            triggers {
                /*
                 * We want to specify the "OS_BRANCH" in the subject as
                 * that is often the most relevant information for
                 * distinguishing builds from one another. When testing
                 * multiple branch simultaneously, if we only had the
                 * build number in the subject, it would be difficult to
                 * determine which email corresponded to which of the
                 * multiple branches being tested. Having this
                 * information in the subject makes it easy for the user
                 * to quickly know which email corresponds to which
                 * test they had previously submitted.
                 */
                def subjectfmt = '${PROJECT_DISPLAY_NAME} - ${OS_BRANCH} - %s'

                aborted {
                    subject(String.format(subjectfmt, 'aborted'))
                }

                failure {
                    subject(String.format(subjectfmt, 'failure'))
                }

                success {
                    subject(String.format(subjectfmt, 'success'))
                }
            }
        }
    }

    definition {
        cps {
            script(readFileFromWorkspace('jenkins/jobs/pipelines/zfs_precommit.groovy'))
            sandbox()
        }
    }
}
