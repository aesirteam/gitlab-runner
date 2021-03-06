# Install GitLab Runner on OpenShift

> [Introduced](https://gitlab.com/gitlab-org/gitlab-runner/-/issues/26640) in GitLab 13.3.

You can install GitLab Runner on Red Hat OpenShift v4 and later.

When you've completed this process, you can run your CI/CD jobs in
GitLab by using the runner you've installed in OpenShift.

## Prerequisites

- OpenShift 4.x cluster with administrator privileges
- GitLab Runner registration token

### Install the OpenShift Operator

First you must install the OpenShift Operator.

1. Open the OpenShift UI and log in as a user with administrator privileges.
1. In the left pane, click **Operators**, then **OperatorHub**.
1. In the main pane, below **All Items**, search for the keyword `GitLab`.

   ![GitLab Operator](img/openshift_allitems_v13_3.png)

1. To install, click the GitLab Operator.
1. On the GitLab Operator summary page, click **Install**.
1. On the Install Operator page, under **Installed Namespace**, select the desired namespace and click **Install**.

   ![GitLab Operator Install Page](img/openshift_installoperator_v13_3.png)

On the Installed Operators page, when the GitLab Operator is ready, the status changes to **Succeeded**.

![GitLab Operator Install Status](img/openshift_success_v13_3.png)

#### Install GitLab Runner

Now install GitLab Runner. The version you're installing is tagged as the latest
in the [Red Hat Ecosystem Catalog container list](https://catalog.redhat.com/software/containers/search).

1. Obtain a token that you'll use to register the runner:
   - For a [shared runner](https://docs.gitlab.com/ee/ci/runners/#shared-runners),
     have an administrator go to the GitLab Admin Area and click **Overview > Runners**.
   - For a [group runner](https://docs.gitlab.com/ee/ci/runners/README.html#group-runners),
     go to **Settings > CI/CD** and expand the **Runners** section.
   - For a [project-specific runner](https://docs.gitlab.com/ee/ci/runners/README.html#specific-runners),
     go to **Settings > CI/CD** and expand the **Runners** section.
1. Under **Use the following registration token during setup:**, copy the token.
1. Open an OpenShift console and switch to the project namespace:

   ```shell
   oc project "PROJECT NAMESPACE"
   ```

1. Use the following command with your Runner token:

   ```shell
   oc create secret generic gitlab-runner-secret --from-literal runner_registration_token="xxx"
   ```

1. Create the Custom Resource Definition (CRD) file and include
   the following information. The `tags` value must be `openshift` for the job to run.

   ```shell
   cat > gitlab-runner.yml << EOF
   apiVersion: gitlab.com/v1beta1
   kind: Runner
   metadata:
     name: gitlab-runner
   spec:
     gitlab:
       url: "https://gitlab.example.com"
     token: gitlab-runner-secret
     tags: openshift
   EOF
   ```

1. Now apply the CRD file by running the command:

   ```shell
   oc apply -f gitlab-runner.yml
   ```
