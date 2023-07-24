[Go back to the Installation documentation page](../../../README.md)

# Frogbot Jenkins Templates

<img src="../../../images/jenkins-logo.png" width="250">

### 🖥️ Follow These steps to install Frogbot on Jenkins
<details>
  <summary>1️⃣  Install Jenkins Webhook Plugin </summary>

- **Install Generic Webhook Trigger**
  - Using the GUI: From your Jenkins dashboard navigate to Manage Jenkins > Manage Plugins and select the Available
    tab. Locate this plugin by searching
    for - [Generic Webhook Trigger](https://plugins.jenkins.io/generic-webhook-trigger/).

</details>
<details>
  <summary>2️⃣ Setup VCS Webhook </summary>

- **Set Up Webhook on your Git Provider**

    <details>
      <summary> Bitbucket Server  </summary>
  
    - Go to repository settings and select Webhooks , and create a new webhook.
    - <img src="../../../images/bitbucket-webhook-setup.png">
    - <img src="../../../images/bitbucketserver-create-webhook.png">

    </details>

  <details>
      <summary> GitHub  </summary>
  - Go
    </details>

  <details>
        <summary> Azure Repos  </summary>
  
   -   [Set Up Azure Repos Jenkins Webhook](https://learn.microsoft.com/en-us/azure/devops/service-hooks/services/jenkins?view=azure-devops)
  
    </details>

  <details>
        <summary> GitLab  </summary>
  
  - Go your project settings and select webhooks.
  - Setup a webhhok with merge request events
  -  <img src="../../../images/GitLab_webhook.png">
      TODO -> EXLPAIN THIS SECRET
   - Fill in your **JENKINS URL/generic-webhook-trigger/invoke** , **SECRET_TOKEN** and select add webhook.

</details>

<details>
  <summary>3️⃣ Set up credentials</summary>

- Make sure you have the connection details of your JFrog environment and saved as credentials, as they will be
  referenced from the Jenkinsfile.
- Set up the following credentials:
    - **JF_URL**
    - **JF_ACCESS_TOKEN** *or* **JF_USER**  & **JF_PASSWORD**
    - **JF_GIT_TOKEN** access token with read&write access to the repository.
    - **TRIGGER_SECRET** secret used when creating the webhook.
- [How to use credentials with Jenkins](https://www.jenkins.io/doc/book/using/using-credentials/)

</details>

<details>
  <summary>4️⃣  Prepare Agents</summary>

- It is necessary to have the package manager corresponding to the repository installed on the machine. For example, for
  an npm project, npm must be installed. In the case of multi-project repositories, ensure that all the required package
  managers are installed

</details>

<details>
  <summary>5️⃣ Copy templates </summary>

  - **Copy and adjust params for each command**

   
   * [Scan And Fix Repository](scan-and-fix.jenkinsfile)


   * [Scan Pull Request](scan-pull-request.jenkinsfile)



      



