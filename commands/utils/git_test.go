package utils

import (
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestGitManager_GenerateCommitMessage(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>: bump ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "<type>: bump mquery",
			description:     "Custom prefix",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "<type>[scope]: Upgrade package ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:    "<type>[scope]: Upgrade package mquery to 3.4.5",
			description: "Default template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{commitMessageTemplate: ""}},
			impactedPackage: "mquery", fixVersion: VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:    "Upgrade mquery to 3.4.5",
			description: "Default template",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage := test.gitManager.GenerateCommitMessage(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GenerateFixBranchName(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[Feature]-${IMPACTED_PACKAGE}-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "[Feature]-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "frogbot-mquery-41b1f45136b25e3624b15999bd57a476",
			description:     "No template",
		}, {
			gitManager:      GitManager{customTemplates: CustomTemplates{branchNameTemplate: "just-a-branch-${BRANCH_NAME_HASH}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "just-a-branch-41b1f45136b25e3624b15999bd57a476",
			description:     "Custom template without inputs",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commitMessage, err := test.gitManager.GenerateFixBranchName("md5Branch", test.impactedPackage, test.fixVersion.FixVersion)
			assert.NoError(t, err)
			assert.Equal(t, test.expected, commitMessage)
		})
	}
}

func TestGitManager_GeneratePullRequestTitle(t *testing.T) {
	tests := []struct {
		gitManager      GitManager
		impactedPackage string
		fixVersion      VulnerabilityDetails
		expected        string
		description     string
	}{
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE} to ${FIX_VERSION}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery to 3.4.5",
			description:     "Custom template",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: "[CustomPR] update ${IMPACTED_PACKAGE}"}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "[CustomPR] update mquery",
			description:     "Custom template one var",
		},
		{
			gitManager:      GitManager{customTemplates: CustomTemplates{pullRequestTitleTemplate: ""}},
			impactedPackage: "mquery",
			fixVersion:      VulnerabilityDetails{FixVersion: "3.4.5"},
			expected:        "[🐸 Frogbot] Update version of mquery to 3.4.5",
			description:     "No prefix",
		},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			titleOutput := test.gitManager.GeneratePullRequestTitle(test.impactedPackage, test.fixVersion.FixVersion)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedFixBranchName(t *testing.T) {
	tests := []struct {
		gitManager GitManager
		expected   string
		desc       string
	}{
		{
			expected:   "frogbot-update-dependencies-0",
			desc:       "No template",
			gitManager: GitManager{},
		},
		{
			expected:   "[feature]-0",
			desc:       "Custom template hash only",
			gitManager: GitManager{customTemplates: CustomTemplates{branchNameTemplate: "[feature]-${BRANCH_NAME_HASH}"}},
		},
	}
	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			titleOutput, err := test.gitManager.GenerateAggregatedFixBranchName()
			assert.NoError(t, err)
			assert.Equal(t, test.expected, titleOutput)
		})
	}
}

func TestGitManager_GenerateAggregatedCommitMessage(t *testing.T) {
	tests := []struct {
		gitManager GitManager
		expected   string
	}{
		{gitManager: GitManager{}, expected: AggregatedPullRequestTitleTemplate},
		{gitManager: GitManager{customTemplates: CustomTemplates{commitMessageTemplate: "custom_template"}}, expected: "custom_template"},
	}
	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			commit := test.gitManager.GenerateAggregatedCommitMessage()
			assert.Equal(t, commit, test.expected)
		})
	}
}

func TestConvertSSHtoHTTPS(t *testing.T) {
	testsCases := []struct {
		repoName    string
		repoOwner   string
		projectName string
		expected    string
		apiEndpoint string
		vcsProvider vcsutils.VcsProvider
	}{
		{
			repoName:    "npmExample",
			repoOwner:   "repoOwner",
			expected:    "https://github.com/repoOwner/npmExample.git",
			apiEndpoint: "https://github.com",
			vcsProvider: vcsutils.GitHub,
		}, {
			repoName:    "npmExample",
			repoOwner:   "repoOwner",
			expected:    "https://api.github.com/repoOwner/npmExample.git",
			apiEndpoint: "https://api.github.com",
			vcsProvider: vcsutils.GitHub,
		},
		{
			repoName:    "npmProject",
			repoOwner:   "myTest5551218",
			apiEndpoint: "https://gitlab.com",
			expected:    "https://gitlab.com/myTest5551218/npmProject.git",
			vcsProvider: vcsutils.GitLab,
		}, {
			repoName:    "onPremProject",
			repoOwner:   "myTest5551218",
			apiEndpoint: "https://gitlab.example.com",
			expected:    "https://gitlab.example.com/myTest5551218/onPremProject.git",
			vcsProvider: vcsutils.GitLab,
		},
		{
			repoName:    "npmExample",
			projectName: "firstProject",
			repoOwner:   "azureReposOwner",
			apiEndpoint: "https://dev.azure.com/azureReposOwner/",
			expected:    "https://azureReposOwner@dev.azure.com/azureReposOwner/firstProject/_git/npmExample",
			vcsProvider: vcsutils.AzureRepos,
		}, {
			repoName:    "npmExample",
			projectName: "onPremProject",
			repoOwner:   "organization",
			apiEndpoint: "https://your-server-name:port/organization/",
			expected:    "https://organization@your-server-name:port/organization/onPremProject/_git/npmExample",
			vcsProvider: vcsutils.AzureRepos,
		},
		{
			repoName:    "npmExample",
			repoOwner:   "~bitbucketServerOwner", // Bitbucket server private projects owners start with ~ prefix.
			apiEndpoint: "https://git.company.info",
			expected:    "https://git.company.info/scm/~bitbucketServerOwner/npmExample.git",
			vcsProvider: vcsutils.BitbucketServer,
		}, {
			repoName:    "npmExample",
			repoOwner:   "bitbucketServerOwner", // Public on prem repo
			apiEndpoint: "https://git.company.info",
			expected:    "https://git.company.info/scm/bitbucketServerOwner/npmExample.git",
			vcsProvider: vcsutils.BitbucketServer,
		}, {
			repoName:    "notSupported",
			repoOwner:   "cloudOwner",
			expected:    "",
			vcsProvider: vcsutils.BitbucketCloud,
		},
	}
	for _, test := range testsCases {
		t.Run(test.vcsProvider.String(), func(t *testing.T) {
			gm := &Git{ClientInfo: ClientInfo{GitProvider: test.vcsProvider, RepoName: test.repoName, RepoOwner: test.repoOwner, VcsInfo: vcsclient.VcsInfo{Project: test.projectName, APIEndpoint: test.apiEndpoint}}}
			remoteUrl, err := gm.generateHTTPSCloneUrl()
			if remoteUrl == "" {
				assert.Equal(t, err.Error(), "unsupported version control provider: Bitbucket Cloud")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, remoteUrl)
			}
		})
	}
}

// Verifies HTTPS vs SSH & working dir is set properly
func TestIsValidGitRepository(t *testing.T) {
	testsCases := []struct {
		folderName    string
		expectedValid bool
	}{
		{folderName: "sshRemoteUrls", expectedValid: false},
		{folderName: "httpsRemoteUrls", expectedValid: true},
	}
	// In order to use PrepareTestEnvironment
	err := os.Chdir("../")
	assert.NoError(t, err)
	for _, test := range testsCases {
		t.Run(test.folderName, func(t *testing.T) {
			_, cleanUp := PrepareTestEnvironment(t, test.folderName, "git")
			_, valid := isValidGitRepository(false)
			assert.Equal(t, test.expectedValid, valid)
			cleanUp()
		})
	}
}
