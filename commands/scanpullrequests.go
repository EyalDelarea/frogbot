package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"os"
	"sort"
	"strings"

	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
)

var errPullRequestScan = "pull Request number %d in repository %s returned the following error: \n%s\n"

type ScanAllPullRequestsCmd struct {
	scanResults map[string]*ScannedProjectInfo
	scanPrCmd   *ScanPullRequestCmd
}

func (cmd ScanAllPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	cmd.scanResults = make(map[string]*ScannedProjectInfo)
	cmd.scanPrCmd = &ScanPullRequestCmd{}
	for _, config := range configAggregator {
		err := cmd.scanAllPullRequests(config, client)
		if err != nil {
			return err
		}
	}
	return nil
}

// Scan pull requests as follows:
// a. Clone the repository
// b. Retrieve all open pull requests
// c. Find the ones that should be scanned (new PRs or PRs with a 're-scan' comment)
// d. Audit the dependencies of the source and the target branches.
// e. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
func (cmd ScanAllPullRequestsCmd) scanAllPullRequests(repo utils.Repository, client vcsclient.VcsClient) (err error) {
	wd, err := fileutils.CreateTempDir()
	if err != nil {
		return
	}
	defer func() {
		err = errors.Join(err, fileutils.RemoveTempDir(wd))
	}()
	log.Debug("Created temp working directory: ", wd)
	cmd.scanPrCmd.gitManager, err = utils.NewGitManager(false, "", "", "origin", &repo.Git)
	if err != nil {
		return
	}
	if err = os.Chdir(wd); err != nil {
		return
	}
	baseBranch := repo.Branches[0]
	if err = cmd.scanPrCmd.gitManager.Clone(wd, baseBranch); err != nil {
		return
	}
	openPullRequests, err := client.ListOpenPullRequests(context.Background(), repo.RepoOwner, repo.RepoName)
	if err != nil {
		return err
	}

	// Scan All Pull requests
	for _, pr := range openPullRequests {
		repo.PullRequestID = int(pr.ID)
		shouldScan, e := shouldScanPullRequest(repo, client, int(pr.ID))
		if e != nil {
			err = errors.Join(e)
		}
		if !shouldScan {
			continue
		}
		if e = cmd.scanPrCmd.scanPullRequest(&repo, &pr, client); e != nil {
			err = errors.Join(err, fmt.Errorf(errPullRequestScan, int(pr.ID), repo.RepoName, e.Error()))
		}
	}
	return
}

func shouldScanPullRequest(repo utils.Repository, client vcsclient.VcsClient, prID int) (shouldScan bool, err error) {
	pullRequestsComments, err := client.ListPullRequestComments(context.Background(), repo.RepoOwner, repo.RepoName, prID)
	if err != nil {
		return
	}
	// Sort the comment according to time created, the newest comment should be the first one.
	sort.Slice(pullRequestsComments, func(i, j int) bool {
		return pullRequestsComments[i].Created.After(pullRequestsComments[j].Created)
	})

	for _, comment := range pullRequestsComments {
		// If this a 're-scan' request comment
		if isFrogbotRescanComment(comment.Content) {
			return true, nil
		}
		// if this is a Frogbot 'scan results' comment and not 're-scan' request comment, do not scan this pull request.
		if repo.OutputWriter.IsFrogbotResultComment(comment.Content) {
			return false, nil
		}
	}
	// This is a new pull request, and it therefore should be scanned.
	return true, nil
}

func isFrogbotRescanComment(comment string) bool {
	return strings.Contains(strings.ToLower(strings.TrimSpace(comment)), utils.RescanRequestComment)
}

// TODO remove or use it
func (cmd ScanAllPullRequestsCmd) downloadAndScanPullRequest(pr vcsclient.PullRequestInfo, repo utils.Repository, client vcsclient.VcsClient) error {
	// Download the pull request source ("from") branch
	params := utils.Params{
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				GitProvider: repo.GitProvider,
				VcsInfo:     vcsclient.VcsInfo{APIEndpoint: repo.APIEndpoint, Token: repo.Token},
				RepoOwner:   repo.RepoOwner,
				RepoName:    pr.Source.Repository,
				Branches:    []string{pr.Source.Name}},
		}}
	frogbotParams := &utils.Repository{
		Server: repo.Server,
		Params: params,
	}
	wd, cleanup, err := utils.DownloadRepoToTempDir(client, pr.Source.Name, &frogbotParams.Git)
	if err != nil {
		return err
	}
	// Cleanup
	defer func() {
		err = errors.Join(err, cleanup())
	}()
	restoreDir, err := utils.Chdir(wd)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, restoreDir())
	}()
	// The target branch (to) will be downloaded as part of the Frogbot scanPullRequest execution
	params = utils.Params{
		Scan: utils.Scan{
			FailOnSecurityIssues:      repo.FailOnSecurityIssues,
			IncludeAllVulnerabilities: repo.IncludeAllVulnerabilities,
			Projects:                  repo.Projects,
		},
		Git: utils.Git{
			ClientInfo: utils.ClientInfo{
				GitProvider: repo.GitProvider,
				VcsInfo:     vcsclient.VcsInfo{APIEndpoint: repo.APIEndpoint, Token: repo.Token},
				RepoOwner:   repo.RepoOwner,
				Branches:    []string{pr.Target.Name},
				RepoName:    pr.Target.Repository,
			},
			PullRequestID: int(pr.ID),
		},
		JFrogPlatform: utils.JFrogPlatform{
			Watches:         repo.Watches,
			JFrogProjectKey: repo.JFrogProjectKey,
		},
	}

	frogbotParams = &utils.Repository{
		OutputWriter: utils.GetCompatibleOutputWriter(repo.GitProvider),
		Server:       repo.Server,
		Params:       params,
	}

	scanPullRequestCmd := &ScanPullRequestCmd{}
	if results, exists := cmd.scanResults[pr.Target.Name]; exists {
		scanPullRequestCmd.ScannedProjectInfo = *results
		scanPullRequestCmd.branchName = pr.Target.Name
	}

	if err = scanPullRequestCmd.scanPullRequest(frogbotParams, nil, client); err == nil {
		// Save targets scan results to avoid rescans
		cmd.scanResults[scanPullRequestCmd.branchName] = &scanPullRequestCmd.ScannedProjectInfo
	}
	return err
}
