package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/frogbot/commands/utils/packagehandlers"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"golang.org/x/exp/slices"
	"os"
	"strings"
)

type CreateFixPullRequestsCmd struct {
	// The interface that Frogbot utilizes to format and style the displayed messages on the Git providers
	utils.OutputWriter
	// dryRun is used for testing purposes, mocking part of the git commands that requires networking
	dryRun bool
	// When dryRun is enabled, dryRunRepoPath specifies the repository local path to clone
	dryRunRepoPath string
	// The details of the current scan
	details *utils.ScanDetails
	// The current project working directory
	projectWorkingDir string
	// The git client the command performs git operations with
	gitManager *utils.GitManager
	// Determines whether to open a pull request for each vulnerability fix or to aggregate all fixes into one pull request
	aggregateFixes bool
	// Stores all package manager handlers for detected issues
	handlers map[coreutils.Technology]packagehandlers.PackageHandler
}

func (cfp *CreateFixPullRequestsCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repository := configAggregator[0]
	for _, branch := range repository.Branches {
		err := cfp.scanAndFixRepository(&repository, branch, client)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repository *utils.Repository, branch string, client vcsclient.VcsClient) error {
	baseWd, err := os.Getwd()
	if err != nil {
		return err
	}
	cfp.details = utils.NewScanDetails(client, &repository.Server, &repository.Git).
		SetXrayGraphScanParams(repository.Watches, repository.JFrogProjectKey).
		SetFailOnInstallationErrors(*repository.FailOnSecurityIssues).
		SetBranch(branch).
		SetReleasesRepo(repository.JfrogReleasesRepo).
		SetFixableOnly(repository.FixableOnly).
		SetMinSeverity(repository.MinSeverity)
	cfp.aggregateFixes = repository.Git.AggregateFixes
	cfp.OutputWriter = utils.GetCompatibleOutputWriter(cfp.details.GitProvider)
	for i := range repository.Projects {
		cfp.details.Project = &repository.Projects[i]
		projectFullPathWorkingDirs := getFullPathWorkingDirs(cfp.details.Project.WorkingDirs, baseWd)
		for _, fullPathWd := range projectFullPathWorkingDirs {
			scanResults, err := cfp.scan(fullPathWd)
			if err != nil {
				return err
			}
			cfp.OutputWriter.SetEntitledForJas(scanResults.ExtendedScanResults.EntitledForJas)

			err = utils.UploadScanToGitProvider(scanResults, repository, cfp.details.Branch(), cfp.details.Client())
			if err != nil {
				log.Warn(err)
			}

			// Update the working directory to the project current working directory
			cfp.projectWorkingDir = utils.GetRelativeWd(fullPathWd, baseWd)
			// Fix and create PRs
			if err = cfp.fixImpactedPackagesAndCreatePRs(scanResults.ExtendedScanResults, scanResults.IsMultipleRootProject); err != nil {
				return err
			}
		}
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(currentWorkingDir string) (*audit.Results, error) {
	// Audit commit code
	auditResults, err := runInstallAndAudit(cfp.details, currentWorkingDir)
	if err != nil {
		return nil, err
	}
	log.Info("Xray scan completed")
	return auditResults, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(scanResults *xrayutils.ExtendedScanResults, isMultipleRoots bool) (err error) {
	vulnerabilitiesMap, err := cfp.createVulnerabilitiesMap(scanResults, isMultipleRoots)
	if err != nil {
		return err
	}

	// Nothing to fix, return
	if len(vulnerabilitiesMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.details.RepoName)
		return nil
	}

	log.Debug("Found", len(vulnerabilitiesMap), "vulnerable dependencies with fix versions")
	return cfp.fixVulnerablePackages(vulnerabilitiesMap)
}

func (cfp *CreateFixPullRequestsCmd) fixVulnerablePackages(vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) (err error) {
	cfp.gitManager, err = utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", cfp.details.Token, cfp.details.Username, cfp.details.Git)
	if err != nil {
		return
	}

	clonedRepoDir, restoreBaseDir, err := cfp.cloneRepository()
	if err != nil {
		return
	}
	defer func() {
		if cfp.dryRun {
			// On dry runs temp folders are nested inside the main temp folder
			return
		}
		err = errors.Join(err, restoreBaseDir(), fileutils.RemoveTempDir(clonedRepoDir))
	}()
	if cfp.aggregateFixes {
		return cfp.fixIssuesSinglePR(vulnerabilitiesMap)
	}
	return cfp.fixIssuesSeparatePRs(vulnerabilitiesMap)
}

func (cfp *CreateFixPullRequestsCmd) fixIssuesSeparatePRs(vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) (err error) {
	var errList strings.Builder
	if len(vulnerabilitiesMap) == 0 {
		return
	}
	log.Info("-----------------------------------------------------------------")
	for _, vulnDetails := range vulnerabilitiesMap {
		if err = cfp.fixSinglePackageAndCreatePR(vulnDetails); err != nil {
			cfp.handleUpdatePackageErrors(err, errList)
		}
		// After finishing to work on the current vulnerability, we go back to the base branch to start the next vulnerability fix
		log.Debug("Running git checkout to base branch:", cfp.details.Branch())
		if err = cfp.gitManager.Checkout(cfp.details.Branch()); err != nil {
			return
		}
	}
	logAppendedErrorsIfExists(errList)
	log.Info("-----------------------------------------------------------------")
	return
}

// Fix all the issues in one pull request.
// In case of existing aggregated fix, check for different scan results
// if scan results are the same, do nothing.
// Else, force push to the same branch to update
// Only one aggregated pull request should be open at all times.
func (cfp *CreateFixPullRequestsCmd) fixIssuesSinglePR(vulnerabilities map[string]*utils.VulnerabilityDetails) (err error) {
	aggregatedFixBranchName, err := cfp.gitManager.GenerateAggregatedFixBranchName()
	if err != nil {
		return
	}
	pullRequestExists, err := cfp.checkActivePullRequestByBranchName(aggregatedFixBranchName)
	if err != nil {
		return
	}
	if pullRequestExists {
		if identicalScanResults, err := cfp.compareScanResults(vulnerabilities, aggregatedFixBranchName); identicalScanResults || err != nil {
			return err
		}
	}
	return cfp.aggregateFixAndOpenPullRequest(vulnerabilities, aggregatedFixBranchName)
}

// Handles possible error of update package operation
// When the expected custom error occurs, log to debug.
// else, append to errList string
func (cfp *CreateFixPullRequestsCmd) handleUpdatePackageErrors(err error, errList strings.Builder) {
	if _, isCustomError := err.(*utils.ErrUnsupportedFix); isCustomError {
		log.Debug(err.Error())
	} else {
		errList.WriteString(err.Error() + "\n")
	}
}

// Creates a branch for the fixed package and open pull request against the target branch.
// In case a branch already exists on remote, we skip it.
func (cfp *CreateFixPullRequestsCmd) fixSinglePackageAndCreatePR(vulnDetails *utils.VulnerabilityDetails) (err error) {
	fixVersion := vulnDetails.FixVersion
	log.Debug("Start fixing", vulnDetails.ImpactedDependencyName, "with", fixVersion)
	fixBranchName, err := cfp.gitManager.GenerateFixBranchName(cfp.details.Branch(), vulnDetails.ImpactedDependencyName, fixVersion)
	if err != nil {
		return
	}
	existsInRemote, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	if existsInRemote {
		log.Info(fmt.Sprintf("A Pull Request updating dependency '%s' to version '%s' already exists.", vulnDetails.ImpactedDependencyName, vulnDetails.FixVersion))
		return
	}
	log.Debug("Creating branch", fixBranchName, "...")
	if err = cfp.gitManager.CreateBranchAndCheckout(fixBranchName); err != nil {
		return fmt.Errorf("failed while creating new branch: \n%s", err.Error())
	}
	if err = cfp.updatePackageToFixedVersion(vulnDetails); err != nil {
		return
	}
	if err = cfp.openFixingPullRequest(fixBranchName, vulnDetails); err != nil {
		return fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: \n%s",
			vulnDetails.ImpactedDependencyName, fixVersion, err.Error())
	}
	log.Info(fmt.Sprintf("Created Pull Request updating dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.FixVersion))
	return
}

func (cfp *CreateFixPullRequestsCmd) openFixingPullRequest(fixBranchName string, vulnDetails *utils.VulnerabilityDetails) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", vulnDetails.ImpactedDependencyName)
	}

	commitMessage := cfp.gitManager.GenerateCommitMessage(vulnDetails.ImpactedDependencyName, vulnDetails.FixVersion)
	log.Debug("Running git add all and commit...")
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}

	log.Debug("Pushing branch:", fixBranchName, "...")
	if err = cfp.gitManager.Push(false, fixBranchName); err != nil {
		return
	}

	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(vulnDetails.ImpactedDependencyName, vulnDetails.FixVersion)
	log.Debug("Creating Pull Request form:", fixBranchName, " to:", cfp.details.Branch())

	prBody := cfp.OutputWriter.Content([]formats.VulnerabilityOrViolationRow{*vulnDetails.VulnerabilityOrViolationRow})
	return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), pullRequestTitle, prBody)
}

// When aggregate mode is active, there can be only one updated pull request to contain all the available fixes.
// In case of an already opened pull request, Frogbot will only update the branch.
func (cfp *CreateFixPullRequestsCmd) openAggregatedPullRequest(fixBranchName string, vulnerabilities []formats.VulnerabilityOrViolationRow) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		log.Debug("Couldn't fix any of the impacted dependencies")
		return
	}
	commitMessage := cfp.gitManager.GenerateAggregatedCommitMessage()
	log.Debug("Running git add all and commit...")
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	log.Debug("Pushing branch:", fixBranchName, "...")
	if err = cfp.gitManager.Push(true, fixBranchName); err != nil {
		return
	}

	log.Info("Creating Pull Request from:", fixBranchName, "to:", cfp.details.Branch())
	prBody := cfp.OutputWriter.Content(vulnerabilities)
	return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), utils.AggregatedPullRequestTitleTemplate, prBody)
}

func (cfp *CreateFixPullRequestsCmd) cloneRepository() (tempWd string, restoreDir func() error, err error) {
	if cfp.dryRunRepoPath != "" {
		// On dry run, create the temp folder nested in the current folder
		tempWd, err = os.MkdirTemp(cfp.dryRunRepoPath, "nested-temp.")
	} else {
		// Create temp working directory
		tempWd, err = fileutils.CreateTempDir()
	}
	if err != nil {
		return
	}
	log.Debug("Created temp working directory:", tempWd)

	// Clone the content of the repo to the new working directory
	if err = cfp.gitManager.Clone(tempWd, cfp.details.Branch()); err != nil {
		return
	}

	// 'CD' into the temp working directory
	restoreDir, err = utils.Chdir(tempWd)
	return
}

// Create a vulnerabilities map - a map with 'impacted package' as a key and all the necessary information of this vulnerability as value.
func (cfp *CreateFixPullRequestsCmd) createVulnerabilitiesMap(scanResults *xrayutils.ExtendedScanResults, isMultipleRoots bool) (map[string]*utils.VulnerabilityDetails, error) {
	fixVersionsMap := map[string]*utils.VulnerabilityDetails{}
	for _, scanResult := range scanResults.XrayResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, scanResults, isMultipleRoots, true)
			if err != nil {
				return nil, err
			}
			for i := range vulnerabilities {
				if err = cfp.addVulnerabilityToFixVersionsMap(&vulnerabilities[i], fixVersionsMap); err != nil {
					return nil, err
				}
			}
		}
	}
	return fixVersionsMap, nil
}

func (cfp *CreateFixPullRequestsCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, vulnerabilitiesMap map[string]*utils.VulnerabilityDetails) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}
	if vulnDetails, exists := vulnerabilitiesMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
		vulnDetails.UpdateFixVersionIfMax(vulnFixVersion)
	} else {
		isDirectDependency, err := utils.IsDirectDependency(vulnerability.ImpactPaths)
		if err != nil {
			return err
		}
		// First appearance of a version that fixes the current impacted package
		newVulnDetails := utils.NewVulnerabilityDetails(vulnerability, vulnFixVersion)
		newVulnDetails.SetIsDirectDependency(isDirectDependency)
		newVulnDetails.SetCves(vulnerability.Cves)
		vulnerabilitiesMap[vulnerability.ImpactedDependencyName] = newVulnDetails
	}
	// Set the fixed version array to the relevant fixed version so that only that specific fixed version will be displayed
	vulnerability.FixedVersions = []string{vulnerabilitiesMap[vulnerability.ImpactedDependencyName].FixVersion}
	return nil
}

// Updates impacted package, can return ErrUnsupportedFix.
func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(vulnDetails *utils.VulnerabilityDetails) (err error) {
	// 'CD' into the relevant working directory
	if cfp.projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(cfp.projectWorkingDir)
		if err != nil {
			return err
		}
		defer func() {
			err = errors.Join(err, restoreDir())
		}()
	}
	if err = isBuildToolsDependency(vulnDetails); err != nil {
		return
	}
	if cfp.handlers == nil {
		cfp.handlers = make(map[coreutils.Technology]packagehandlers.PackageHandler)
	}
	if cfp.handlers[vulnDetails.Technology] == nil {
		cfp.handlers[vulnDetails.Technology] = packagehandlers.GetCompatiblePackageHandler(vulnDetails, cfp.details)
	}
	return cfp.handlers[vulnDetails.Technology].UpdateDependency(vulnDetails)
}

// Computes the MD5 hash of a FixVersionMap object originated from the remote branch's scan results
func (cfp *CreateFixPullRequestsCmd) getRemoteBranchScanHash(remoteBranchName string) (hash string, err error) {
	cfp.details = utils.NewScanDetails(cfp.details.Client(), cfp.details.ServerDetails, cfp.details.Git).
		SetProject(cfp.details.Project).
		SetReleasesRepo(cfp.details.ReleasesRepo()).
		SetXrayGraphScanParams(cfp.details.Watches, cfp.details.ProjectKey).
		SetMinSeverity(cfp.details.MinSeverityFilter()).
		SetFixableOnly(cfp.details.FixableOnly()).
		SetBranch(remoteBranchName)
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	res, err := cfp.scan(wd)
	if err != nil {
		return
	}
	targetFixVersionMap, err := cfp.createVulnerabilitiesMap(res.ExtendedScanResults, res.IsMultipleRootProject)
	if err != nil {
		return
	}
	return utils.FixVersionsMapToMd5Hash(targetFixVersionMap)
}

func (cfp *CreateFixPullRequestsCmd) checkActivePullRequestByBranchName(branchName string) (exists bool, err error) {
	list, err := cfp.details.Client().ListOpenPullRequests(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName)
	if err != nil {
		return
	}
	for _, pr := range list {
		if pr.Source.Name == branchName {
			exists = true
			return
		}
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) aggregateFixAndOpenPullRequest(vulnerabilities map[string]*utils.VulnerabilityDetails, aggregatedFixBranchName string) (err error) {
	var errList strings.Builder
	var atLeastOneFix bool
	log.Info("-----------------------------------------------------------------")
	log.Info("Starting aggregated dependencies fix")
	log.Debug("Creating branch", aggregatedFixBranchName, "...")
	if err = cfp.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName); err != nil {
		return
	}
	// Fix all packages in the same branch if expected error accrued, log and continue.
	var fixedVulnerabilities []formats.VulnerabilityOrViolationRow
	for _, vulnDetails := range vulnerabilities {
		if err = cfp.updatePackageToFixedVersion(vulnDetails); err != nil {
			cfp.handleUpdatePackageErrors(err, errList)
		} else {
			vulnDetails.FixedVersions = []string{vulnDetails.FixVersion}
			fixedVulnerabilities = append(fixedVulnerabilities, *vulnDetails.VulnerabilityOrViolationRow)
			log.Info(fmt.Sprintf("Updated dependency '%s' to version '%s'", vulnDetails.ImpactedDependencyName, vulnDetails.FixVersion))
			atLeastOneFix = true
		}
	}
	if atLeastOneFix {
		if err = cfp.openAggregatedPullRequest(aggregatedFixBranchName, fixedVulnerabilities); err != nil {
			return fmt.Errorf("failed while creating aggreagted pull request. Error: \n%s", err.Error())
		}
	}
	logAppendedErrorsIfExists(errList)
	log.Info("-----------------------------------------------------------------")
	return
}

// Compares the scan results of a remote branch by computing the MD5 hash of the created FixVersionMap.
func (cfp *CreateFixPullRequestsCmd) compareScanResults(fixVersionsMap map[string]*utils.VulnerabilityDetails, aggregatedFixBranchName string) (identical bool, err error) {
	currentScanHash, err := utils.FixVersionsMapToMd5Hash(fixVersionsMap)
	if err != nil {
		return
	}
	remoteBranchScanHash, err := cfp.getRemoteBranchScanHash(aggregatedFixBranchName)
	if err != nil {
		return
	}
	if currentScanHash == remoteBranchScanHash {
		log.Info("The scan results have not changed since the last Frogbot run.")
		identical = true
		return
	}
	return
}

func isBuildToolsDependency(vulnDetails *utils.VulnerabilityDetails) error {
	// Skip build tools dependencies (for example, pip)
	// that are not defined in the descriptor file and cannot be fixed by a PR.
	if slices.Contains(utils.BuildToolsDependenciesMap[vulnDetails.Technology], vulnDetails.ImpactedDependencyName) {
		return &utils.ErrUnsupportedFix{
			PackageName:  vulnDetails.ImpactedDependencyName,
			FixedVersion: vulnDetails.FixVersion,
			ErrorType:    utils.BuildToolsDependencyFixNotSupported,
		}
	}
	return nil
}

// getMinimalFixVersion find the minimal version that fixes the current impactedPackage;
// fixVersions is a sorted array. The function returns the first version in the array, that is larger than impactedPackageVersion.
func getMinimalFixVersion(impactedPackageVersion string, fixVersions []string) string {
	// Trim 'v' prefix in case of Go package
	currVersionStr := strings.TrimPrefix(impactedPackageVersion, "v")
	currVersion := version.NewVersion(currVersionStr)
	for _, fixVersion := range fixVersions {
		fixVersionCandidate := parseVersionChangeString(fixVersion)
		if currVersion.Compare(fixVersionCandidate) > 0 {
			return fixVersionCandidate
		}
	}
	return ""
}

// 1.0         --> 1.0 ≤ x
// (,1.0]      --> x ≤ 1.0
// (,1.0)      --> x &lt; 1.0
// [1.0]       --> x == 1.0
// (1.0,)      --> 1.0 &lt; x
// (1.0, 2.0)  --> 1.0 &lt; x &lt; 2.0
// [1.0, 2.0]  --> 1.0 ≤ x ≤ 2.0
func parseVersionChangeString(fixVersion string) string {
	latestVersion := strings.Split(fixVersion, ",")[0]
	if latestVersion[0] == '(' {
		return ""
	}
	latestVersion = strings.Trim(latestVersion, "[")
	latestVersion = strings.Trim(latestVersion, "]")
	return latestVersion
}

// During the operation of updating packages, there could be some errors,
// in order to not fail the whole run, we store the errors in strings.builder and log them at the end.
func logAppendedErrorsIfExists(errList strings.Builder) {
	if errList.String() != "" {
		log.Error("During fixing dependencies operations the following errors occurred:\n", errors.New(errList.String()))
	}
}
