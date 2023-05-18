package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/frogbot/commands/utils/packagehandlers"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"golang.org/x/exp/slices"
	"os"
	"strings"
)

type CreateFixPullRequestsCmd struct {
	// mavenDepToPropertyMap holds a map of direct dependencies found in pom.xml.
	// Keys values are only set if the key version is a property.
	mavenDepToPropertyMap map[string][]string
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
	// Determines whether to open a pull request for each vulnerability fix or to aggregate all fixes into one pull request.
	aggregateFixes bool
}

func (cfp *CreateFixPullRequestsCmd) Run(configAggregator utils.FrogbotConfigAggregator, client vcsclient.VcsClient) error {
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

func (cfp *CreateFixPullRequestsCmd) scanAndFixRepository(repository *utils.FrogbotRepoConfig, branch string, client vcsclient.VcsClient) error {
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
	for i := range repository.Projects {
		cfp.details.Project = &repository.Projects[i]
		projectFullPathWorkingDirs := getFullPathWorkingDirs(cfp.details.Project.WorkingDirs, baseWd)
		for _, fullPathWd := range projectFullPathWorkingDirs {
			scanResults, isMultipleRoots, err := cfp.scan(cfp.details, fullPathWd)
			if err != nil {
				return err
			}

			err = utils.UploadScanToGitProvider(scanResults, repository, cfp.details.Branch(), cfp.details.Client(), isMultipleRoots)
			if err != nil {
				log.Warn(err)
			}

			// Update the working directory to the project current working directory
			cfp.projectWorkingDir = utils.GetRelativeWd(fullPathWd, baseWd)
			// Fix and create PRs
			if err = cfp.fixImpactedPackagesAndCreatePRs(scanResults, isMultipleRoots); err != nil {
				return err
			}
		}
	}
	return nil
}

// Audit the dependencies of the current commit.
func (cfp *CreateFixPullRequestsCmd) scan(scanSetup *utils.ScanDetails, currentWorkingDir string) ([]services.ScanResponse, bool, error) {
	// Audit commit code
	scanResults, isMultipleRoots, err := runInstallAndAudit(scanSetup, currentWorkingDir)
	if err != nil {
		return nil, false, err
	}
	log.Info("Xray scan completed")
	return scanResults, isMultipleRoots, nil
}

func (cfp *CreateFixPullRequestsCmd) fixImpactedPackagesAndCreatePRs(scanResults []services.ScanResponse, isMultipleRoots bool) (err error) {
	fixVersionsMap, err := cfp.createFixVersionsMap(scanResults, isMultipleRoots)
	if err != nil {
		return err
	}

	// Nothing to fix, return
	if len(fixVersionsMap) == 0 {
		log.Info("Didn't find vulnerable dependencies with existing fix versions for", cfp.details.RepoName)
		return nil
	}

	log.Debug("Found", len(fixVersionsMap), "vulnerable dependencies with fix versions")
	return cfp.fixVulnerablePackages(fixVersionsMap)
}

func (cfp *CreateFixPullRequestsCmd) fixVulnerablePackages(fixVersionsMap map[string]*utils.FixDetails) (err error) {
	cfp.gitManager, err = utils.NewGitManager(cfp.dryRun, cfp.dryRunRepoPath, ".", "origin", cfp.details.Token, cfp.details.Username, cfp.details.Git)
	if err != nil {
		return
	}

	clonedRepoDir, restoreBaseDir, err := cfp.cloneRepository()
	if err != nil {
		return
	}
	defer func() {
		e1 := restoreBaseDir()
		e2 := fileutils.RemoveTempDir(clonedRepoDir)
		if err == nil {
			err = e1
			if err == nil {
				err = e2
			}
		}
	}()
	if cfp.aggregateFixes {
		err = cfp.fixIssuesSinglePR(fixVersionsMap)
	} else {
		err = cfp.fixIssuesSeparatePRs(fixVersionsMap)
	}
	return
}

func (cfp *CreateFixPullRequestsCmd) fixIssuesSeparatePRs(fixVersionsMap map[string]*utils.FixDetails) (err error) {
	var errList strings.Builder
	log.Info("-----------------------------------------------------------------")
	for _, fixVersionInfo := range fixVersionsMap {
		if err = cfp.fixSinglePackageAndCreatePR(fixVersionInfo); err != nil {
			if customErr, ok := err.(*utils.ErrUnsupportedFix); ok {
				log.Debug(customErr.Error())
				continue
			} else {
				errList.WriteString(err.Error())
			}
		}
		// After finishing to work on the current vulnerability, we go back to the base branch to start the next vulnerability fix
		log.Debug("Running git checkout to base branch:", cfp.details.Branch())
		log.Debug("-----------------------------------------------------------------")
		if err = cfp.gitManager.Checkout(cfp.details.Branch()); err != nil {
			return
		}
	}
	if errList.String() != "" {
		return errors.New(errList.String())
	}
	log.Info("-----------------------------------------------------------------")
	return
}

func (cfp *CreateFixPullRequestsCmd) fixIssuesSinglePR(fixVersionsMap map[string]*utils.FixDetails) (err error) {
	var errList strings.Builder
	amountOfFixePackage := 0
	log.Info("-----------------------------------------------------------------")
	log.Info("Starting aggregated dependencies fix")
	aggregatedFixBranchName, err := cfp.gitManager.GenerateAggregatedFixBranchName(fixVersionsMap)
	if err != nil {
		return
	}
	log.Debug("Creating branch", aggregatedFixBranchName, "...")
	err = cfp.gitManager.CreateBranchAndCheckout(aggregatedFixBranchName)
	if err != nil {
		return
	}

	// Fix all packages in the same branch
	for _, fixDetails := range fixVersionsMap {
		err := cfp.updatePackageToFixedVersion(fixDetails)
		if customErr, ok := err.(*utils.ErrUnsupportedFix); ok {
			log.Debug(customErr.Error())
			continue
		}
		if err != nil {
			errList.WriteString(err.Error())
		}

		logMessage := fmt.Sprintf("Updated dependency '%s' to version '%s'", fixDetails.ImpactedDependency, fixDetails.FixVersion)
		log.Info(logMessage)
		amountOfFixePackage += 1
	}
	// Verify fixes were made
	if amountOfFixePackage == 0 {
		// No packages were updated, don't attempt open PR.
		log.Debug("Couldn't fix any of the impacted dependencies")
		return
	}
	if err = cfp.openAggregatedPullRequest(aggregatedFixBranchName); err != nil {
		return fmt.Errorf("failed while creating aggreagted pull request. Error: \n%s", err.Error())
	}
	// Log fix attempts errors
	if errList.String() != "" {
		log.Error(errors.New(errList.String()))
	}
	log.Info("-----------------------------------------------------------------")
	return
}

// Creates a branch for the fixed package and open pull request against the target branch.
// In case branch already exists on remote, we skip it.
func (cfp *CreateFixPullRequestsCmd) fixSinglePackageAndCreatePR(fixDetails *utils.FixDetails) (err error) {
	fixVersion := fixDetails.FixVersion
	log.Debug("Start fixing", fixDetails.ImpactedDependency, "with", fixVersion)
	fixBranchName, err := cfp.gitManager.GenerateFixBranchName(cfp.details.Branch(), fixDetails.ImpactedDependency, fixVersion)
	if err != nil {
		return
	}
	existsInRemote, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	if existsInRemote {
		logMessage := fmt.Sprintf("A Pull Request updating dependency '%s' to version '%s' already exists.", fixDetails.ImpactedDependency, fixDetails.FixVersion)
		log.Info(logMessage)
		return
	}
	log.Debug("Creating branch", fixBranchName, "...")
	if err = cfp.gitManager.CreateBranchAndCheckout(fixBranchName); err != nil {
		return fmt.Errorf("failed while creating new branch: \n%s", err.Error())
	}
	if err = cfp.updatePackageToFixedVersion(fixDetails); err != nil {
		return
	}
	if err = cfp.openFixingPullRequest(fixBranchName, fixDetails); err != nil {
		return fmt.Errorf("failed while creating a fixing pull request for: %s with version: %s with error: \n%s",
			fixDetails.ImpactedDependency, fixVersion, err.Error())
	}
	logMessage := fmt.Sprintf("Created Pull Request updating dependency '%s' to version '%s'", fixDetails.ImpactedDependency, fixDetails.FixVersion)
	log.Info(logMessage)
	return
}

func (cfp *CreateFixPullRequestsCmd) openFixingPullRequest(fixBranchName string, fixDetails *utils.FixDetails) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		return fmt.Errorf("there were no changes to commit after fixing the package '%s'", fixDetails.ImpactedDependency)
	}

	commitMessage := cfp.gitManager.GenerateCommitMessage(fixDetails.ImpactedDependency, fixDetails.FixVersion)
	log.Debug("Running git add all and commit...")
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}

	log.Debug("Pushing branch:", fixBranchName, "...")
	if err = cfp.gitManager.Push(false, fixBranchName); err != nil {
		return
	}

	pullRequestTitle := cfp.gitManager.GeneratePullRequestTitle(fixDetails.ImpactedDependency, fixDetails.FixVersion)
	log.Debug("Creating Pull Request form:", fixBranchName, " to:", cfp.details.Branch())

	prBody := commitMessage + "\n\n" + utils.WhatIsFrogbotMd
	return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), pullRequestTitle, prBody)
}

// When aggregate mode is active, there can be only one updated pull request to contain all the available fixes.
// In case of an already opened pull request, Frogbot will only update the branch.
func (cfp *CreateFixPullRequestsCmd) openAggregatedPullRequest(fixBranchName string) (err error) {
	log.Debug("Checking if there are changes to commit")
	isClean, err := cfp.gitManager.IsClean()
	if err != nil {
		return
	}
	if isClean {
		return fmt.Errorf("there were no changes in the fix branch '%s'", fixBranchName)
	}
	commitMessage := cfp.gitManager.GenerateAggregatedCommitMessage()
	log.Debug("Running git add all and commit...")
	if err = cfp.gitManager.AddAllAndCommit(commitMessage); err != nil {
		return
	}
	exists, err := cfp.gitManager.BranchExistsInRemote(fixBranchName)
	if err != nil {
		return
	}
	log.Debug("Pushing branch:", fixBranchName, "...")
	if err = cfp.gitManager.Push(true, fixBranchName); err != nil {
		return
	}
	if !exists {
		log.Info("Creating Pull Request from:", fixBranchName, "to:", cfp.details.Branch())
		prBody := commitMessage + "\n\n" + utils.WhatIsFrogbotMd
		return cfp.details.Client().CreatePullRequest(context.Background(), cfp.details.RepoOwner, cfp.details.RepoName, fixBranchName, cfp.details.Branch(), utils.AggregatedPullRequestTitleTemplate, prBody)
	}
	log.Info("Pull Request branch:", fixBranchName, "has been updated")
	return
}

func (cfp *CreateFixPullRequestsCmd) cloneRepository() (tempWd string, restoreDir func() error, err error) {
	// Create temp working directory
	tempWd, err = fileutils.CreateTempDir()
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

// Create fixVersionMap - a map with 'impacted package' as key and 'fix version' as value.
func (cfp *CreateFixPullRequestsCmd) createFixVersionsMap(scanResults []services.ScanResponse, isMultipleRoots bool) (map[string]*utils.FixDetails, error) {
	fixVersionsMap := map[string]*utils.FixDetails{}
	for _, scanResult := range scanResults {
		if len(scanResult.Vulnerabilities) > 0 {
			vulnerabilities, err := xrayutils.PrepareVulnerabilities(scanResult.Vulnerabilities, isMultipleRoots, true)
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

func (cfp *CreateFixPullRequestsCmd) addVulnerabilityToFixVersionsMap(vulnerability *formats.VulnerabilityOrViolationRow, fixVersionsMap map[string]*utils.FixDetails) error {
	if len(vulnerability.FixedVersions) == 0 {
		return nil
	}
	vulnFixVersion := getMinimalFixVersion(vulnerability.ImpactedDependencyVersion, vulnerability.FixedVersions)
	if vulnFixVersion == "" {
		return nil
	}
	if fixVersionInfo, exists := fixVersionsMap[vulnerability.ImpactedDependencyName]; exists {
		// More than one vulnerability can exist on the same impacted package.
		// Among all possible fix versions that fix the above impacted package, we select the maximum fix version.
		fixVersionInfo.UpdateFixVersionIfMax(vulnFixVersion)
	} else {
		isDirectDependency, err := utils.IsDirectDependency(vulnerability.ImpactPaths)
		if err != nil {
			return err
		}
		// First appearance of a version that fixes the current impacted package
		fixVersionsMap[vulnerability.ImpactedDependencyName] = utils.NewFixDetails(vulnFixVersion, vulnerability.Technology, isDirectDependency, vulnerability.ImpactedDependencyName)
	}
	return nil
}

// Updates impacted package, can return ErrUnsupportedFix.
func (cfp *CreateFixPullRequestsCmd) updatePackageToFixedVersion(fixDetails *utils.FixDetails) (err error) {
	// 'CD' into the relevant working directory
	if cfp.projectWorkingDir != "" {
		restoreDir, err := utils.Chdir(cfp.projectWorkingDir)
		if err != nil {
			return err
		}
		defer func() {
			e := restoreDir()
			if err == nil {
				err = e
			} else if e != nil {
				err = fmt.Errorf("%s\n%s", err.Error(), e.Error())
			}
		}()
	}
	err = isBuildToolsDependency(fixDetails)
	if err != nil {
		return
	}
	packageHandler, err := packagehandlers.GetCompatiblePackageHandler(fixDetails, cfp.details, &cfp.mavenDepToPropertyMap)
	if err != nil {
		return
	}
	return packageHandler.UpdateDependency(fixDetails)
}

func isBuildToolsDependency(fixDetails *utils.FixDetails) error {
	// Skip build tools dependencies (for example, pip)
	// That are not defined in the descriptor file and cannot be fixed by a PR.
	if slices.Contains(utils.BuildToolsDependenciesMap[fixDetails.PackageType], fixDetails.ImpactedDependency) {
		return &utils.ErrUnsupportedFix{
			PackageName: fixDetails.ImpactedDependency,
			Reason: fmt.Sprintf("Skipping vulnerable package %s since it is not defined in your package descriptor file. "+
				"Update %s version to %s to fix this vulnerability.",
				fixDetails.ImpactedDependency, fixDetails.ImpactedDependency, fixDetails.FixVersion),
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
