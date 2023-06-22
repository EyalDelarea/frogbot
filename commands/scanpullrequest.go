package commands

import (
	"context"
	"errors"
	"fmt"
	"github.com/jfrog/frogbot/commands/utils"
	"github.com/jfrog/froggit-go/vcsclient"
	"github.com/jfrog/froggit-go/vcsutils"
	audit "github.com/jfrog/jfrog-cli-core/v2/xray/commands/audit/generic"
	"github.com/jfrog/jfrog-cli-core/v2/xray/formats"
	xrayutils "github.com/jfrog/jfrog-cli-core/v2/xray/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	securityIssueFoundErr    = "issues were detected by Frogbot\n You can avoid marking the Frogbot scan as failed by setting failOnSecurityIssues to false in the " + utils.FrogbotConfigFile + " file"
	installationCmdFailedErr = "Couldn't run the installation command on the base branch. Assuming new project in the source branch: "
	noGitHubEnvErr           = "frogbot did not scan this PR, because a GitHub Environment named 'frogbot' does not exist. Please refer to the Frogbot documentation for instructions on how to create the Environment"
	noGitHubEnvReviewersErr  = "frogbot did not scan this PR, because the existing GitHub Environment named 'frogbot' doesn't have reviewers selected. Please refer to the Frogbot documentation for instructions on how to create the Environment"
)

// ScannedProjectInfo Save scanned projects info to avoid rescans when executing scan-pull-requests command.
type ScannedProjectInfo struct {
	scanResults    []services.ScanResponse
	branchName     string
	isMultipleRoot bool
	projectIndex   int
}

func (spi *ScannedProjectInfo) shouldScanProject(branchName string, projectIndex int) bool {
	return spi.branchName != branchName || projectIndex != spi.projectIndex
}

func (spi *ScannedProjectInfo) setScannedProject(branchName string, projectIndex int) {
	spi.projectIndex, spi.branchName = projectIndex, branchName
}

type ScanPullRequestCmd struct {
	ScannedProjectInfo
	gitManager *utils.GitManager
	wd         string
}

// Run ScanPullRequest method only works for a single repository scan.
// Therefore, the first repository config represents the repository on which Frogbot runs, and it is the only one that matters.
func (cmd *ScanPullRequestCmd) Run(configAggregator utils.RepoAggregator, client vcsclient.VcsClient) error {
	cmd.projectIndex = -1
	if err := utils.ValidateSingleRepoConfiguration(&configAggregator); err != nil {
		return err
	}
	repoConfig := &(configAggregator)[0]
	if repoConfig.GitProvider == vcsutils.GitHub {
		if err := verifyGitHubFrogbotEnvironment(client, repoConfig); err != nil {
			return err
		}
	}
	// Init git manager in the current working dir
	// Using the first configAggregator as we are running on a single pull request
	gitManager, err := utils.NewGitManager(false, "", "", "origin", &configAggregator[0].Git)
	if err != nil {
		return err
	}
	cmd.gitManager = gitManager

	pullRequestDetails, err := client.GetPullRequest(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, repoConfig.PullRequestID)
	if err != nil {
		return err
	}
	return cmd.scanPullRequest(repoConfig, &pullRequestDetails, client)
}

// By default, includeAllVulnerabilities is set to false and the scan goes as follows:
// a. Audit the dependencies of the source and the target branches.
// b. Compare the vulnerabilities found in source and target branches, and show only the new vulnerabilities added by the pull request.
// Otherwise, only the source branch is scanned and all found vulnerabilities are being displayed.
func (cmd *ScanPullRequestCmd) scanPullRequest(repoConfig *utils.Repository, pullRequestDetails *vcsclient.PullRequestInfo, client vcsclient.VcsClient) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	cmd.wd = wd

	log.Info("---------------------------------------------------")
	log.Info(fmt.Sprintf("Scanning pull request ID: %d", pullRequestDetails.ID))
	log.Info("---------------------------------------------------")
	// Audit PR code
	vulnerabilitiesRows, err := cmd.auditPullRequest(repoConfig, pullRequestDetails, client)
	if err != nil {
		return err
	}

	// Create a pull request message
	message := createPullRequestMessage(vulnerabilitiesRows, repoConfig.OutputWriter)

	// Add comment to the pull request
	if err = client.AddPullRequestComment(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, message, repoConfig.PullRequestID); err != nil {
		return errors.New("couldn't add pull request comment: " + err.Error())
	}

	// Fail the Frogbot task if a security issue is found and Frogbot isn't configured to avoid the failure.
	if repoConfig.FailOnSecurityIssues != nil && *repoConfig.FailOnSecurityIssues && len(vulnerabilitiesRows) > 0 {
		err = errors.New(securityIssueFoundErr)
	}
	log.Info(fmt.Sprintf("Finished scanning pull request ID: %d", pullRequestDetails.ID))
	log.Info("---------------------------------------------------")
	return err
}

func (cmd *ScanPullRequestCmd) auditPullRequest(repoConfig *utils.Repository, prDetails *vcsclient.PullRequestInfo, client vcsclient.VcsClient) ([]formats.VulnerabilityOrViolationRow, error) {
	var vulnerabilitiesRows []formats.VulnerabilityOrViolationRow
	targetBranch := prDetails.Target.Name
	sourceBranch := prDetails.Source.Name
	for i := range repoConfig.Projects {
		// Scan source
		if err := cmd.gitManager.CheckoutRemoteBranch(sourceBranch); err != nil {
			return nil, fmt.Errorf("checkout to pull reuqest source branch failed with the following error: %s", err.Error())
		}
		scanDetails := utils.NewScanDetails(client, &repoConfig.Server, &repoConfig.Git).
			SetProject(&repoConfig.Projects[i]).
			SetReleasesRepo(repoConfig.JfrogReleasesRepo).
			SetXrayGraphScanParams(repoConfig.Watches, repoConfig.JFrogProjectKey).
			SetMinSeverity(repoConfig.MinSeverity).
			SetFixableOnly(repoConfig.FixableOnly).
			SetBranch(sourceBranch)
		sourceScan, isMultipleRoot, err := cmd.checkPathsAndAudit(scanDetails)
		if err != nil {
			return nil, err
		}

		if repoConfig.IncludeAllVulnerabilities {
			log.Info("Frogbot is configured to show all vulnerabilities")
			allIssuesRows, err := createAllIssuesRows(sourceScan, isMultipleRoot)
			if err != nil {
				return nil, err
			}
			vulnerabilitiesRows = append(vulnerabilitiesRows, allIssuesRows...)
			continue
		}
		// Audit target code if not provided with scan results
		scanDetails.SetFailOnInstallationErrors(*repoConfig.FailOnSecurityIssues)

		if cmd.shouldScanProject(targetBranch, i) {
			if err = cmd.gitManager.Checkout(targetBranch); err != nil {
				return nil, err
			}
			if cmd.scanResults, cmd.isMultipleRoot, err = cmd.checkPathsAndAudit(scanDetails); err != nil {
				return nil, err
			}
			cmd.setScannedProject(targetBranch, i)
		}
		newIssuesRows, err := createNewIssuesRows(cmd.scanResults, sourceScan, cmd.isMultipleRoot)
		if err != nil {
			return nil, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newIssuesRows...)
	}
	log.Info("Xray scan completed")
	return vulnerabilitiesRows, nil
}

// Verify that the 'frogbot' GitHub environment was properly configured on the repository
func verifyGitHubFrogbotEnvironment(client vcsclient.VcsClient, repoConfig *utils.Repository) error {
	if repoConfig.APIEndpoint != "" && repoConfig.APIEndpoint != "https://api.github.com" {
		// Don't verify 'frogbot' environment on GitHub on-prem
		return nil
	}
	if _, exist := os.LookupEnv(utils.GitHubActionsEnv); !exist {
		// Don't verify 'frogbot' environment on non GitHub Actions CI
		return nil
	}

	// If the repository is not public, using 'frogbot' environment is not mandatory
	repoInfo, err := client.GetRepositoryInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName)
	if err != nil {
		return err
	}
	if repoInfo.RepositoryVisibility != vcsclient.Public {
		return nil
	}

	// Get the 'frogbot' environment info and make sure it exists and includes reviewers
	repoEnvInfo, err := client.GetRepositoryEnvironmentInfo(context.Background(), repoConfig.RepoOwner, repoConfig.RepoName, "frogbot")
	if err != nil {
		return errors.New(err.Error() + "/n" + noGitHubEnvErr)
	}
	if len(repoEnvInfo.Reviewers) == 0 {
		return errors.New(noGitHubEnvReviewersErr)
	}

	return nil
}

// Create vulnerability rows. The rows should contain only the new issues added by this PR
func createNewIssuesRows(targetScan, sourceScan []services.ScanResponse, isMultipleRoot bool) (vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetScanAggregatedResults := aggregateScanResults(targetScan)
	sourceScanAggregatedResults := aggregateScanResults(sourceScan)

	if len(sourceScanAggregatedResults.Violations) > 0 {
		newViolations, err := getNewViolations(targetScanAggregatedResults, sourceScanAggregatedResults, isMultipleRoot)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newViolations...)
	} else if len(sourceScanAggregatedResults.Vulnerabilities) > 0 {
		newVulnerabilities, err := getNewVulnerabilities(targetScanAggregatedResults, sourceScanAggregatedResults, isMultipleRoot)
		if err != nil {
			return vulnerabilitiesRows, err
		}
		vulnerabilitiesRows = append(vulnerabilitiesRows, newVulnerabilities...)
	}

	return vulnerabilitiesRows, nil
}

func aggregateScanResults(scanResults []services.ScanResponse) services.ScanResponse {
	aggregateResults := services.ScanResponse{
		Violations:      []services.Violation{},
		Vulnerabilities: []services.Vulnerability{},
	}
	for _, scanResult := range scanResults {
		aggregateResults.Violations = append(aggregateResults.Violations, scanResult.Violations...)
		aggregateResults.Vulnerabilities = append(aggregateResults.Vulnerabilities, scanResult.Vulnerabilities...)
	}
	return aggregateResults
}

// Create vulnerability rows. The rows should contain all the issues that were found in this module scan.
func getScanVulnerabilitiesRows(violations []services.Violation, vulnerabilities []services.Vulnerability, isMultipleRoot bool) ([]formats.VulnerabilityOrViolationRow, error) {
	if len(violations) > 0 {
		violationsRows, _, _, err := xrayutils.PrepareViolations(violations, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
		return violationsRows, err
	}
	if len(vulnerabilities) > 0 {
		return xrayutils.PrepareVulnerabilities(vulnerabilities, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
	}
	return []formats.VulnerabilityOrViolationRow{}, nil
}

// Create vulnerability rows. The rows should contain all the issues that were found in this PR
func createAllIssuesRows(currentScan []services.ScanResponse, isMultipleRoot bool) ([]formats.VulnerabilityOrViolationRow, error) {
	violations, vulnerabilities, _ := xrayutils.SplitScanResults(currentScan)
	return getScanVulnerabilitiesRows(violations, vulnerabilities, isMultipleRoot)
}

func (cmd *ScanPullRequestCmd) checkPathsAndAudit(scanSetup *utils.ScanDetails) ([]services.ScanResponse, bool, error) {
	fullPathWds := getFullPathWorkingDirs(scanSetup.WorkingDirs, cmd.wd)
	return runInstallAndAudit(scanSetup, fullPathWds...)
}

func getFullPathWorkingDirs(workingDirs []string, baseWd string) []string {
	var fullPathWds []string
	if len(workingDirs) != 0 {
		for _, workDir := range workingDirs {
			if workDir == utils.RootDir {
				fullPathWds = append(fullPathWds, baseWd)
				continue
			}
			fullPathWds = append(fullPathWds, filepath.Join(baseWd, workDir))
		}
	} else {
		fullPathWds = append(fullPathWds, baseWd)
	}
	return fullPathWds
}

// TODO remove or use it
func auditTarget(scanSetup *utils.ScanDetails) (res []services.ScanResponse, isMultipleRoot bool, err error) {
	// First download the target repo to temp dir
	log.Info("Auditing the", scanSetup.Git.RepoName, "repository on the", scanSetup.Branch(), "branch")
	wd, cleanup, err := utils.DownloadRepoToTempDir(scanSetup.Client(), scanSetup.Branch(), scanSetup.Git)
	if err != nil {
		return
	}
	// Cleanup
	defer func() {
		e := cleanup()
		if err == nil {
			err = e
		}
	}()
	fullPathWds := getFullPathWorkingDirs(scanSetup.Project.WorkingDirs, wd)
	return runInstallAndAudit(scanSetup, fullPathWds...)
}

func runInstallAndAudit(scanSetup *utils.ScanDetails, workDirs ...string) (results []services.ScanResponse, isMultipleRoot bool, err error) {
	for _, wd := range workDirs {
		if err = runInstallIfNeeded(scanSetup, wd); err != nil {
			return nil, false, err
		}
	}
	graphBasicParams := (&xrayutils.GraphBasicParams{}).
		SetPipRequirementsFile(scanSetup.PipRequirementsFile).
		SetUseWrapper(*scanSetup.UseWrapper).
		SetDepsRepo(scanSetup.Repository).
		SetIgnoreConfigFile(true).
		SetServerDetails(scanSetup.ServerDetails).
		SetReleasesRepo(scanSetup.ReleasesRepo())
	auditParams := audit.NewAuditParams().
		SetXrayGraphScanParams(scanSetup.XrayGraphScanParams).
		SetWorkingDirs(workDirs).
		SetMinSeverityFilter(scanSetup.MinSeverityFilter()).
		SetFixableOnly(scanSetup.FixableOnly())
	auditParams.GraphBasicParams = graphBasicParams
	results, isMultipleRoot, err = audit.GenericAudit(auditParams)
	if err != nil {
		return nil, false, err
	}
	return results, isMultipleRoot, err
}

func runInstallIfNeeded(scanSetup *utils.ScanDetails, workDir string) (err error) {
	if scanSetup.InstallCommandName == "" {
		return nil
	}
	restoreDir, err := utils.Chdir(workDir)
	defer func() {
		restoreErr := restoreDir()
		if err == nil {
			err = restoreErr
		}
	}()
	log.Info(fmt.Sprintf("Executing '%s %s' at %s", scanSetup.InstallCommandName, scanSetup.InstallCommandArgs, workDir))
	output, err := runInstallCommand(scanSetup)
	if err != nil && !scanSetup.FailOnInstallationErrors() {
		log.Info(installationCmdFailedErr, err.Error(), "\n", string(output))
		// failOnInstallationErrors set to 'false'
		err = nil
	}
	return
}

func runInstallCommand(scanSetup *utils.ScanDetails) ([]byte, error) {
	if scanSetup.Repository == "" {
		//#nosec G204 -- False positive - the subprocess only runs after the user's approval.
		return exec.Command(scanSetup.InstallCommandName, scanSetup.InstallCommandArgs...).CombinedOutput()
	}

	if _, exists := utils.MapTechToResolvingFunc[scanSetup.InstallCommandName]; !exists {
		return nil, fmt.Errorf(scanSetup.InstallCommandName, "isn't recognized as an install command")
	}
	log.Info("Resolving dependencies from", scanSetup.ServerDetails.Url, "from repo", scanSetup.Repository)
	return utils.MapTechToResolvingFunc[scanSetup.InstallCommandName](scanSetup)
}

func getNewViolations(previousScan, currentScan services.ScanResponse, isMultipleRoot bool) (newViolationsRows []formats.VulnerabilityOrViolationRow, err error) {
	existsViolationsMap := make(map[string]formats.VulnerabilityOrViolationRow)
	violationsRows, _, _, err := xrayutils.PrepareViolations(previousScan.Violations, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
	if err != nil {
		return violationsRows, err
	}
	for _, violation := range violationsRows {
		existsViolationsMap[getUniqueID(violation)] = violation
	}
	violationsRows, _, _, err = xrayutils.PrepareViolations(currentScan.Violations, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
	if err != nil {
		return newViolationsRows, err
	}
	for _, violation := range violationsRows {
		if _, exists := existsViolationsMap[getUniqueID(violation)]; !exists {
			newViolationsRows = append(newViolationsRows, violation)
		}
	}
	return
}

func getNewVulnerabilities(targetScan, sourceScan services.ScanResponse, isMultipleRoot bool) (newVulnerabilitiesRows []formats.VulnerabilityOrViolationRow, err error) {
	targetVulnerabilitiesMap := make(map[string]formats.VulnerabilityOrViolationRow)
	targetVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(targetScan.Vulnerabilities, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range targetVulnerabilitiesRows {
		targetVulnerabilitiesMap[getUniqueID(vulnerability)] = vulnerability
	}
	sourceVulnerabilitiesRows, err := xrayutils.PrepareVulnerabilities(sourceScan.Vulnerabilities, &xrayutils.ExtendedScanResults{}, isMultipleRoot, true)
	if err != nil {
		return newVulnerabilitiesRows, err
	}
	for _, vulnerability := range sourceVulnerabilitiesRows {
		if _, exists := targetVulnerabilitiesMap[getUniqueID(vulnerability)]; !exists {
			newVulnerabilitiesRows = append(newVulnerabilitiesRows, vulnerability)
		}
	}
	return
}

func getUniqueID(vulnerability formats.VulnerabilityOrViolationRow) string {
	return vulnerability.ImpactedDependencyName + vulnerability.ImpactedDependencyVersion + vulnerability.IssueId
}

func createPullRequestMessage(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer utils.OutputWriter) string {
	if len(vulnerabilitiesRows) == 0 {
		return writer.NoVulnerabilitiesTitle()
	}
	tableContent := getTableContent(vulnerabilitiesRows, writer)
	return writer.VulnerabiltiesTitle() + writer.TableHeader() + tableContent
}

func getTableContent(vulnerabilitiesRows []formats.VulnerabilityOrViolationRow, writer utils.OutputWriter) string {
	var tableContent string
	for _, vulnerability := range vulnerabilitiesRows {
		tableContent += writer.TableRow(vulnerability)
	}
	return tableContent
}
